import { app, BrowserWindow, ipcMain, protocol, net } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import * as child_process from 'child_process';
import * as readline from 'readline';
import { pathToFileURL } from 'url';
import { IpcRequest, IpcResponse, IpcEvent } from '../src/types/ipc';
import { SecureAutoUpdater } from './updater';
import { UpdateChannel } from '../src/types/updater';
import { LicensingEngine } from './licensing';

// Hardware acceleration can fail in some virtual environments or headless sessions
app.disableHardwareAcceleration();

// Register privileged custom scheme BEFORE app.whenReady() to avoid CORS/origin issues
protocol.registerSchemesAsPrivileged([
  {
    scheme: 'app',
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      corsEnabled: true,
      allowServiceWorkers: true,
    },
  },
]);

let mainWindow: BrowserWindow | null = null;
const earlyLogBuffer: string[] = [];

// Persistent file-based diagnostic logging for production runs
function logToFile(msg: string) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  if (!app.isReady()) {
    earlyLogBuffer.push(line);
    return;
  }
  try {
    const logDir = app.getPath('userData');
    fs.mkdirSync(logDir, { recursive: true });
    const logFile = path.join(logDir, 'smart-cleaner.log');
    if (earlyLogBuffer.length > 0) {
      fs.appendFileSync(logFile, earlyLogBuffer.splice(0).join(''), 'utf8');
    }
    fs.appendFileSync(logFile, line, 'utf8');
  } catch {
    // Fail silently if unable to write log
  }
}

// Whitelist of valid IPC actions from renderer (Security Hardening M4.6 & Stage 2)
const ALLOWED_IPC_ACTIONS = new Set<string>([
  'ping',
  'get_system_status',
  'get_scan_status',
  'get_settings',
  'update_settings',
  'get_storage_summary',
  'get_cleanup_candidates',
  'get_candidate_explainability',
  'get_quarantine_contents',
  'get_audit_history',
  'start_scan',
  'cancel_scan',
  'select_candidate',
  'select_all_candidates',
  'quarantine_selected',
  'restore_quarantine_item',
  'purge_quarantine_item',
  'request_analysis',
  'request_elevation',
  // Secure Auto-Updater Actions (Stage 2)
  'updater_get_status',
  'updater_check_for_updates',
  'updater_download_update',
  'updater_apply_update',
  'updater_set_channel',
  'updater_cancel',
  // Licensing & Entitlements Actions (Stage 3)
  'licensing_get_status',
  'licensing_activate_manual',
  'licensing_start_device_auth',
  'licensing_poll_device_auth',
  'licensing_deactivate',
]);

// Stage 3 Licensing Engine
const licensingEngine = new LicensingEngine();

// Runtime Safety Engine State Tracking for Deferred Updates
let isScanActive = false;
let activeQuarantineOps = 0;

const autoUpdater = new SecureAutoUpdater({
  currentVersion: '1.0.5',
  defaultChannel: 'stable',
  eventBroadcaster: (event) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('smart-cleaner:event', event as IpcEvent);
    }
  },
});

autoUpdater.setEngineBusyProvider(() => isScanActive || activeQuarantineOps > 0);

class RustCoreBridge {
  private child: child_process.ChildProcess | null = null;
  private pendingRequests: Map<
    string,
    {
      resolve: (response: IpcResponse) => void;
      reject: (error: Error) => void;
      timer: NodeJS.Timeout;
    }
  > = new Map();
  private restartCount: number = 0;
  private lastRestartTime: number = 0;
  private isShuttingDown: boolean = false;

  constructor() {}

  public resolveCoreBinaryPath(): string {
    if (process.env.SMART_CLEANER_CORE_PATH) {
      return process.env.SMART_CLEANER_CORE_PATH;
    }

    const binaryName = process.platform === 'win32' ? 'smart-cleaner-core.exe' : 'smart-cleaner-core';

    if (app.isPackaged) {
      return path.join(process.resourcesPath, 'bin', binaryName);
    }

    // In dev mode, check release target first, then debug
    const rootDir = path.resolve(__dirname, '../../../');
    const releasePath = path.join(rootDir, 'core', 'target', 'release', binaryName);
    const debugPath = path.join(rootDir, 'core', 'target', 'debug', binaryName);

    return releasePath;
  }

  public start(): void {
    if (this.isShuttingDown) return;

    const corePath = this.resolveCoreBinaryPath();
    const startMsg = `[Electron Main] Spawning Rust Core binary: ${corePath}`;
    console.log(startMsg);
    logToFile(startMsg);

    try {
      this.child = child_process.spawn(corePath, ['--ipc-stdio'], {
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      });

      if (!this.child.stdout || !this.child.stdin) {
        throw new Error('Failed to attach stdio pipes to Rust Core process');
      }

      // Handle standard output (JSON lines)
      const rlOut = readline.createInterface({
        input: this.child.stdout,
        crlfDelay: Infinity,
      });

      rlOut.on('line', (line: string) => {
        this.handleCoreOutputLine(line.trim());
      });

      // Handle standard error (diagnostics / panic logs)
      if (this.child.stderr) {
        const rlErr = readline.createInterface({
          input: this.child.stderr,
          crlfDelay: Infinity,
        });

        rlErr.on('line', (errLine: string) => {
          console.error(`[Rust Core stderr] ${errLine}`);
          logToFile(`[Rust Core stderr] ${errLine}`);
        });
      }

      this.child.on('exit', (code: number | null, signal: string | null) => {
        const exitMsg = `[Electron Main] Rust Core exited with code: ${code}, signal: ${signal}`;
        console.warn(exitMsg);
        logToFile(exitMsg);
        this.handleProcessExit();
      });

      this.child.on('error', (err: Error) => {
        const errMsg = `[Electron Main] Rust Core process spawn error: ${err.message}`;
        console.error(errMsg);
        logToFile(errMsg);
      });
    } catch (err: unknown) {
      const errMsg = `[Electron Main] Failed to spawn Rust Core process: ${err instanceof Error ? err.message : String(err)}`;
      console.error(errMsg);
      logToFile(errMsg);
    }
  }

  private handleCoreOutputLine(line: string): void {
    if (!line) return;

    try {
      const parsed = JSON.parse(line);

      // 1. Is this an IPC Response correlated with a pending request?
      if (parsed && typeof parsed === 'object' && typeof parsed.id === 'string') {
        const pending = this.pendingRequests.get(parsed.id);
        if (pending) {
          clearTimeout(pending.timer);
          this.pendingRequests.delete(parsed.id);
          pending.resolve(parsed as IpcResponse);
          return;
        }
      }

      // 2. Is this an asynchronous IPC Event streamed from Core?
      if (parsed && typeof parsed === 'object' && (parsed.type || parsed.event)) {
        const evtType = parsed.type || parsed.event;
        if (evtType === 'scan_started') {
          isScanActive = true;
        } else if (evtType === 'scan_completed' || evtType === 'scan_cancelled') {
          isScanActive = false;
        }

        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('smart-cleaner:event', parsed as IpcEvent);
        }
        return;
      }

      console.log('[Rust Core unhandled line]', line);
    } catch (parseError) {
      console.warn('[Rust Core non-JSON stdout]', line);
    }
  }

  public send(request: IpcRequest): Promise<IpcResponse> {
    if (!this.child || !this.child.stdin || this.child.killed) {
      return Promise.reject(new Error('Rust Core process is not available'));
    }

    return new Promise((resolve, reject) => {
      // 30s timeout for standard requests, 300s for large scans
      const timeoutMs = request.action === 'start_scan' ? 300000 : 30000;

      const timer = setTimeout(() => {
        this.pendingRequests.delete(request.id);
        reject(new Error(`Rust Core IPC request '${request.action}' (ID: ${request.id}) timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      this.pendingRequests.set(request.id, { resolve, reject, timer });

      const payloadLine = JSON.stringify(request) + '\n';
      this.child?.stdin?.write(payloadLine, 'utf8', (err) => {
        if (err) {
          clearTimeout(timer);
          this.pendingRequests.delete(request.id);
          reject(err);
        }
      });
    });
  }

  private handleProcessExit(): void {
    // Reject any in-flight requests immediately
    for (const [id, pending] of this.pendingRequests.entries()) {
      clearTimeout(pending.timer);
      pending.reject(new Error(`Rust Core terminated abruptly while awaiting response for request ID: ${id}`));
    }
    this.pendingRequests.clear();
    this.child = null;

    if (this.isShuttingDown) return;

    // Restart throttling: Max 3 restarts within 10 seconds
    const now = Date.now();
    if (now - this.lastRestartTime > 10000) {
      this.restartCount = 0;
    }

    this.lastRestartTime = now;
    this.restartCount++;

    if (this.restartCount <= 3) {
      console.log(`[Electron Main] Restarting Rust Core (Attempt ${this.restartCount}/3)...`);
      setTimeout(() => this.start(), 1000);
    } else {
      console.error('[Electron Main] Rust Core exceeded maximum restart attempts. Halting auto-restart.');
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('smart-cleaner:event', {
          type: 'diagnostic_message',
          level: 'error',
          message: 'Rust Core process terminated unexpectedly and could not be restarted.',
        });
      }
    }
  }

  public shutdown(): void {
    this.isShuttingDown = true;
    if (this.child) {
      try {
        this.child.stdin?.end();
        this.child.kill('SIGTERM');
      } catch (err) {
        console.error('Error shutting down core child process:', err);
      }
    }
  }

  public isRunning(): boolean {
    return Boolean(this.child && !this.child.killed);
  }
}

const coreBridge = new RustCoreBridge();

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 750,
    minWidth: 800,
    minHeight: 600,
    title: 'Smart Cleaner',
    backgroundColor: '#0f172a',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.webContents.on('did-fail-load', (_event, errorCode, errorDescription, validatedURL) => {
    const err = `[RENDERER_FAIL_LOAD] Failed to load ${validatedURL}: ${errorDescription} (${errorCode})`;
    console.error(err);
    logToFile(err);
  });

  mainWindow.webContents.on('render-process-gone', (_event, details) => {
    const err = `[RENDERER_GONE] Render process gone: ${details.reason} (exitCode: ${details.exitCode})`;
    console.error(err);
    logToFile(err);
  });

  mainWindow.webContents.on('console-message', (_event, level, message, line, sourceId) => {
    const msg = `[RENDERER_CONSOLE] [Level ${level}] ${message} (${sourceId}:${line})`;
    if (level >= 2) {
      console.error(msg);
    }
    logToFile(msg);
  });

  // Diagnostic hotkey: F12 or Ctrl+Shift+I toggles DevTools
  mainWindow.webContents.on('before-input-event', (_event, input) => {
    if (input.key === 'F12' || (input.control && input.shift && input.key.toLowerCase() === 'i')) {
      mainWindow?.webContents.toggleDevTools();
    }
  });

  // Automatically open DevTools if requested via CLI flag or env var
  if (
    process.argv.includes('--devtools') ||
    process.env.SMART_CLEANER_DEVTOOLS === '1' ||
    process.env.ELECTRON_DEVTOOLS === '1'
  ) {
    mainWindow.webContents.openDevTools();
  }

  if (process.env.VITE_DEV_SERVER_URL) {
    mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else {
    // Primary: Custom app:// scheme prevents CORS origin:null blocks on ES modules and path issues
    mainWindow.loadURL('app://smartcleaner/index.html').catch((err) => {
      const msg = `[LOAD_URL_FAIL] app:// load failed: ${err}; falling back to loadFile`;
      console.warn(msg);
      logToFile(msg);

      const appRoot = app.getAppPath();
      const candidatePaths = [
        path.join(appRoot, 'dist/index.html'),
        path.join(__dirname, '../../dist/index.html'),
        path.join(__dirname, '../dist/index.html'),
      ];
      const targetPath = candidatePaths.find((p) => fs.existsSync(p));
      if (targetPath) {
        mainWindow?.loadFile(targetPath);
      } else {
        console.error('[FATAL] Could not locate dist/index.html in candidate paths:', candidatePaths);
        mainWindow?.loadFile(path.join(__dirname, '../dist/index.html'));
      }
    });
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Register IPC Handler
ipcMain.handle('smart-cleaner:ipc', async (_event, request: IpcRequest): Promise<IpcResponse> => {
  // Security Enforcement: Whitelist validation (M4.6)
  if (!request || typeof request !== 'object' || !ALLOWED_IPC_ACTIONS.has(request.action)) {
    return {
      id: request?.id ?? 'invalid-id',
      status: 'error',
      error: {
        code: 'UNSUPPORTED_CAPABILITY',
        message: `Action '${request?.action}' is not permitted by Electron main process security whitelist.`,
      },
    };
  }

  // Intercept and handle Secure Auto-Updater actions in Electron main process
  if (request.action.startsWith('updater_')) {
    try {
      switch (request.action) {
        case 'updater_get_status':
          return { id: request.id, status: 'ok', data: autoUpdater.getStatus() };
        case 'updater_check_for_updates': {
          const payload = request.payload as { manifestUrl?: string } | undefined;
          const status = await autoUpdater.checkForUpdates({ manifestUrlOverride: payload?.manifestUrl });
          return { id: request.id, status: 'ok', data: status };
        }
        case 'updater_download_update': {
          const status = await autoUpdater.downloadUpdate();
          return { id: request.id, status: 'ok', data: status };
        }
        case 'updater_apply_update': {
          const payload = request.payload as { confirm?: boolean } | undefined;
          const result = await autoUpdater.applyUpdate({
            confirm: Boolean(payload?.confirm),
            onApplySpawn: () => {
              app.quit();
            },
          });
          return { id: request.id, status: 'ok', data: result };
        }
        case 'updater_set_channel': {
          const payload = request.payload as { channel: UpdateChannel };
          const status = autoUpdater.setChannel(payload.channel);
          return { id: request.id, status: 'ok', data: status };
        }
        case 'updater_cancel': {
          const status = autoUpdater.cancel();
          return { id: request.id, status: 'ok', data: status };
        }
        default:
          return {
            id: request.id,
            status: 'error',
            error: { code: 'UNSUPPORTED_CAPABILITY', message: `Updater action '${request.action}' not recognized` },
          };
      }
    } catch (updaterErr: unknown) {
      return {
        id: request.id,
        status: 'error',
        error: {
          code: 'UPDATER_ERROR',
          message: updaterErr instanceof Error ? updaterErr.message : String(updaterErr),
        },
      };
    }
  }

  // Intercept and handle Licensing & Entitlement actions in Electron main process
  if (request.action.startsWith('licensing_')) {
    try {
      switch (request.action) {
        case 'licensing_get_status':
          return { id: request.id, status: 'ok', data: licensingEngine.getStatus() };
        case 'licensing_activate_manual': {
          const payload = request.payload as { token: string };
          const status = licensingEngine.activateManual(payload.token);
          return { id: request.id, status: 'ok', data: status };
        }
        case 'licensing_start_device_auth': {
          const res = licensingEngine.startDeviceAuth();
          return { id: request.id, status: 'ok', data: res };
        }
        case 'licensing_poll_device_auth': {
          const payload = request.payload as { device_code: string };
          const res = licensingEngine.pollDeviceAuth(payload.device_code);
          return { id: request.id, status: 'ok', data: res };
        }
        case 'licensing_deactivate': {
          const status = licensingEngine.deactivate();
          return { id: request.id, status: 'ok', data: status };
        }
        default:
          return {
            id: request.id,
            status: 'error',
            error: { code: 'UNSUPPORTED_CAPABILITY', message: `Licensing action '${request.action}' not recognized` },
          };
      }
    } catch (licErr: unknown) {
      return {
        id: request.id,
        status: 'error',
        error: {
          code: 'LICENSING_ERROR',
          message: licErr instanceof Error ? licErr.message : String(licErr),
        },
      };
    }
  }

  // Track active operations for runtime safety gate
  const isQuarantineOp =
    request.action === 'quarantine_selected' ||
    request.action === 'restore_quarantine_item' ||
    request.action === 'purge_quarantine_item';

  if (isQuarantineOp) {
    activeQuarantineOps++;
  }

  try {
    return await coreBridge.send(request);
  } catch (err: unknown) {
    return {
      id: request.id,
      status: 'error',
      error: {
        code: 'INTERNAL_CORE_ERROR',
        message: err instanceof Error ? err.message : 'Unknown IPC communication error',
      },
    };
  } finally {
    if (isQuarantineOp) {
      activeQuarantineOps = Math.max(0, activeQuarantineOps - 1);
    }
  }
});

app.whenReady().then(() => {
  // Register custom 'app://' protocol handler to serve local renderer assets
  protocol.handle('app', (request) => {
    try {
      const parsedUrl = new URL(request.url);
      let pathname = decodeURIComponent(parsedUrl.pathname);
      if (pathname.startsWith('/')) {
        pathname = pathname.slice(1);
      }
      if (!pathname || pathname === '/') {
        pathname = 'index.html';
      }

      const appRoot = app.getAppPath();
      const candidatePaths = [
        path.join(appRoot, 'dist', pathname),
        path.join(__dirname, '../../dist', pathname),
        path.join(__dirname, '../dist', pathname),
      ];

      const resolvedPath = candidatePaths.find((p) => fs.existsSync(p));
      if (resolvedPath) {
        return net.fetch(pathToFileURL(resolvedPath).toString());
      }

      // If specific asset not found, check if index.html exists for SPA fallback
      const fallbackIndex = candidatePaths
        .map((p) => path.join(path.dirname(p), 'index.html'))
        .find((p) => fs.existsSync(p));
      if (fallbackIndex) {
        return net.fetch(pathToFileURL(fallbackIndex).toString());
      }

      logToFile(`[PROTOCOL_404] Resource not found: ${request.url}`);
      return new Response('Resource Not Found', { status: 404 });
    } catch (err) {
      logToFile(`[PROTOCOL_ERROR] Error handling ${request.url}: ${err}`);
      return new Response('Internal Protocol Error', { status: 500 });
    }
  });

  coreBridge.start();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('before-quit', () => {
  coreBridge.shutdown();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
