import { app, BrowserWindow, ipcMain } from 'electron';
import * as path from 'path';
import * as child_process from 'child_process';
import * as readline from 'readline';
import { IpcRequest, IpcResponse, IpcEvent } from '../src/types/ipc';

let mainWindow: BrowserWindow | null = null;

// Whitelist of valid IPC actions from renderer (Security Hardening M4.6)
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
]);

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
    console.log(`[Electron Main] Spawning Rust Core binary: ${corePath}`);

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
        });
      }

      this.child.on('exit', (code: number | null, signal: string | null) => {
        console.warn(`[Electron Main] Rust Core exited with code: ${code}, signal: ${signal}`);
        this.handleProcessExit();
      });

      this.child.on('error', (err: Error) => {
        console.error('[Electron Main] Rust Core process spawn error:', err);
      });
    } catch (err: unknown) {
      console.error('[Electron Main] Failed to spawn Rust Core process:', err);
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
      sandbox: true,
    },
  });

  if (process.env.VITE_DEV_SERVER_URL) {
    mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
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
  }
});

app.whenReady().then(() => {
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
