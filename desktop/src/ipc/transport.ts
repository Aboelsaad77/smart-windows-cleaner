import { IpcRequest, IpcResponse, IpcEvent } from '../types/ipc';

export type EventListener = (event: IpcEvent) => void;

export interface IpcTransport {
  send(request: IpcRequest): Promise<IpcResponse>;
  subscribe(listener: EventListener): () => void;
  isConnected(): boolean;
  connect?(): Promise<void>;
  disconnect?(): Promise<void>;
}

// Global declaration for Electron contextBridge if available
declare global {
  interface Window {
    smartCleanerIpc?: {
      send(request: IpcRequest): Promise<IpcResponse>;
      onEvent(callback: (event: IpcEvent) => void): () => void;
      isConnected(): boolean;
    };
  }
}

/**
 * Native Electron Bridge Transport using contextBridge (preload.ts)
 */
export class ElectronTransport implements IpcTransport {
  send(request: IpcRequest): Promise<IpcResponse> {
    if (typeof window !== 'undefined' && window.smartCleanerIpc) {
      return window.smartCleanerIpc.send(request);
    }
    return Promise.reject(new Error('Electron IPC bridge (window.smartCleanerIpc) is not available'));
  }

  subscribe(listener: EventListener): () => void {
    if (typeof window !== 'undefined' && window.smartCleanerIpc) {
      return window.smartCleanerIpc.onEvent(listener);
    }
    return () => {};
  }

  isConnected(): boolean {
    return typeof window !== 'undefined' && Boolean(window.smartCleanerIpc?.isConnected());
  }
}

/**
 * Mock Transport for unit tests and local development/preview
 */
export class MockTransport implements IpcTransport {
  private connected: boolean = true;
  private listeners: Set<EventListener> = new Set();
  private mockResponses: Map<string, (req: IpcRequest) => IpcResponse> = new Map();

  constructor() {
    this.registerDefaultHandlers();
  }

  setConnected(status: boolean): void {
    this.connected = status;
  }

  isConnected(): boolean {
    return this.connected;
  }

  registerHandler(action: string, handler: (req: IpcRequest) => IpcResponse): void {
    this.mockResponses.set(action, handler);
  }

  async send(request: IpcRequest): Promise<IpcResponse> {
    if (!this.connected) {
      return {
        id: request.id,
        status: 'error',
        error: {
          code: 'INTERNAL_CORE_ERROR',
          message: 'Cannot reach native Rust core process (disconnected).',
        },
      };
    }

    const handler = this.mockResponses.get(request.action);
    if (handler) {
      return handler(request);
    }

    return {
      id: request.id,
      status: 'error',
      error: {
        code: 'UNSUPPORTED_CAPABILITY',
        message: `Action '${request.action}' not handled in mock transport.`,
      },
    };
  }

  subscribe(listener: EventListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  emit(event: IpcEvent): void {
    this.listeners.forEach((listener) => {
      try {
        listener(event);
      } catch (err) {
        console.error('Error in mock event listener:', err);
      }
    });
  }

  private registerDefaultHandlers(): void {
    this.mockResponses.set('get_system_status', (req) => ({
      id: req.id,
      status: 'ok',
      data: {
        os_version: 'Windows 11 Pro 64-bit (Build 22631)',
        is_elevated: false,
        uac_level: 'standard_user',
        quarantine_vault_path: 'C:\\ProgramData\\SmartCleaner\\Quarantine',
        quarantine_item_count: 0,
        quarantine_total_bytes: 0,
      },
    }));

    this.mockResponses.set('get_scan_status', (req) => ({
      id: req.id,
      status: 'ok',
      data: {
        state: 'idle',
        files_scanned: 0,
        candidates_found: 0,
        elapsed_ms: 0,
      },
    }));

    this.mockResponses.set('get_settings', (req) => ({
      id: req.id,
      status: 'ok',
      data: {
        quarantine_retention_days: 7,
        excluded_paths: ['C:\\Windows', 'C:\\Program Files'],
        enable_deep_scan: false,
        auto_rescan_on_startup: false,
      },
    }));

    this.mockResponses.set('get_storage_summary', (req) => ({
      id: req.id,
      status: 'ok',
      data: {
        drives: [
          { mount_point: 'C:\\', total_bytes: 512000000000, free_bytes: 142000000000, available_bytes: 142000000000 },
          { mount_point: 'D:\\', total_bytes: 1024000000000, free_bytes: 620000000000, available_bytes: 620000000000 },
        ],
        winsxs_protection: {
          path: 'C:\\Windows\\WinSxS',
          is_protected: true,
          reason: 'Windows Component Store protected by hard safety rule',
        },
      },
    }));

    this.mockResponses.set('get_cleanup_candidates', (req) => ({
      id: req.id,
      status: 'ok',
      data: [],
    }));

    this.mockResponses.set('get_quarantine_contents', (req) => ({
      id: req.id,
      status: 'ok',
      data: [],
    }));

    this.mockResponses.set('get_audit_history', (req) => ({
      id: req.id,
      status: 'ok',
      data: [],
    }));

    this.mockResponses.set('start_scan', (req) => {
      const sessionId = `scan-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
      return {
        id: req.id,
        status: 'ok',
        data: { session_id: sessionId },
      };
    });

    this.mockResponses.set('cancel_scan', (req) => {
      const payload = req.payload as { session_id?: string } | undefined;
      return {
        id: req.id,
        status: 'ok',
        data: { session_id: payload?.session_id ?? 'unknown' },
      };
    });

    this.mockResponses.set('select_candidate', (req) => {
      const payload = req.payload as { path: string; selected: boolean } | undefined;
      return {
        id: req.id,
        status: 'ok',
        data: {
          selected_count: payload?.selected ? 1 : 0,
          selected_bytes: payload?.selected ? 10485760 : 0,
          can_quarantine_all: true,
        },
      };
    });

    this.mockResponses.set('select_all_candidates', (req) => {
      const payload = req.payload as { selected: boolean } | undefined;
      return {
        id: req.id,
        status: 'ok',
        data: {
          selected_count: payload?.selected ? 5 : 0,
          selected_bytes: payload?.selected ? 52428800 : 0,
          can_quarantine_all: true,
        },
      };
    });

    this.mockResponses.set('quarantine_selected', (req) => {
      const payload = req.payload as { paths: string[] } | undefined;
      const paths = payload?.paths || [];
      return {
        id: req.id,
        status: 'ok',
        data: {
          quarantined: paths.map((p, idx) => ({
            item_id: `q-item-${idx + 1}-${Date.now()}`,
            original_path: p,
            category: 'User Temp',
            quarantined_size_bytes: 1048576,
            sha256_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            quarantined_at: new Date().toISOString(),
            retention_days: 7,
            days_remaining: 7,
            is_expired: false,
          })),
          blocked: [],
          failed: [],
        },
      };
    });

    this.mockResponses.set('restore_quarantine_item', (req) => {
      const payload = req.payload as { item_id: string; target_path_override?: string } | undefined;
      return {
        id: req.id,
        status: 'ok',
        data: {
          item_id: payload?.item_id || 'q-item-1',
          restored_to: payload?.target_path_override || 'C:\\Restored\\file.tmp',
        },
      };
    });

    this.mockResponses.set('purge_quarantine_item', (req) => {
      const payload = req.payload as { item_id: string } | undefined;
      return {
        id: req.id,
        status: 'ok',
        data: {
          item_id: payload?.item_id || 'q-item-1',
          purged: true,
        },
      };
    });

    this.mockResponses.set('request_analysis', (req) => {
      const payload = req.payload as { path: string } | undefined;
      const targetPath = payload?.path || 'C:\\mock\\file.tmp';
      return {
        id: req.id,
        status: 'ok',
        data: {
          id: `cand-${Date.now()}`,
          path: targetPath,
          size_bytes: 2097152,
          category: 'User Temp',
          app_owner: 'Mock App',
          app_confidence: 'direct_key',
          risk_score: 25,
          risk_band: 'Safe',
          risk_factors: [{ name: 'SAFE_CACHE_EXPIRY', weight: 0, reason: 'Cache expired by policy' }],
          local_rules: [{ rule_id: 'RULE_USER_TEMP', confidence: 'high', category: 'User Temp', reclaim_estimate_bytes: 2097152 }],
          safety_verdict: 'auto_quarantine',
          can_quarantine: true,
          allowed_reasons: ['User temp directory item older than 7 days'],
          blocked_reasons: [],
          is_pe: false,
          is_signed: false,
          is_in_use: false,
          is_hidden_or_system: false,
          selected: false,
        },
      };
    });

    this.mockResponses.set('request_elevation', (req) => {
      this.mockResponses.set('get_system_status', (statusReq) => ({
        id: statusReq.id,
        status: 'ok',
        data: {
          os_version: 'Windows 11 Pro 64-bit (Build 22631)',
          is_elevated: true,
          uac_level: 'highest',
          quarantine_vault_path: 'C:\\ProgramData\\SmartCleaner\\Quarantine',
          quarantine_item_count: 5,
          quarantine_total_bytes: 4294967296,
        },
      }));

      return {
        id: req.id,
        status: 'ok',
        data: { elevated: true },
      };
    });
  }
}
