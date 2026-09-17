import {
  IpcRequest,
  IpcEvent,
  IpcError,
  SystemStatusDto,
  ScanStatusDto,
  StorageSummaryDto,
  CandidateExplainabilityDto,
  QuarantineItemDto,
  SettingsDto,
  AuditEntryDto,
  ScanSummaryDto,
  CandidateFilter,
  QuarantineFilter,
  AuditFilter,
  StartScanCommand,
  SelectionSummaryDto,
  QuarantineOperationResultDto,
  UpdateStatusDto,
  UpdateChannel,
  LicenseStatusDto,
  DeviceAuthResponseDto,
  DeviceAuthPollResultDto,
} from '../types/ipc';
import { IpcTransport, ElectronTransport, MockTransport } from './transport';

export interface IpcClientOptions {
  timeoutMs?: number;
  transport?: IpcTransport;
}

export class IpcClientError extends Error {
  public readonly code: string;
  public readonly details?: Record<string, unknown>;

  constructor(ipcError: IpcError) {
    super(ipcError.message);
    this.name = 'IpcClientError';
    this.code = ipcError.code;
    this.details = ipcError.details;
  }
}

let requestIdCounter = 0;
function generateRequestId(): string {
  requestIdCounter += 1;
  return `req-${Date.now()}-${requestIdCounter}`;
}

export class IpcClient {
  private transport: IpcTransport;
  private timeoutMs: number;
  private eventListeners: Set<(event: IpcEvent) => void> = new Set();
  private transportUnsubscribe?: () => void;

  constructor(options: IpcClientOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? 10000;
    
    if (options.transport) {
      this.transport = options.transport;
    } else if (typeof window !== 'undefined' && window.smartCleanerIpc) {
      this.transport = new ElectronTransport();
    } else {
      this.transport = new MockTransport();
    }

    this.initEventListener();
  }

  public getTransport(): IpcTransport {
    return this.transport;
  }

  public isConnected(): boolean {
    return this.transport.isConnected();
  }

  private initEventListener(): void {
    this.transportUnsubscribe = this.transport.subscribe((event: IpcEvent) => {
      this.eventListeners.forEach((listener) => {
        try {
          listener(event);
        } catch (err) {
          console.error('[IpcClient] Event listener threw error:', err);
        }
      });
    });
  }

  public destroy(): void {
    if (this.transportUnsubscribe) {
      this.transportUnsubscribe();
      this.transportUnsubscribe = undefined;
    }
    this.eventListeners.clear();
  }

  /**
   * Subscribe to all or specific IPC events with clean unsubscription.
   */
  public onEvent(listener: (event: IpcEvent) => void): () => void {
    this.eventListeners.add(listener);
    return () => {
      this.eventListeners.delete(listener);
    };
  }

  /**
   * Subscribe specifically to events of a particular type.
   */
  public on<TType extends IpcEvent['type']>(
    type: TType,
    listener: (event: Extract<IpcEvent, { type: TType }>) => void
  ): () => void {
    const wrapper = (event: IpcEvent) => {
      if (event.type === type) {
        listener(event as Extract<IpcEvent, { type: TType }>);
      }
    };
    return this.onEvent(wrapper);
  }

  /**
   * Low-level invoke method with request correlation and timeout handling.
   */
  public async invoke<TPayload = unknown, TResult = unknown>(
    action: string,
    payload: TPayload,
    timeoutMs: number = this.timeoutMs
  ): Promise<TResult> {
    const id = generateRequestId();
    const request: IpcRequest<TPayload> = {
      id,
      action,
      payload,
    };

    const timeoutPromise = new Promise<never>((_, reject) => {
      const timer = setTimeout(() => {
        reject(
          new IpcClientError({
            code: 'REQUEST_TIMEOUT',
            message: `IPC request '${action}' (ID ${id}) timed out after ${timeoutMs}ms`,
          })
        );
      }, timeoutMs);
      if (typeof timer === 'object' && timer !== null && 'unref' in timer) {
        (timer as { unref: () => void }).unref();
      }
    });

    try {
      const response = await Promise.race([this.transport.send(request), timeoutPromise]);

      if (response.id !== id) {
        throw new IpcClientError({
          code: 'CORRELATION_ERROR',
          message: `Mismatched IPC response ID: expected '${id}', got '${response.id}'`,
        });
      }

      if (response.status === 'error' || response.error) {
        throw new IpcClientError(
          response.error ?? {
            code: 'INTERNAL_CORE_ERROR',
            message: 'Unknown error occurred in Rust core response',
          }
        );
      }

      return response.data as TResult;
    } catch (err) {
      if (err instanceof IpcClientError) {
        throw err;
      }
      throw new IpcClientError({
        code: 'TRANSPORT_ERROR',
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // --- Strongly-typed Query Methods ---

  public async getSystemStatus(): Promise<SystemStatusDto> {
    return this.invoke<null, SystemStatusDto>('get_system_status', null);
  }

  public async getScanStatus(): Promise<ScanStatusDto> {
    return this.invoke<null, ScanStatusDto>('get_scan_status', null);
  }

  public async getScanSummary(): Promise<ScanSummaryDto> {
    return this.invoke<null, ScanSummaryDto>('get_scan_summary', null);
  }

  public async getStorageSummary(): Promise<StorageSummaryDto> {
    return this.invoke<null, StorageSummaryDto>('get_storage_summary', null);
  }

  public async getCleanupCandidates(filter?: CandidateFilter): Promise<CandidateExplainabilityDto[]> {
    return this.invoke<CandidateFilter | null, CandidateExplainabilityDto[]>('get_cleanup_candidates', filter ?? null);
  }

  public async getQuarantineContents(filter?: QuarantineFilter): Promise<QuarantineItemDto[]> {
    return this.invoke<QuarantineFilter | null, QuarantineItemDto[]>('get_quarantine_contents', filter ?? null);
  }

  public async getAuditHistory(filter?: AuditFilter): Promise<AuditEntryDto[]> {
    return this.invoke<AuditFilter | null, AuditEntryDto[]>('get_audit_history', filter ?? null);
  }

  public async getSettings(): Promise<SettingsDto> {
    return this.invoke<null, SettingsDto>('get_settings', null);
  }

  public async requestAnalysis(path: string): Promise<CandidateExplainabilityDto> {
    return this.invoke<{ path: string }, CandidateExplainabilityDto>('request_analysis', { path });
  }

  // --- Strongly-typed Command Methods ---

  public async startScan(cmd: StartScanCommand): Promise<{ session_id: string }> {
    return this.invoke<StartScanCommand, { session_id: string }>('start_scan', cmd);
  }

  public async cancelScan(sessionId: string): Promise<{ session_id: string }> {
    return this.invoke<{ session_id: string }, { session_id: string }>('cancel_scan', { session_id: sessionId });
  }

  public async selectCandidate(path: string, selected: boolean): Promise<SelectionSummaryDto> {
    return this.invoke<{ path: string; selected: boolean }, SelectionSummaryDto>('select_candidate', {
      path,
      selected,
    });
  }

  public async selectAllCandidates(selected: boolean, filter?: CandidateFilter): Promise<SelectionSummaryDto> {
    return this.invoke<{ filter?: CandidateFilter; selected: boolean }, SelectionSummaryDto>(
      'select_all_candidates',
      { filter, selected }
    );
  }

  public async quarantineSelected(paths: string[]): Promise<QuarantineOperationResultDto> {
    return this.invoke<{ paths: string[] }, QuarantineOperationResultDto>('quarantine_selected', { paths });
  }

  public async restoreQuarantineItem(itemId: string, targetPathOverride?: string): Promise<{ item_id: string; restored_to: string }> {
    return this.invoke<{ item_id: string; target_path_override?: string }, { item_id: string; restored_to: string }>(
      'restore_quarantine_item',
      { item_id: itemId, target_path_override: targetPathOverride }
    );
  }

  public async purgeQuarantineItem(itemId: string): Promise<{ item_id: string; purged: boolean }> {
    return this.invoke<{ item_id: string }, { item_id: string; purged: boolean }>('purge_quarantine_item', {
      item_id: itemId,
    });
  }

  public async saveSettings(settings: SettingsDto): Promise<SettingsDto> {
    return this.invoke<{ settings: SettingsDto }, SettingsDto>('save_settings', { settings });
  }

  // --- Strongly-typed Updater Methods (Stage 2) ---

  public async updaterGetStatus(): Promise<UpdateStatusDto> {
    return this.invoke<null, UpdateStatusDto>('updater_get_status', null);
  }

  public async updaterCheckForUpdates(manifestUrl?: string): Promise<UpdateStatusDto> {
    return this.invoke<{ manifestUrl?: string } | null, UpdateStatusDto>(
      'updater_check_for_updates',
      manifestUrl ? { manifestUrl } : null
    );
  }

  public async updaterDownloadUpdate(): Promise<UpdateStatusDto> {
    return this.invoke<null, UpdateStatusDto>('updater_download_update', null);
  }

  public async updaterApplyUpdate(confirm: boolean): Promise<{ applied: boolean; deferred: boolean; reason?: string }> {
    return this.invoke<{ confirm: boolean }, { applied: boolean; deferred: boolean; reason?: string }>(
      'updater_apply_update',
      { confirm }
    );
  }

  public async updaterSetChannel(channel: UpdateChannel): Promise<UpdateStatusDto> {
    return this.invoke<{ channel: UpdateChannel }, UpdateStatusDto>('updater_set_channel', { channel });
  }

  public async updaterCancel(): Promise<UpdateStatusDto> {
    return this.invoke<null, UpdateStatusDto>('updater_cancel', null);
  }

  // --- Strongly-typed Licensing Methods (Stage 3) ---

  public async licensingGetStatus(): Promise<LicenseStatusDto> {
    return this.invoke<null, LicenseStatusDto>('licensing_get_status', null);
  }

  public async licensingActivateManual(token: string): Promise<LicenseStatusDto> {
    return this.invoke<{ token: string }, LicenseStatusDto>('licensing_activate_manual', { token });
  }

  public async licensingStartDeviceAuth(): Promise<DeviceAuthResponseDto> {
    return this.invoke<null, DeviceAuthResponseDto>('licensing_start_device_auth', null);
  }

  public async licensingPollDeviceAuth(deviceCode: string): Promise<DeviceAuthPollResultDto> {
    return this.invoke<{ device_code: string }, DeviceAuthPollResultDto>('licensing_poll_device_auth', {
      device_code: deviceCode,
    });
  }

  public async licensingDeactivate(): Promise<LicenseStatusDto> {
    return this.invoke<null, LicenseStatusDto>('licensing_deactivate', null);
  }
}
