import React, { createContext, useContext, useEffect, useState, useCallback, useMemo } from 'react';
import {
  SystemStatusDto,
  ScanStatusDto,
  SettingsDto,
  ScanSummaryDto,
  IpcError,
  IpcEvent,
  UpdateStatusDto,
  UpdateChannel,
  LicenseStatusDto,
  DeviceAuthResponseDto,
  DeviceAuthPollResultDto,
} from '../types/ipc';
import { IpcClient, IpcClientError } from '../ipc/client';
import { CoreConnectionStatus } from '../design-system/StatusIndicator';

export type NavigationRoute =
  | 'dashboard'
  | 'scan'
  | 'results'
  | 'quarantine'
  | 'storage'
  | 'logs'
  | 'settings';

export interface AppNotification {
  id: string;
  type: 'info' | 'warn' | 'error';
  message: string;
  timestamp: Date;
}

export interface AppContextValue {
  client: IpcClient;
  connectionStatus: CoreConnectionStatus;
  currentRoute: NavigationRoute;
  setCurrentRoute: (route: NavigationRoute) => void;
  systemStatus: SystemStatusDto | null;
  scanStatus: ScanStatusDto | null;
  settings: SettingsDto | null;
  latestScanSummary: ScanSummaryDto | null;
  coreError: IpcError | null;
  notifications: AppNotification[];
  pendingOperations: Set<string>;
  dismissNotification: (id: string) => void;
  reconnectCore: () => Promise<void>;
  trackOperation: <T>(operationName: string, promise: Promise<T>) => Promise<T>;
  requestElevation: () => Promise<void>;
  isElevationModalOpen: boolean;
  elevationReason?: string;
  openElevationModal: (reason?: string) => void;
  closeElevationModal: () => void;
  // Secure Auto-Updater State & Actions (Stage 2)
  updateStatus: UpdateStatusDto | null;
  checkForUpdates: (manifestUrl?: string) => Promise<UpdateStatusDto>;
  downloadUpdate: () => Promise<UpdateStatusDto>;
  applyUpdate: (confirm: boolean) => Promise<{ applied: boolean; deferred: boolean; reason?: string }>;
  setUpdateChannel: (channel: UpdateChannel) => Promise<UpdateStatusDto>;
  cancelUpdate: () => Promise<UpdateStatusDto>;
  // Licensing & Entitlements State & Actions (Stage 3)
  licenseStatus: LicenseStatusDto | null;
  isEntitled: (feature: string) => boolean;
  activateLicenseManual: (token: string) => Promise<LicenseStatusDto>;
  startDeviceAuth: () => Promise<DeviceAuthResponseDto>;
  pollDeviceAuth: (deviceCode: string) => Promise<DeviceAuthPollResultDto>;
  deactivateLicense: () => Promise<LicenseStatusDto>;
}

const AppContext = createContext<AppContextValue | null>(null);

export interface AppProviderProps {
  children: React.ReactNode;
  client?: IpcClient;
  initialRoute?: NavigationRoute;
}

export const AppProvider: React.FC<AppProviderProps> = ({
  children,
  client: customClient,
  initialRoute = 'dashboard',
}) => {
  const client = useMemo(() => customClient ?? new IpcClient(), [customClient]);

  const [connectionStatus, setConnectionStatus] = useState<CoreConnectionStatus>('connecting');
  const [currentRoute, setCurrentRoute] = useState<NavigationRoute>(initialRoute);
  const [systemStatus, setSystemStatus] = useState<SystemStatusDto | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatusDto | null>(null);
  const [settings, setSettings] = useState<SettingsDto | null>(null);
  const [latestScanSummary, setLatestScanSummary] = useState<ScanSummaryDto | null>(null);
  const [coreError, setCoreError] = useState<IpcError | null>(null);
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [pendingOperations, setPendingOperations] = useState<Set<string>>(new Set());
  const [isElevationModalOpen, setIsElevationModalOpen] = useState<boolean>(false);
  const [elevationReason, setElevationReason] = useState<string | undefined>(undefined);

  // Secure Auto-Updater State (Stage 2)
  const [updateStatus, setUpdateStatus] = useState<UpdateStatusDto | null>(null);

  // Licensing & Entitlements State (Stage 3)
  const [licenseStatus, setLicenseStatus] = useState<LicenseStatusDto | null>(null);

  const openElevationModal = useCallback((reason?: string) => {
    setElevationReason(reason);
    setIsElevationModalOpen(true);
  }, []);

  const closeElevationModal = useCallback(() => {
    setIsElevationModalOpen(false);
    setElevationReason(undefined);
  }, []);

  const addNotification = useCallback((type: 'info' | 'warn' | 'error', message: string) => {
    const notif: AppNotification = {
      id: `notif-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      type,
      message,
      timestamp: new Date(),
    };
    setNotifications((prev) => [notif, ...prev.slice(0, 49)]); // retain up to 50 notifications
  }, []);

  const dismissNotification = useCallback((id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  }, []);

  const trackOperation = useCallback(async <T,>(operationName: string, promise: Promise<T>): Promise<T> => {
    setPendingOperations((prev) => new Set(prev).add(operationName));
    try {
      return await promise;
    } finally {
      setPendingOperations((prev) => {
        const next = new Set(prev);
        next.delete(operationName);
        return next;
      });
    }
  }, []);

  const initCoreConnection = useCallback(async () => {
    setConnectionStatus('connecting');
    setCoreError(null);

    try {
      if (!client.isConnected()) {
        throw new IpcClientError({
          code: 'INTERNAL_CORE_ERROR',
          message: 'Native core process is not running or IPC channel failed to bind.',
        });
      }

      // Query core state per Requirement 5
      const [sysStatus, scnStatus, setts, licStatus] = await Promise.all([
        client.getSystemStatus(),
        client.getScanStatus(),
        client.getSettings(),
        client.licensingGetStatus().catch(() => null),
      ]);

      setSystemStatus(sysStatus);
      setScanStatus(scnStatus);
      setSettings(setts);
      if (licStatus) {
        setLicenseStatus(licStatus);
      }
      setConnectionStatus('connected');
    } catch (err) {
      setConnectionStatus('error');
      if (err instanceof IpcClientError) {
        setCoreError({
          code: err.code,
          message: err.message,
          details: err.details,
        });
      } else {
        setCoreError({
          code: 'INTERNAL_CORE_ERROR',
          message: err instanceof Error ? err.message : String(err),
        });
      }
    }
  }, [client]);

  // Request UAC Elevation via IPC
  const requestElevation = useCallback(async () => {
    addNotification('info', 'Requesting administrator elevation via Windows UAC...');
    try {
      // In a real Electron setup, this triggers the elevated sidecar spawn or UAC prompt
      await client.invoke('request_elevation', {});
      await initCoreConnection();
      addNotification('info', 'Administrator elevation granted successfully (UAC active).');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      addNotification('warn', `Elevation request was cancelled or failed: ${msg}`);
      throw err;
    }
  }, [client, addNotification, initCoreConnection]);

  // Secure Auto-Updater Operations (Stage 2)
  const checkForUpdates = useCallback(
    async (manifestUrl?: string) => {
      addNotification('info', 'Checking for cryptographically signed release updates...');
      try {
        const res = await trackOperation('check_updates', client.updaterCheckForUpdates(manifestUrl));
        setUpdateStatus(res);
        if (res.state === 'available' && res.available_update) {
          addNotification(
            'info',
            `Update available: v${res.available_update.version} (${res.available_update.channel} channel).`
          );
        } else if (res.state === 'not_available') {
          addNotification('info', 'Smart Windows Cleaner is up to date.');
        }
        return res;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        addNotification('error', `Update check failed: ${msg}`);
        throw err;
      }
    },
    [client, trackOperation, addNotification]
  );

  const downloadUpdate = useCallback(async () => {
    addNotification('info', 'Downloading verified update package...');
    try {
      const res = await trackOperation('download_update', client.updaterDownloadUpdate());
      setUpdateStatus(res);
      addNotification('info', 'Update downloaded and cryptographic hashes verified successfully.');
      return res;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      addNotification('error', `Update download failed: ${msg}`);
      throw err;
    }
  }, [client, trackOperation, addNotification]);

  const applyUpdate = useCallback(
    async (confirm: boolean) => {
      if (!confirm) {
        throw new Error('User confirmation is required to apply the update.');
      }

      // Check runtime safety: block if active operations exist
      const isBusy =
        scanStatus?.state === 'scanning' ||
        pendingOperations.size > 0;

      if (isBusy) {
        const deferredMsg = 'Update Ready — Restart when current operation finishes.';
        setUpdateStatus((prev) =>
          prev
            ? {
                ...prev,
                state: 'deferred_busy',
                deferred_reason: deferredMsg,
              }
            : null
        );
        addNotification('warn', deferredMsg);
        return { applied: false, deferred: true, reason: deferredMsg };
      }

      try {
        const res = await client.updaterApplyUpdate(confirm);
        if (res.deferred) {
          addNotification('warn', res.reason || 'Update deferred: engine busy.');
        } else {
          addNotification('info', 'Restarting application to apply update...');
        }
        return res;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        addNotification('error', `Failed to apply update: ${msg}`);
        throw err;
      }
    },
    [client, scanStatus, pendingOperations, addNotification]
  );

  const setUpdateChannel = useCallback(
    async (channel: UpdateChannel) => {
      try {
        const res = await client.updaterSetChannel(channel);
        setUpdateStatus(res);
        addNotification('info', `Update channel switched to '${channel}'.`);
        return res;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        addNotification('error', `Failed to switch channel: ${msg}`);
        throw err;
      }
    },
    [client, addNotification]
  );

  const cancelUpdate = useCallback(async () => {
    try {
      const res = await client.updaterCancel();
      setUpdateStatus(res);
      addNotification('info', 'Update operation cancelled.');
      return res;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      addNotification('error', `Failed to cancel update: ${msg}`);
      throw err;
    }
  }, [client, addNotification]);

  // Licensing Operations & Entitlements Feature Gate (Stage 3)
  const isEntitled = useCallback(
    (feature: string): boolean => {
      if (!licenseStatus || !licenseStatus.is_active || licenseStatus.clock_rollback_detected) {
        return false;
      }
      return licenseStatus.entitlements.includes(feature);
    },
    [licenseStatus]
  );

  const activateLicenseManual = useCallback(
    async (token: string): Promise<LicenseStatusDto> => {
      addNotification('info', 'Verifying cryptographic license signature...');
      try {
        const res = await trackOperation('activate_license', client.licensingActivateManual(token));
        setLicenseStatus(res);
        addNotification('info', `Pro license activated successfully for account ${res.account_email ?? 'Pro User'}.`);
        return res;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        addNotification('error', `License activation failed: ${msg}`);
        throw err;
      }
    },
    [client, trackOperation, addNotification]
  );

  const startDeviceAuth = useCallback(async (): Promise<DeviceAuthResponseDto> => {
    try {
      return await client.licensingStartDeviceAuth();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      addNotification('error', `Device authorization request failed: ${msg}`);
      throw err;
    }
  }, [client, addNotification]);

  const pollDeviceAuth = useCallback(
    async (deviceCode: string): Promise<DeviceAuthPollResultDto> => {
      try {
        const res = await client.licensingPollDeviceAuth(deviceCode);
        if (res.status === 'authorized') {
          const updated = await client.licensingGetStatus();
          setLicenseStatus(updated);
          addNotification('info', 'Device successfully authorized! Pro features unlocked.');
        }
        return res;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        addNotification('error', `Device polling error: ${msg}`);
        throw err;
      }
    },
    [client, addNotification]
  );

  const deactivateLicense = useCallback(async (): Promise<LicenseStatusDto> => {
    try {
      const res = await client.licensingDeactivate();
      setLicenseStatus(res);
      addNotification('info', 'License removed. Operating in Community Edition.');
      return res;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      addNotification('error', `Failed to deactivate license: ${msg}`);
      throw err;
    }
  }, [client, addNotification]);

  // Subscribe to core streaming events per Requirement 5
  useEffect(() => {
    initCoreConnection();

    const unsubscribe = client.onEvent((event: IpcEvent) => {
      switch (event.type) {
        case 'scan_started':
          setScanStatus({
            state: 'scanning',
            session_id: event.session_id,
            files_scanned: 0,
            candidates_found: 0,
            elapsed_ms: 0,
          });
          addNotification('info', `Scan session ${event.session_id.slice(0, 8)} started in ${event.mode} mode.`);
          break;

        case 'scan_progress':
          setScanStatus({
            state: 'scanning',
            session_id: event.session_id,
            files_scanned: event.files_scanned,
            candidates_found: event.candidates_found,
            elapsed_ms: event.elapsed_ms,
            current_path: event.current_path,
          });
          break;

        case 'scan_completed':
          setScanStatus({
            state: 'completed',
            session_id: event.summary.session_id,
            files_scanned: event.summary.total_files_scanned,
            candidates_found: event.summary.total_candidates_found,
            elapsed_ms: event.summary.elapsed_ms,
          });
          setLatestScanSummary(event.summary);
          addNotification(
            'info',
            `Scan completed: ${event.summary.total_files_scanned} files inspected, ${event.summary.total_candidates_found} candidates found.`
          );
          break;

        case 'scan_cancelled':
          setScanStatus({
            state: 'cancelled',
            session_id: event.session_id,
            files_scanned: event.partial_summary.total_files_scanned,
            candidates_found: event.partial_summary.total_candidates_found,
            elapsed_ms: event.partial_summary.elapsed_ms,
          });
          addNotification('warn', `Scan session ${event.session_id.slice(0, 8)} was cancelled by user.`);
          break;

        case 'elevation_required':
          addNotification('warn', `Action '${event.action_attempted}' requires elevation: ${event.reason}`);
          break;

        case 'diagnostic_message':
          addNotification(event.level, event.message);
          break;

        case 'updater_status_changed':
          setUpdateStatus(event.status);
          break;

        case 'updater_progress':
          setUpdateStatus((prev) =>
            prev
              ? {
                  ...prev,
                  state: 'downloading',
                  download_progress: {
                    percent: event.percent,
                    bytes_transferred: event.bytes_transferred,
                    total_bytes: event.total_bytes,
                  },
                }
              : null
          );
          break;

        case 'updater_error':
          addNotification('error', `Updater [${event.code}]: ${event.message}`);
          break;

        default:
          break;
      }
    });

    return () => {
      unsubscribe();
    };
  }, [client, initCoreConnection, addNotification]);

  const value: AppContextValue = {
    client,
    connectionStatus,
    currentRoute,
    setCurrentRoute,
    systemStatus,
    scanStatus,
    settings,
    latestScanSummary,
    coreError,
    notifications,
    pendingOperations,
    dismissNotification,
    reconnectCore: initCoreConnection,
    trackOperation,
    requestElevation,
    isElevationModalOpen,
    elevationReason,
    openElevationModal,
    closeElevationModal,
    // Secure Auto-Updater
    updateStatus,
    checkForUpdates,
    downloadUpdate,
    applyUpdate,
    setUpdateChannel,
    cancelUpdate,
    // Licensing & Entitlements
    licenseStatus,
    isEntitled,
    activateLicenseManual,
    startDeviceAuth,
    pollDeviceAuth,
    deactivateLicense,
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
};

export const useApp = (): AppContextValue => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
};
