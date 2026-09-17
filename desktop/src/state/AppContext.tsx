import React, { createContext, useContext, useEffect, useState, useCallback, useMemo } from 'react';
import {
  SystemStatusDto,
  ScanStatusDto,
  SettingsDto,
  ScanSummaryDto,
  IpcError,
  IpcEvent,
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
      const [sysStatus, scnStatus, setts] = await Promise.all([
        client.getSystemStatus(),
        client.getScanStatus(),
        client.getSettings(),
      ]);

      setSystemStatus(sysStatus);
      setScanStatus(scnStatus);
      setSettings(setts);
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
