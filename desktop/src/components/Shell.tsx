import React from 'react';
import { useApp } from '../state/AppContext';
import { AppHeader } from './AppHeader';
import { Sidebar } from './Sidebar';
import { StatusBar } from './StatusBar';
import { ElevationModal } from './ElevationModal';
import { UpdateBanner } from './UpdateBanner';
import { ErrorState } from '../design-system/ErrorState';
import { DashboardView } from '../views/DashboardView';
import { ScanView } from '../views/ScanView';
import { ResultsView } from '../views/ResultsView';
import { QuarantineView } from '../views/QuarantineView';
import { StorageView } from '../views/StorageView';
import { LogsView } from '../views/LogsView';
import { SettingsView } from '../views/SettingsView';
import { X, AlertCircle, Info, AlertTriangle } from 'lucide-react';

export const Shell: React.FC = () => {
  const {
    currentRoute,
    connectionStatus,
    coreError,
    reconnectCore,
    requestElevation,
    isElevationModalOpen,
    elevationReason,
    openElevationModal,
    closeElevationModal,
    notifications,
    dismissNotification,
  } = useApp();

  const renderActiveView = () => {
    switch (currentRoute) {
      case 'dashboard':
        return <DashboardView />;
      case 'scan':
        return <ScanView />;
      case 'results':
        return <ResultsView />;
      case 'quarantine':
        return <QuarantineView />;
      case 'storage':
        return <StorageView />;
      case 'logs':
        return <LogsView />;
      case 'settings':
        return <SettingsView />;
      default:
        return <DashboardView />;
    }
  };

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        width: '100vw',
        overflow: 'hidden',
        backgroundColor: 'var(--bg-primary)',
      }}
    >
      <AppHeader />

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <Sidebar />

        <main
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            overflowY: 'auto',
            padding: '20px 24px',
            position: 'relative',
          }}
        >
          {/* Secure Auto-Updater Active Banner (Stage 2) */}
          <UpdateBanner />

          {/* Active Notifications Banner */}
          {notifications.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '16px' }}>
              {notifications.slice(0, 3).map((notif) => (
                <div
                  key={notif.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    backgroundColor:
                      notif.type === 'error'
                        ? 'rgba(69, 10, 10, 0.7)'
                        : notif.type === 'warn'
                        ? 'rgba(69, 26, 3, 0.7)'
                        : 'rgba(30, 58, 95, 0.7)',
                    border:
                      notif.type === 'error'
                        ? '1px solid var(--safety-danger-border)'
                        : notif.type === 'warn'
                        ? '1px solid var(--safety-review-border)'
                        : '1px solid #0284c7',
                    fontSize: '12px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {notif.type === 'error' ? (
                      <AlertCircle size={15} color="#ef4444" />
                    ) : notif.type === 'warn' ? (
                      <AlertTriangle size={15} color="#f59e0b" />
                    ) : (
                      <Info size={15} color="#38bdf8" />
                    )}
                    <span>{notif.message}</span>
                  </div>
                  <button
                    onClick={() => dismissNotification(notif.id)}
                    aria-label="Dismiss notification"
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-muted)',
                      cursor: 'pointer',
                      display: 'flex',
                      padding: '2px',
                    }}
                  >
                    <X size={14} />
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Core Error State if connection dropped or failed */}
          {connectionStatus === 'error' && coreError ? (
            <div style={{ marginBottom: '16px' }}>
              <ErrorState
                error={coreError}
                onRetry={reconnectCore}
                onRequestElevation={() => openElevationModal('Windows Core reported permission denied on subsystem location')}
              />
            </div>
          ) : null}

          {/* Active View Content */}
          <div style={{ flex: 1 }}>{renderActiveView()}</div>
        </main>
      </div>

      <StatusBar />

      {/* Administrator Elevation Modal */}
      <ElevationModal
        isOpen={isElevationModalOpen}
        onClose={closeElevationModal}
        onConfirm={requestElevation}
        reason={elevationReason}
      />
    </div>
  );
};
