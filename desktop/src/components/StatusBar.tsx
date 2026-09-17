import React from 'react';
import { useApp } from '../state/AppContext';
import { HardDrive, RefreshCw } from 'lucide-react';

export const StatusBar: React.FC = () => {
  const { systemStatus, pendingOperations, connectionStatus, reconnectCore } = useApp();

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  return (
    <footer
      style={{
        height: '28px',
        backgroundColor: 'var(--bg-secondary)',
        borderTop: '1px solid var(--border-color)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 12px',
        fontSize: '11px',
        color: 'var(--text-muted)',
        userSelect: 'none',
        flexShrink: 0,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <span>OS: {systemStatus?.os_version ?? 'Querying Windows Native Core...'}</span>
        {systemStatus && (
          <>
            <span style={{ color: 'var(--border-color)' }}>|</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <HardDrive size={12} />
              Vault: {systemStatus.quarantine_item_count} items ({formatBytes(systemStatus.quarantine_total_bytes)})
            </span>
          </>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        {pendingOperations.size > 0 && (
          <span style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span style={{ animation: 'spin 1s linear infinite', display: 'inline-block' }}>⏳</span>
            Operations in progress ({pendingOperations.size})...
          </span>
        )}

        {connectionStatus === 'error' && (
          <button
            onClick={reconnectCore}
            style={{
              background: 'none',
              border: 'none',
              color: '#f87171',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              fontSize: '11px',
            }}
          >
            <RefreshCw size={11} /> Reconnect Native Core
          </button>
        )}
      </div>
    </footer>
  );
};
