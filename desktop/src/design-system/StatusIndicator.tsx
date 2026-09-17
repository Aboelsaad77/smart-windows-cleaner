import React from 'react';

export type CoreConnectionStatus = 'connected' | 'disconnected' | 'connecting' | 'error';

export interface StatusIndicatorProps {
  status: CoreConnectionStatus;
  label?: string;
  subtext?: string;
  style?: React.CSSProperties;
}

export const StatusIndicator: React.FC<StatusIndicatorProps> = ({
  status,
  label,
  subtext,
  style,
}) => {
  const getDotColor = (): string => {
    switch (status) {
      case 'connected':
        return '#10b981'; // emerald-500
      case 'connecting':
        return '#f59e0b'; // amber-500
      case 'error':
        return '#ef4444'; // red-500
      case 'disconnected':
      default:
        return '#64748b'; // slate-500
    }
  };

  const getDefaultLabel = (): string => {
    switch (status) {
      case 'connected':
        return 'Core Connected';
      case 'connecting':
        return 'Connecting to Core...';
      case 'error':
        return 'Core Initialization Error';
      case 'disconnected':
      default:
        return 'Core Unavailable';
    }
  };

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '8px',
        fontSize: '12px',
        color: 'var(--text-secondary)',
        ...style,
      }}
      title={subtext}
    >
      <span
        style={{
          width: '8px',
          height: '8px',
          borderRadius: '50%',
          backgroundColor: getDotColor(),
          display: 'inline-block',
          boxShadow: status === 'connected' ? '0 0 6px rgba(16, 185, 129, 0.4)' : 'none',
        }}
      />
      <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
        {label || getDefaultLabel()}
      </span>
      {subtext && <span style={{ color: 'var(--text-muted)' }}>({subtext})</span>}
    </div>
  );
};
