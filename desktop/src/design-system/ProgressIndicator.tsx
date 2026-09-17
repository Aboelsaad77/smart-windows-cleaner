import React from 'react';

export interface ProgressIndicatorProps {
  progressPercent?: number; // Exact 0-100 percentage. If undefined, renders an indeterminate pulse/bar.
  statusLabel?: string;
  detailLabel?: string;
  style?: React.CSSProperties;
}

export const ProgressIndicator: React.FC<ProgressIndicatorProps> = ({
  progressPercent,
  statusLabel,
  detailLabel,
  style,
}) => {
  const isDeterminate = typeof progressPercent === 'number' && !isNaN(progressPercent);
  const clampedPercent = isDeterminate ? Math.min(100, Math.max(0, progressPercent)) : 0;

  return (
    <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '6px', ...style }}>
      {(statusLabel || detailLabel || isDeterminate) && (
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
          <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
            {statusLabel ?? 'Working...'}
          </span>
          <span style={{ color: 'var(--text-secondary)' }}>
            {isDeterminate ? `${Math.round(clampedPercent)}%` : detailLabel ?? 'Scanning...'}
          </span>
        </div>
      )}

      <div
        style={{
          width: '100%',
          height: '6px',
          backgroundColor: 'var(--bg-tertiary)',
          borderRadius: '3px',
          overflow: 'hidden',
          position: 'relative',
        }}
      >
        {isDeterminate ? (
          <div
            style={{
              width: `${clampedPercent}%`,
              height: '100%',
              backgroundColor: '#2563eb',
              transition: 'width 0.2s ease',
              borderRadius: '3px',
            }}
          />
        ) : (
          <div
            style={{
              width: '35%',
              height: '100%',
              backgroundColor: '#3b82f6',
              borderRadius: '3px',
              animation: 'indeterminate-slide 1.5s infinite ease-in-out',
            }}
          />
        )}
      </div>

      <style>{`
        @keyframes indeterminate-slide {
          0% { transform: translateX(-100%); }
          50% { transform: translateX(180%); }
          100% { transform: translateX(350%); }
        }
      `}</style>
    </div>
  );
};
