import React from 'react';
import { Loader2 } from 'lucide-react';

export interface LoadingStateProps {
  label?: string;
  subtext?: string;
  style?: React.CSSProperties;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  label = 'Loading...',
  subtext,
  style,
}) => {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '48px 24px',
        textAlign: 'center',
        gap: '12px',
        ...style,
      }}
    >
      <Loader2
        size={28}
        color="var(--btn-primary-bg)"
        style={{ animation: 'spin 1s linear infinite' }}
      />
      <div>
        <p style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-primary)' }}>{label}</p>
        {subtext && (
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
            {subtext}
          </p>
        )}
      </div>
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};
