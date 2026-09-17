import React from 'react';
import { IpcError } from '../types/ipc';
import { formatIpcError } from '../ipc/errors';
import { Button } from './Button';
import { AlertCircle, ShieldAlert, RefreshCw } from 'lucide-react';

export interface ErrorStateProps {
  error: IpcError | Error | string;
  onRetry?: () => void;
  onRequestElevation?: () => void;
  style?: React.CSSProperties;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  error,
  onRetry,
  onRequestElevation,
  style,
}) => {
  let normalizedIpcError: IpcError;

  if (!error) {
    normalizedIpcError = { code: 'INTERNAL_CORE_ERROR', message: 'An unexpected error occurred.' };
  } else if (typeof error === 'string') {
    normalizedIpcError = { code: 'INTERNAL_CORE_ERROR', message: error };
  } else if (typeof error === 'object' && 'code' in error && typeof (error as IpcError).code === 'string') {
    normalizedIpcError = error as IpcError;
  } else {
    normalizedIpcError = {
      code: 'INTERNAL_CORE_ERROR',
      message: (error as Error).message || 'An unexpected error occurred in the core layer.',
    };
  }

  const presentation = formatIpcError(normalizedIpcError);

  const getBorderColor = (): string => {
    switch (presentation.severity) {
      case 'warning':
        return 'var(--safety-review-border)';
      case 'info':
        return '#0284c7';
      case 'error':
      default:
        return 'var(--safety-danger-border)';
    }
  };

  const getBgColor = (): string => {
    switch (presentation.severity) {
      case 'warning':
        return 'rgba(69, 26, 3, 0.4)';
      case 'info':
        return 'rgba(12, 74, 110, 0.4)';
      case 'error':
      default:
        return 'rgba(69, 10, 10, 0.4)';
    }
  };

  return (
    <div
      role="alert"
      style={{
        border: `1px solid ${getBorderColor()}`,
        backgroundColor: getBgColor(),
        borderRadius: '8px',
        padding: '20px',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
        ...style,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
        <div style={{ flexShrink: 0, marginTop: '2px' }}>
          {presentation.requiresElevation ? (
            <ShieldAlert size={22} color="#f97316" />
          ) : (
            <AlertCircle size={22} color="#ef4444" />
          )}
        </div>

        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
              {presentation.title}
            </h4>
            <span
              style={{
                fontFamily: 'monospace',
                fontSize: '11px',
                padding: '1px 6px',
                borderRadius: '3px',
                backgroundColor: 'rgba(0,0,0,0.3)',
                color: 'var(--text-secondary)',
                border: '1px solid var(--border-color)',
              }}
            >
              {normalizedIpcError.code}
            </span>
          </div>

          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            {presentation.description}
          </p>

          {presentation.suggestedAction && (
            <div
              style={{
                marginTop: '8px',
                fontSize: '12px',
                color: 'var(--text-muted)',
                backgroundColor: 'rgba(0,0,0,0.2)',
                padding: '6px 10px',
                borderRadius: '4px',
              }}
            >
              <strong>Remedy: </strong>
              {presentation.suggestedAction}
            </div>
          )}
        </div>
      </div>

      {(onRetry || (presentation.requiresElevation && onRequestElevation)) && (
        <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end', marginTop: '4px' }}>
          {presentation.requiresElevation && onRequestElevation && (
            <Button
              variant="primary"
              size="sm"
              leftIcon={<ShieldAlert size={14} />}
              onClick={onRequestElevation}
            >
              Request Administrator Access
            </Button>
          )}

          {presentation.canRetry && onRetry && (
            <Button
              variant="secondary"
              size="sm"
              leftIcon={<RefreshCw size={14} />}
              onClick={onRetry}
            >
              Retry Action
            </Button>
          )}
        </div>
      )}
    </div>
  );
};
