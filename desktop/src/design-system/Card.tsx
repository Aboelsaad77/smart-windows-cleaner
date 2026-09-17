import React from 'react';

export interface CardProps {
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  actions?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  style?: React.CSSProperties;
  className?: string;
}

export const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  actions,
  children,
  footer,
  style,
}) => {
  return (
    <div
      style={{
        backgroundColor: 'var(--bg-secondary)',
        border: '1px solid var(--border-color)',
        borderRadius: '6px',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
        ...style,
      }}
    >
      {(title || subtitle || actions) && (
        <div
          style={{
            padding: '12px 16px',
            borderBottom: '1px solid var(--border-color)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div>
            {title && (
              <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
                {title}
              </h3>
            )}
            {subtitle && (
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
                {subtitle}
              </p>
            )}
          </div>
          {actions && <div style={{ display: 'flex', gap: '8px' }}>{actions}</div>}
        </div>
      )}
      <div style={{ padding: '16px', flex: 1 }}>{children}</div>
      {footer && (
        <div
          style={{
            padding: '10px 16px',
            borderTop: '1px solid var(--border-color)',
            backgroundColor: 'rgba(0,0,0,0.15)',
            fontSize: '12px',
            color: 'var(--text-secondary)',
          }}
        >
          {footer}
        </div>
      )}
    </div>
  );
};
