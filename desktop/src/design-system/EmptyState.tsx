import React from 'react';
import { Inbox } from 'lucide-react';

export interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description: string;
  action?: React.ReactNode;
  style?: React.CSSProperties;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  action,
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
        border: '1px dashed var(--border-color)',
        borderRadius: '8px',
        backgroundColor: 'rgba(30, 41, 59, 0.4)',
        ...style,
      }}
    >
      <div style={{ color: 'var(--text-muted)', marginBottom: '14px' }}>
        {icon ?? <Inbox size={36} />}
      </div>
      <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
        {title}
      </h3>
      <p style={{ fontSize: '13px', color: 'var(--text-secondary)', maxWidth: '420px', marginBottom: action ? '16px' : '0' }}>
        {description}
      </p>
      {action && <div>{action}</div>}
    </div>
  );
};
