import React from 'react';
import { RiskBand, SafetyVerdict } from '../types/ipc';

export type BadgeVariant =
  | 'safe'
  | 'review'
  | 'dangerous'
  | 'protected'
  | 'elevation'
  | 'neutral'
  | 'info'
  | 'success';

export interface BadgeProps {
  children?: React.ReactNode;
  variant?: BadgeVariant;
  riskBand?: RiskBand;
  safetyVerdict?: SafetyVerdict;
  title?: string;
  style?: React.CSSProperties;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant,
  riskBand,
  safetyVerdict,
  title,
  style,
}) => {
  let resolvedVariant: BadgeVariant = variant ?? 'neutral';
  let content = children;

  if (riskBand) {
    switch (riskBand) {
      case 'Safe':
        resolvedVariant = 'safe';
        break;
      case 'Review':
        resolvedVariant = 'review';
        break;
      case 'Dangerous':
        resolvedVariant = 'dangerous';
        break;
      case 'Protected':
        resolvedVariant = 'protected';
        break;
    }
    if (!content) content = riskBand;
  } else if (safetyVerdict) {
    switch (safetyVerdict) {
      case 'auto_quarantine':
        resolvedVariant = 'safe';
        if (!content) content = 'Auto Quarantine';
        break;
      case 'user_confirm':
        resolvedVariant = 'review';
        if (!content) content = 'User Confirm';
        break;
      case 'never_delete':
        resolvedVariant = 'protected';
        if (!content) content = 'Protected (Never Delete)';
        break;
    }
  }

  const getStyles = (): React.CSSProperties => {
    switch (resolvedVariant) {
      case 'safe':
        return {
          backgroundColor: 'var(--safety-safe-bg)',
          color: 'var(--safety-safe-text)',
          border: '1px solid var(--safety-safe-border)',
        };
      case 'review':
        return {
          backgroundColor: 'var(--safety-review-bg)',
          color: 'var(--safety-review-text)',
          border: '1px solid var(--safety-review-border)',
        };
      case 'dangerous':
        return {
          backgroundColor: 'var(--safety-danger-bg)',
          color: 'var(--safety-danger-text)',
          border: '1px solid var(--safety-danger-border)',
        };
      case 'protected':
        return {
          backgroundColor: 'var(--safety-protected-bg)',
          color: 'var(--safety-protected-text)',
          border: '1px solid var(--safety-protected-border)',
          fontWeight: 600,
        };
      case 'elevation':
        return {
          backgroundColor: '#3b2505',
          color: '#fed7aa',
          border: '1px solid #f97316',
        };
      case 'info':
        return {
          backgroundColor: '#0c4a6e',
          color: '#7dd3fc',
          border: '1px solid #0284c7',
        };
      case 'neutral':
      default:
        return {
          backgroundColor: 'var(--bg-tertiary)',
          color: 'var(--text-secondary)',
          border: '1px solid var(--border-color)',
        };
    }
  };

  const baseStyle: React.CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '4px',
    padding: '2px 8px',
    borderRadius: '9999px',
    fontSize: '11px',
    fontWeight: 500,
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    lineHeight: '16px',
    ...getStyles(),
    ...style,
  };

  return (
    <span style={baseStyle} title={title}>
      {content}
    </span>
  );
};
