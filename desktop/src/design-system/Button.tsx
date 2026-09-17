import React from 'react';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline';
  size?: 'sm' | 'md' | 'lg';
  isLoading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'secondary',
  size = 'md',
  isLoading = false,
  leftIcon,
  rightIcon,
  disabled,
  style,
  ...props
}) => {
  const getVariantStyles = (): React.CSSProperties => {
    switch (variant) {
      case 'primary':
        return {
          backgroundColor: 'var(--btn-primary-bg)',
          color: 'var(--btn-primary-text)',
          border: '1px solid #3b82f6',
        };
      case 'danger':
        return {
          backgroundColor: '#991b1b',
          color: '#fee2e2',
          border: '1px solid #dc2626',
        };
      case 'ghost':
        return {
          backgroundColor: 'transparent',
          color: 'var(--text-secondary)',
          border: '1px solid transparent',
        };
      case 'outline':
        return {
          backgroundColor: 'transparent',
          color: 'var(--text-primary)',
          border: '1px solid var(--border-color)',
        };
      case 'secondary':
      default:
        return {
          backgroundColor: 'var(--bg-secondary)',
          color: 'var(--text-primary)',
          border: '1px solid var(--border-color)',
        };
    }
  };

  const getSizeStyles = (): React.CSSProperties => {
    switch (size) {
      case 'sm':
        return { padding: '4px 8px', fontSize: '12px' };
      case 'lg':
        return { padding: '10px 20px', fontSize: '15px' };
      case 'md':
      default:
        return { padding: '6px 14px', fontSize: '13px' };
    }
  };

  const baseStyle: React.CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '6px',
    borderRadius: '4px',
    fontWeight: 500,
    cursor: disabled || isLoading ? 'not-allowed' : 'pointer',
    opacity: disabled || isLoading ? 0.6 : 1,
    transition: 'background-color 0.15s ease, border-color 0.15s ease',
    ...getVariantStyles(),
    ...getSizeStyles(),
    ...style,
  };

  return (
    <button disabled={disabled || isLoading} style={baseStyle} {...props}>
      {isLoading ? (
        <span style={{ display: 'inline-block', animation: 'spin 1s linear infinite' }}>⏳</span>
      ) : (
        leftIcon
      )}
      {children}
      {!isLoading && rightIcon}
    </button>
  );
};
