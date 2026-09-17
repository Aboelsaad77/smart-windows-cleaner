import React from 'react';
import { Modal } from './Modal';
import { Button } from './Button';
import { AlertTriangle, Info } from 'lucide-react';

export interface ConfirmationDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'danger' | 'warning' | 'primary';
  isLoading?: boolean;
  requiresExplicitCheck?: boolean;
  explicitCheckLabel?: string;
}

export const ConfirmationDialog: React.FC<ConfirmationDialogProps> = ({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  variant = 'primary',
  isLoading = false,
  requiresExplicitCheck = false,
  explicitCheckLabel = 'I understand this operation will proceed through the Safety Engine',
}) => {
  const [isChecked, setIsChecked] = React.useState(false);

  // Reset check whenever modal opens
  React.useEffect(() => {
    if (isOpen) setIsChecked(false);
  }, [isOpen]);

  const canConfirm = !requiresExplicitCheck || isChecked;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={title}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={isLoading}>
            {cancelLabel}
          </Button>
          <Button
            variant={variant === 'danger' ? 'danger' : 'primary'}
            onClick={onConfirm}
            disabled={!canConfirm || isLoading}
            isLoading={isLoading}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div style={{ display: 'flex', gap: '14px', alignItems: 'flex-start' }}>
        <div style={{ flexShrink: 0, marginTop: '2px' }}>
          {variant === 'danger' ? (
            <AlertTriangle size={24} color="#ef4444" />
          ) : (
            <Info size={24} color="#3b82f6" />
          )}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <p style={{ fontSize: '13px', color: 'var(--text-primary)', lineHeight: 1.5 }}>
            {message}
          </p>

          {requiresExplicitCheck && (
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontSize: '12px',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                marginTop: '6px',
                backgroundColor: 'rgba(0,0,0,0.2)',
                padding: '8px 10px',
                borderRadius: '4px',
                border: '1px solid var(--border-color)',
              }}
            >
              <input
                type="checkbox"
                checked={isChecked}
                onChange={(e) => setIsChecked(e.target.checked)}
              />
              <span>{explicitCheckLabel}</span>
            </label>
          )}
        </div>
      </div>
    </Modal>
  );
};
