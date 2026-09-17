import React, { useState } from 'react';
import { Modal } from '../design-system/Modal';
import { Button } from '../design-system/Button';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Lock,
  AlertTriangle,
  KeyRound,
} from 'lucide-react';

export interface ElevationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => Promise<void>;
  reason?: string;
}

export const ElevationModal: React.FC<ElevationModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  reason,
}) => {
  const [isBusy, setIsBusy] = useState<boolean>(false);
  const [elevationError, setElevationError] = useState<string | null>(null);

  const handleElevate = async () => {
    setIsBusy(true);
    setElevationError(null);
    try {
      await onConfirm();
      onClose();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setElevationError(msg);
    } finally {
      setIsBusy(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Administrator Elevation Request (Windows UAC)"
      description="Elevate Smart Windows Cleaner to analyze and quarantine protected system locations"
      width="640px"
      footer={
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
          <Button variant="ghost" size="sm" onClick={onClose} disabled={isBusy}>
            Remain in Standard User Mode
          </Button>
          <div style={{ display: 'flex', gap: '10px' }}>
            <Button
              variant="primary"
              size="md"
              leftIcon={<Shield size={15} />}
              isLoading={isBusy}
              onClick={handleElevate}
            >
              Elevate via UAC Prompt
            </Button>
          </div>
        </div>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
        {/* Elevation Reason Alert if triggered by specific failure */}
        {reason && (
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
              padding: '10px 14px',
              backgroundColor: 'rgba(249, 115, 22, 0.1)',
              border: '1px solid rgba(249, 115, 22, 0.3)',
              borderRadius: '6px',
              fontSize: '12px',
              color: 'var(--text-primary)',
            }}
          >
            <ShieldAlert size={16} color="#f97316" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong>Action Required: </strong>
              <span>{reason}</span>
            </div>
          </div>
        )}

        {/* Elevation Error State if UAC failed */}
        {elevationError && (
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
              padding: '10px 14px',
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: '6px',
              fontSize: '12px',
              color: '#ef4444',
            }}
          >
            <AlertTriangle size={16} color="#ef4444" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong>Elevation Failed or Dismissed: </strong>
              <span>{elevationError}</span>
            </div>
          </div>
        )}

        {/* Standard vs Elevated Comparison Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
          {/* What Administrator Mode Unlocks */}
          <div
            style={{
              padding: '14px',
              backgroundColor: 'var(--bg-primary)',
              borderRadius: '6px',
              border: '1px solid var(--border-color)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <KeyRound size={16} color="#3b82f6" />
              <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Locations Unlocked by UAC
              </span>
            </div>
            <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              <li>
                <strong>Windows System Temp</strong> (<code style={{ fontSize: '11px' }}>C:\Windows\Temp</code>)
              </li>
              <li>
                <strong>Windows Update Staging</strong> (<code style={{ fontSize: '11px' }}>SoftwareDistribution\Download</code>)
              </li>
              <li>
                <strong>Crash Dumps</strong> (<code style={{ fontSize: '11px' }}>MEMORY.DMP</code>, Kernel Minidumps)
              </li>
              <li>
                <strong>Multi-User Caches</strong> (cross-profile application caches)
              </li>
            </ul>
          </div>

          {/* Hard Safety Engine Boundaries */}
          <div
            style={{
              padding: '14px',
              backgroundColor: 'var(--bg-primary)',
              borderRadius: '6px',
              border: '1px solid var(--border-color)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <Lock size={16} color="#10b981" />
              <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Safety Boundaries (Permanent)
              </span>
            </div>
            <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              <li>
                <strong>WinSxS Component Store</strong> (Zero raw file deletion allowed)
              </li>
              <li>
                <strong>Core OS Binaries</strong> (<code style={{ fontSize: '11px' }}>System32</code>, bootloader files)
              </li>
              <li>
                <strong>User Personal Data</strong> (Documents, Desktop, Photos)
              </li>
              <li>
                <strong>In-Use Files</strong> (Exclusive process locks respected)
              </li>
            </ul>
          </div>
        </div>

        {/* Security Transparency & Architecture Guarantee */}
        <div
          style={{
            padding: '12px 14px',
            backgroundColor: 'rgba(59, 130, 246, 0.08)',
            border: '1px solid rgba(59, 130, 246, 0.25)',
            borderRadius: '6px',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '10px',
          }}
        >
          <ShieldCheck size={18} color="var(--accent-blue)" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            <strong style={{ color: 'var(--text-primary)' }}>Safety Architecture Guarantee: </strong>
            Elevating permissions does not grant unrestricted deletion. Smart Windows Cleaner UI is strictly a presentation layer.
            Every operation runs through the Rust Core Safety Engine, with preflight checks, SHA-256 integrity receipts,
            and reversible quarantine retention.
          </div>
        </div>
      </div>
    </Modal>
  );
};
