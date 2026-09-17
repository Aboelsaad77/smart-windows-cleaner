import React from 'react';
import { useApp } from '../state/AppContext';
import { Button } from '../design-system/Button';
import { ArrowDownCircle, RefreshCw, AlertTriangle, ShieldCheck, CheckCircle2 } from 'lucide-react';

export const UpdateBanner: React.FC = () => {
  const { updateStatus, downloadUpdate, applyUpdate, cancelUpdate } = useApp();

  if (!updateStatus || updateStatus.state === 'idle' || updateStatus.state === 'not_available') {
    return null;
  }

  const { state, available_update, is_portable, download_progress, deferred_reason } = updateStatus;

  // 1. Deferred busy state (Scan, Quarantine, Restore, or Purge in progress)
  if (state === 'deferred_busy' || deferred_reason) {
    return (
      <div
        data-testid="updater-deferred-banner"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 14px',
          borderRadius: '6px',
          backgroundColor: 'rgba(69, 26, 3, 0.85)',
          border: '1px solid var(--safety-review-border)',
          color: '#fbbf24',
          marginBottom: '14px',
          fontSize: '13px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <AlertTriangle size={18} color="#f59e0b" />
          <div>
            <div style={{ fontWeight: 600 }}>Update Ready — Restart when current operation finishes.</div>
            <div style={{ fontSize: '12px', color: '#fef3c7', opacity: 0.9 }}>
              An active scan or quarantine operation is running. Update execution is safely held until the operation completes.
            </div>
          </div>
        </div>
      </div>
    );
  }

  // 2. Portable mode notification
  if (state === 'available' && is_portable && available_update) {
    return (
      <div
        data-testid="updater-portable-banner"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 14px',
          borderRadius: '6px',
          backgroundColor: 'rgba(30, 58, 95, 0.85)',
          border: '1px solid #0284c7',
          color: '#e0f2fe',
          marginBottom: '14px',
          fontSize: '13px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <ShieldCheck size={18} color="#38bdf8" />
          <div>
            <div style={{ fontWeight: 600 }}>
              New Release v{available_update.version} Available (Portable Mode Active)
            </div>
            <div style={{ fontSize: '12px', color: '#bae6fd', opacity: 0.9 }}>
              Automatic in-place updater is disabled in Portable Mode to preserve system isolation. Please download the verified ZIP package manually.
            </div>
          </div>
        </div>
        <a
          href={available_update.download_url}
          target="_blank"
          rel="noreferrer"
          style={{
            padding: '6px 12px',
            backgroundColor: '#0284c7',
            borderRadius: '4px',
            color: '#ffffff',
            textDecoration: 'none',
            fontSize: '12px',
            fontWeight: 600,
          }}
        >
          View Release
        </a>
      </div>
    );
  }

  // 3. Update Available (Standard NSIS installation)
  if (state === 'available' && available_update) {
    return (
      <div
        data-testid="updater-available-banner"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 14px',
          borderRadius: '6px',
          backgroundColor: 'rgba(23, 37, 84, 0.85)',
          border: '1px solid #2563eb',
          color: '#eff6ff',
          marginBottom: '14px',
          fontSize: '13px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <ArrowDownCircle size={18} color="#60a5fa" />
          <div>
            <div style={{ fontWeight: 600 }}>
              Smart Windows Cleaner v{available_update.version} Available
            </div>
            <div style={{ fontSize: '12px', color: '#bfdbfe', opacity: 0.9 }}>
              Signed by pinned release key. Channel: {available_update.channel} ({((available_update.artifact_size) / 1024 / 1024).toFixed(1)} MB)
            </div>
          </div>
        </div>
        <Button variant="primary" size="sm" onClick={() => downloadUpdate()}>
          Download Update
        </Button>
      </div>
    );
  }

  // 4. Downloading progress
  if (state === 'downloading') {
    const percent = download_progress?.percent ?? 0;
    return (
      <div
        data-testid="updater-downloading-banner"
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
          padding: '10px 14px',
          borderRadius: '6px',
          backgroundColor: 'rgba(30, 41, 59, 0.85)',
          border: '1px solid #475569',
          color: '#f8fafc',
          marginBottom: '14px',
          fontSize: '13px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <RefreshCw size={16} className="animate-spin" color="#38bdf8" />
            <span>Downloading Update... {percent}%</span>
          </div>
          <Button variant="outline" size="sm" onClick={() => cancelUpdate()}>
            Cancel
          </Button>
        </div>
        <div style={{ width: '100%', height: '4px', backgroundColor: '#334155', borderRadius: '2px', overflow: 'hidden' }}>
          <div
            style={{
              width: `${percent}%`,
              height: '100%',
              backgroundColor: '#38bdf8',
              transition: 'width 0.2s ease',
            }}
          />
        </div>
      </div>
    );
  }

  // 5. Downloaded and Verified Ready to Install
  if (state === 'downloaded' && available_update) {
    return (
      <div
        data-testid="updater-downloaded-banner"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 14px',
          borderRadius: '6px',
          backgroundColor: 'rgba(6, 78, 59, 0.85)',
          border: '1px solid #059669',
          color: '#ecfdf5',
          marginBottom: '14px',
          fontSize: '13px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <CheckCircle2 size={18} color="#34d399" />
          <div>
            <div style={{ fontWeight: 600 }}>
              Update v{available_update.version} Verified & Ready
            </div>
            <div style={{ fontSize: '12px', color: '#a7f3d0', opacity: 0.9 }}>
              Cryptographic SHA-256 and SHA-512 hashes verified. User confirmation required to restart.
            </div>
          </div>
        </div>
        <Button
          variant="primary"
          size="sm"
          onClick={() => applyUpdate(true)}
          style={{ backgroundColor: '#059669', borderColor: '#047857' }}
        >
          Restart & Apply Update
        </Button>
      </div>
    );
  }

  return null;
};
