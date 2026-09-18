import React, { useState } from 'react';
import { useApp } from '../state/AppContext';
import { Card } from '../design-system/Card';
import { Badge } from '../design-system/Badge';
import { Button } from '../design-system/Button';
import {
  Settings as SettingsIcon,
  ShieldCheck,
  ArrowDownCircle,
  RefreshCw,
  KeyRound,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { UpdateChannel } from '../types/ipc';

export const SettingsView: React.FC = () => {
  const {
    settings,
    updateStatus,
    checkForUpdates,
    setUpdateChannel,
    pendingOperations,
    licenseStatus,
    activateLicenseManual,
    startDeviceAuth,
    pollDeviceAuth,
    deactivateLicense,
  } = useApp();

  const isChecking = pendingOperations.has('check_updates') || updateStatus?.state === 'checking';
  const currentChannel = updateStatus?.channel ?? 'stable';

  // Licensing activation modal / panel state
  const [showActivation, setShowActivation] = useState(false);
  const [activationMethod, setActivationMethod] = useState<'device' | 'manual'>('device');
  const [manualKeyInput, setManualKeyInput] = useState('');
  const [activationError, setActivationError] = useState<string | null>(null);
  const [deviceAuthInfo, setDeviceAuthInfo] = useState<{
    device_code: string;
    user_code: string;
    verification_uri: string;
  } | null>(null);
  const [isPollingDevice, setIsPollingDevice] = useState(false);

  const isPro = licenseStatus?.plan === 'pro' || licenseStatus?.plan === 'enterprise';

  const handleStartDeviceAuth = async () => {
    setActivationError(null);
    try {
      const res = await startDeviceAuth();
      setDeviceAuthInfo(res);
      setIsPollingDevice(true);

      // Start automatic polling interval
      const pollTimer = setInterval(async () => {
        try {
          const pollRes = await pollDeviceAuth(res.device_code);
          if (pollRes.status === 'authorized') {
            clearInterval(pollTimer);
            setIsPollingDevice(false);
            setShowActivation(false);
          } else if (pollRes.status === 'expired' || pollRes.status === 'denied') {
            clearInterval(pollTimer);
            setIsPollingDevice(false);
            setActivationError(pollRes.error || 'Device authorization timed out or was denied');
          }
        } catch (err) {
          clearInterval(pollTimer);
          setIsPollingDevice(false);
          setActivationError(err instanceof Error ? err.message : String(err));
        }
      }, 5000);
    } catch (err) {
      setActivationError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleManualActivate = async () => {
    setActivationError(null);
    if (!manualKeyInput.trim()) {
      setActivationError('Please paste your signed license payload or token');
      return;
    }
    try {
      await activateLicenseManual(manualKeyInput.trim());
      setShowActivation(false);
      setManualKeyInput('');
    } catch (err) {
      setActivationError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div>
        <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
          Settings & Policies
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
          Configure safety parameters, retention periods, path exclusions, license entitlements, and updates.
        </p>
      </div>

      {/* Licensing & Entitlements Card (Stage 3) */}
      <Card
        title="Subscription & Entitlements"
        subtitle="Manage product licensing, offline grace periods, and non-safety advanced capabilities"
        actions={<KeyRound size={16} color="var(--text-muted)" />}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Unconditional Core Safety Reassurance Banner */}
          <div
            style={{
              padding: '10px 14px',
              backgroundColor: 'rgba(16, 185, 129, 0.1)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              borderRadius: '6px',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
            }}
          >
            <ShieldCheck size={18} color="#10b981" />
            <div style={{ fontSize: '12px', color: 'var(--text-primary)', lineHeight: 1.4 }}>
              <strong>Unconditional Safety Invariant:</strong> The core Safety Engine, NeverDelete rules,
              Preflight locks, and Quarantine Vault are 100% free and fully functional on all plans. Licensing
              only governs non-safety reporting and automated scheduling.
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Current Edition: {isPro ? 'Pro Edition' : 'Community Edition'}
                </span>
                <Badge variant={isPro ? 'safe' : 'neutral'}>
                  {isPro ? 'PRO ACTIVE' : 'FREE COMMUNITY'}
                </Badge>
                {licenseStatus?.is_in_grace_period && (
                  <Badge variant="review">OFFLINE GRACE PERIOD</Badge>
                )}
                {licenseStatus?.clock_rollback_detected && (
                  <Badge variant="dangerous">CLOCK ROLLBACK DETECTED</Badge>
                )}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                {licenseStatus?.account_email
                  ? `Licensed to: ${licenseStatus.account_email}`
                  : 'Free community license for personal and standard system maintenance.'}
              </div>
            </div>

            <div style={{ display: 'flex', gap: '8px' }}>
              {!isPro ? (
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => {
                    setShowActivation(!showActivation);
                    setActivationError(null);
                  }}
                >
                  Activate Pro
                </Button>
              ) : (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => deactivateLicense()}
                >
                  Deactivate License
                </Button>
              )}
            </div>
          </div>

          {/* Machine Identifier */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              borderTop: '1px solid var(--border-color)',
              paddingTop: '12px',
            }}
          >
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Machine Fingerprint (Device ID)
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                SHA-256 bound device identifier for deterministic seat validation.
              </div>
            </div>
            <span
              style={{
                fontFamily: 'monospace',
                fontSize: '11px',
                padding: '4px 8px',
                backgroundColor: 'rgba(0,0,0,0.3)',
                borderRadius: '4px',
                color: 'var(--text-secondary)',
              }}
            >
              {licenseStatus?.device_id ? `${licenseStatus.device_id.slice(0, 16)}...` : 'Unknown'}
            </span>
          </div>

          {/* Activation Form Dialog */}
          {showActivation && (
            <div
              style={{
                border: '1px solid var(--accent-primary, #3b82f6)',
                borderRadius: '6px',
                padding: '14px',
                backgroundColor: 'rgba(59, 130, 246, 0.05)',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Activate Pro License
                </span>
                <div style={{ display: 'flex', gap: '6px' }}>
                  <button
                    onClick={() => setActivationMethod('device')}
                    style={{
                      padding: '3px 8px',
                      fontSize: '11px',
                      borderRadius: '4px',
                      border: '1px solid var(--border-color)',
                      cursor: 'pointer',
                      backgroundColor: activationMethod === 'device' ? 'var(--accent-primary, #2563eb)' : 'transparent',
                      color: activationMethod === 'device' ? '#fff' : 'var(--text-secondary)',
                    }}
                  >
                    Web Device Flow
                  </button>
                  <button
                    onClick={() => setActivationMethod('manual')}
                    style={{
                      padding: '3px 8px',
                      fontSize: '11px',
                      borderRadius: '4px',
                      border: '1px solid var(--border-color)',
                      cursor: 'pointer',
                      backgroundColor: activationMethod === 'manual' ? 'var(--accent-primary, #2563eb)' : 'transparent',
                      color: activationMethod === 'manual' ? '#fff' : 'var(--text-secondary)',
                    }}
                  >
                    Manual Token / Air-gap
                  </button>
                </div>
              </div>

              {activationError && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    color: '#ef4444',
                    fontSize: '12px',
                  }}
                >
                  <AlertTriangle size={14} />
                  <span>{activationError}</span>
                </div>
              )}

              {activationMethod === 'device' ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    Authorize this installation via RFC 8628 Device Authorization. No password required on this machine.
                  </p>
                  {!deviceAuthInfo ? (
                    <Button variant="primary" size="sm" onClick={handleStartDeviceAuth}>
                      Generate Device Link Code
                    </Button>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <div
                        style={{
                          fontSize: '18px',
                          letterSpacing: '2px',
                          fontWeight: 700,
                          textAlign: 'center',
                          padding: '10px',
                          backgroundColor: 'rgba(0,0,0,0.3)',
                          borderRadius: '4px',
                          color: '#60a5fa',
                        }}
                      >
                        {deviceAuthInfo.user_code}
                      </div>
                      <div style={{ fontSize: '11px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                        Enter code at{' '}
                        <a
                          href={deviceAuthInfo.verification_uri}
                          target="_blank"
                          rel="noreferrer"
                          style={{ color: '#3b82f6', textDecoration: 'underline' }}
                        >
                          {deviceAuthInfo.verification_uri} <ExternalLink size={10} style={{ display: 'inline' }} />
                        </a>
                      </div>
                      {isPollingDevice && (
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
                          <RefreshCw size={12} className="animate-spin" />
                          Waiting for browser authorization...
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    Paste your cryptographically signed Ed25519 license envelope JSON or base64 token:
                  </p>
                  <textarea
                    rows={3}
                    value={manualKeyInput}
                    onChange={(e) => setManualKeyInput(e.target.value)}
                    placeholder="eyJzY2hlbWFfdmVyc2lvbiI6ICIxLjAuMCIsIC..."
                    style={{
                      width: '100%',
                      fontFamily: 'monospace',
                      fontSize: '11px',
                      padding: '6px 8px',
                      backgroundColor: 'rgba(0,0,0,0.3)',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '4px',
                      resize: 'vertical',
                    }}
                  />
                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                    <Button variant="outline" size="sm" onClick={() => setShowActivation(false)}>
                      Cancel
                    </Button>
                    <Button variant="primary" size="sm" onClick={handleManualActivate}>
                      Verify & Activate
                    </Button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Feature Entitlements Breakdown */}
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
              borderTop: '1px solid var(--border-color)',
              paddingTop: '12px',
            }}
          >
            <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Non-Safety Feature Entitlements Status
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px', marginTop: '4px' }}>
              {[
                { id: 'pro.deep_forensics', label: 'Deep Forensics Telemetry' },
                { id: 'pro.scheduled_scans', label: 'Automated Background Scheduler' },
                { id: 'pro.advanced_reporting', label: 'Executive Audit PDF/HTML Export' },
              ].map((feat) => {
                const entitled = Boolean(licenseStatus?.entitlements.includes(feat.id));
                return (
                  <div
                    key={feat.id}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '4px',
                      border: '1px solid var(--border-color)',
                      backgroundColor: entitled ? 'rgba(16, 185, 129, 0.05)' : 'rgba(0,0,0,0.1)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '4px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <CheckCircle2 size={13} color={entitled ? '#10b981' : 'var(--text-muted)'} />
                      <span style={{ fontSize: '11px', fontWeight: 600, color: entitled ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                        {feat.label}
                      </span>
                    </div>
                    <span style={{ fontSize: '10px', color: entitled ? '#10b981' : 'var(--text-muted)' }}>
                      {entitled ? 'Enabled' : 'Pro Feature'}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </Card>

      {/* Updates & Releases Card (Stage 2) */}
      <Card
        title="Updates & Releases (Ed25519 Authenticity)"
        subtitle="Cryptographically verified updates with pinned public keys & downgrade prevention"
        actions={<ArrowDownCircle size={16} color="var(--text-muted)" />}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Installed Version
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                v1.0.2 (Core Native Release)
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              {updateStatus?.is_portable && (
                <Badge variant="elevation" title="Running in Portable Mode without registry installation">
                  Portable Mode
                </Badge>
              )}
              <Button
                variant="outline"
                size="sm"
                onClick={() => checkForUpdates()}
                disabled={isChecking}
              >
                {isChecking ? (
                  <>
                    <RefreshCw size={14} className="animate-spin" style={{ marginRight: '6px' }} />
                    Checking...
                  </>
                ) : (
                  'Check for Updates'
                )}
              </Button>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid var(--border-color)', paddingTop: '12px' }}>
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Update Release Channel
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                Choose release channel. Channels are strictly verified; switching is never automated.
              </div>
            </div>
            <div style={{ display: 'flex', gap: '6px' }}>
              {(['stable', 'beta', 'rc'] as UpdateChannel[]).map((ch) => (
                <button
                  key={ch}
                  onClick={() => setUpdateChannel(ch)}
                  style={{
                    padding: '4px 10px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 600,
                    textTransform: 'uppercase',
                    cursor: 'pointer',
                    backgroundColor: currentChannel === ch ? 'var(--accent-primary, #2563eb)' : 'var(--bg-tertiary)',
                    color: currentChannel === ch ? '#ffffff' : 'var(--text-secondary)',
                    border: '1px solid var(--border-color)',
                  }}
                >
                  {ch}
                </button>
              ))}
            </div>
          </div>
        </div>
      </Card>

      <Card
        title="Quarantine Retention Policy"
        subtitle="Automatic purging timeline for quarantined files"
        actions={<SettingsIcon size={16} color="var(--text-muted)" />}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Retention Window
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Files remain safely in the vault before becoming eligible for permanent purge.
            </div>
          </div>
          <Badge variant="info">
            {settings?.quarantine_retention_days ?? 7} Days
          </Badge>
        </div>
      </Card>

      <Card
        title="Excluded Protected Directories"
        subtitle="Paths automatically bypassed and protected by default"
        actions={<ShieldCheck size={16} color="#10b981" />}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {settings?.excluded_paths.map((path) => (
            <div
              key={path}
              style={{
                fontFamily: 'monospace',
                fontSize: '12px',
                padding: '6px 10px',
                backgroundColor: 'rgba(0,0,0,0.2)',
                borderRadius: '4px',
                border: '1px solid var(--border-color)',
                color: 'var(--text-secondary)',
              }}
            >
              {path}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};
