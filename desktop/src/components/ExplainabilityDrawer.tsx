import React, { useState } from 'react';
import { CandidateExplainabilityDto } from '../types/ipc';
import { Badge } from '../design-system/Badge';
import { Button } from '../design-system/Button';
import { formatBytes } from '../utils/format';
import {
  X,
  Copy,
  Check,
  Shield,
  ShieldAlert,
  ShieldCheck,
  FileText,
  AlertTriangle,
  RefreshCw,
  Folder,
  CheckCircle2,
  Lock,
} from 'lucide-react';

export interface ExplainabilityDrawerProps {
  candidate: CandidateExplainabilityDto | null;
  onClose: () => void;
  onReanalyze?: (path: string) => Promise<CandidateExplainabilityDto | void>;
  onElevate?: () => void;
}

export const ExplainabilityDrawer: React.FC<ExplainabilityDrawerProps> = ({
  candidate,
  onClose,
  onReanalyze,
  onElevate,
}) => {
  const [copied, setCopied] = useState<boolean>(false);
  const [isReanalyzing, setIsReanalyzing] = useState<boolean>(false);

  if (!candidate) return null;

  const handleCopyPath = () => {
    navigator.clipboard.writeText(candidate.path);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleReanalyze = async () => {
    if (!onReanalyze) return;
    setIsReanalyzing(true);
    try {
      await onReanalyze(candidate.path);
    } finally {
      setIsReanalyzing(false);
    }
  };

  const fileName = candidate.path.split(/[/\\]/).pop() || candidate.path;

  return (
    <div
      role="dialog"
      aria-label="Candidate Explainability Details"
      style={{
        position: 'fixed',
        top: 0,
        right: 0,
        bottom: 0,
        width: '480px',
        maxWidth: '90vw',
        backgroundColor: 'var(--bg-secondary)',
        borderLeft: '1px solid var(--border-color)',
        boxShadow: '-8px 0 24px rgba(0, 0, 0, 0.5)',
        zIndex: 900,
        display: 'flex',
        flexDirection: 'column',
        animation: 'slideInRight 0.2s ease-out',
      }}
    >
      {/* Drawer Header */}
      <div
        style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border-color)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          backgroundColor: 'rgba(0,0,0,0.2)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
          <Folder size={18} color="#3b82f6" style={{ flexShrink: 0 }} />
          <div style={{ minWidth: 0 }}>
            <h3
              style={{
                fontSize: '15px',
                fontWeight: 600,
                color: 'var(--text-primary)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
              title={fileName}
            >
              {fileName}
            </h3>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              Category: {candidate.category}
            </span>
          </div>
        </div>

        <button
          onClick={onClose}
          aria-label="Close explainability panel"
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            padding: '4px',
            borderRadius: '4px',
            display: 'flex',
          }}
        >
          <X size={18} />
        </button>
      </div>

      {/* Drawer Body */}
      <div
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '20px',
        }}
      >
        {/* Section 1: Identity & Ownership */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Identity & Provenance
          </div>

          <div
            style={{
              padding: '12px',
              backgroundColor: 'rgba(0,0,0,0.2)',
              borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
              fontSize: '12px',
            }}
          >
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Full Path:</span>
              <div
                style={{
                  fontFamily: 'monospace',
                  fontSize: '11px',
                  color: 'var(--text-primary)',
                  backgroundColor: 'rgba(0,0,0,0.2)',
                  padding: '6px 8px',
                  borderRadius: '4px',
                  wordBreak: 'break-all',
                  marginTop: '4px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <span>{candidate.path}</span>
                <button
                  onClick={handleCopyPath}
                  title="Copy path"
                  style={{
                    background: 'none',
                    border: 'none',
                    color: copied ? '#10b981' : 'var(--text-muted)',
                    cursor: 'pointer',
                    marginLeft: '6px',
                  }}
                >
                  {copied ? <Check size={14} /> : <Copy size={14} />}
                </button>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '2px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Capacity:</span>
              <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                {formatBytes(candidate.size_bytes)} ({candidate.size_bytes.toLocaleString()} bytes)
              </span>
            </div>

            {candidate.app_owner && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: 'var(--text-muted)' }}>Application Attribution:</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                    {candidate.app_owner}
                  </span>
                  {candidate.app_confidence && (
                    <Badge variant="info" title={`Confidence: ${candidate.app_confidence}`}>
                      {candidate.app_confidence.replace('_', ' ')}
                    </Badge>
                  )}
                </div>
              </div>
            )}

            {/* Hardware / Binary Flags */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '4px' }}>
              {candidate.is_pe && (
                <Badge variant="review" title="Verified PE executable bytes via COFF/PE32 header inspection">
                  PE Binary
                </Badge>
              )}
              {candidate.is_signed && (
                <Badge variant="safe" title="Authenticode digital signature verified">
                  Signed Component
                </Badge>
              )}
              {candidate.is_in_use && (
                <Badge variant="dangerous" title="Active handle lock detected in another process">
                  In Use (Locked)
                </Badge>
              )}
              {candidate.is_hidden_or_system && (
                <Badge variant="review" title="Windows Hidden or System attribute flag is active">
                  System / Hidden
                </Badge>
              )}
            </div>
          </div>
        </div>

        {/* Section 2: Why Was This Detected? (Classification Evidence) */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Why Smart Cleaner Detected This File
          </div>

          {candidate.local_rules.length === 0 ? (
            <div style={{ padding: '10px', fontSize: '12px', color: 'var(--text-muted)', backgroundColor: 'rgba(0,0,0,0.1)', borderRadius: '4px' }}>
              Discovered via directory tree traversal matching heuristic candidate criteria.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {candidate.local_rules.map((rule) => (
                <div
                  key={rule.rule_id}
                  style={{
                    padding: '10px',
                    borderRadius: '6px',
                    backgroundColor: 'rgba(0,0,0,0.2)',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                    fontSize: '12px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <FileText size={14} color="#38bdf8" />
                      <code style={{ fontFamily: 'monospace', color: '#93c5fd', fontSize: '11px' }}>
                        {rule.rule_id}
                      </code>
                    </div>
                    <Badge variant="info">
                      {rule.confidence} confidence
                    </Badge>
                  </div>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '11px' }}>
                    Category: <strong>{rule.category}</strong> • Est: {formatBytes(rule.reclaim_estimate_bytes)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Section 3: Why Is This Risky? (Risk Assessment) */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Deletion-Risk Assessment
            </span>
            <Badge riskBand={candidate.risk_band}>
              {candidate.risk_band} ({candidate.risk_score} / 100)
            </Badge>
          </div>

          <div
            style={{
              padding: '12px',
              backgroundColor: 'rgba(0,0,0,0.2)',
              borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
            }}
          >
            {/* Score visual meter */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                <span>Risk Scale</span>
                <span>{candidate.risk_score} / 100</span>
              </div>
              <div style={{ height: '6px', width: '100%', backgroundColor: 'var(--bg-tertiary)', borderRadius: '3px', overflow: 'hidden' }}>
                <div
                  style={{
                    height: '100%',
                    width: `${candidate.risk_score}%`,
                    backgroundColor:
                      candidate.risk_score >= 86
                        ? '#9333ea'
                        : candidate.risk_score >= 60
                        ? '#ef4444'
                        : candidate.risk_score >= 35
                        ? '#f59e0b'
                        : '#10b981',
                  }}
                />
              </div>
            </div>

            {/* Contributing Risk Factors */}
            {candidate.risk_factors.length === 0 ? (
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Zero elevated risk factors identified. Base score assigned.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  Evaluated Risk Factors:
                </div>
                {candidate.risk_factors.map((factor) => (
                  <div
                    key={factor.name}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '4px',
                      backgroundColor: 'rgba(0,0,0,0.15)',
                      display: 'flex',
                      alignItems: 'flex-start',
                      justifyContent: 'space-between',
                      fontSize: '11px',
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        {factor.name}
                      </div>
                      <div style={{ color: 'var(--text-muted)', marginTop: '2px' }}>
                        {factor.reason}
                      </div>
                    </div>
                    {factor.weight > 0 && (
                      <span style={{ color: '#f87171', fontWeight: 600, fontFamily: 'monospace' }}>
                        +{factor.weight}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}

            <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontStyle: 'italic' }}>
              Note: Risk score is an advisory evaluation. The Safety Engine maintains absolute final authority.
            </div>
          </div>
        </div>

        {/* Section 4: Safety Verdict & Quarantine Eligibility */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Safety Engine Gate Verdict
          </div>

          <div
            style={{
              padding: '14px',
              borderRadius: '6px',
              border:
                candidate.safety_verdict === 'never_delete'
                  ? '1px solid var(--safety-protected-border)'
                  : candidate.safety_verdict === 'user_confirm'
                  ? '1px solid var(--safety-review-border)'
                  : '1px solid var(--safety-safe-border)',
              backgroundColor:
                candidate.safety_verdict === 'never_delete'
                  ? 'rgba(46, 16, 101, 0.3)'
                  : candidate.safety_verdict === 'user_confirm'
                  ? 'rgba(69, 26, 3, 0.3)'
                  : 'rgba(6, 78, 59, 0.3)',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {candidate.safety_verdict === 'never_delete' ? (
                  <ShieldAlert size={20} color="#c084fc" />
                ) : candidate.safety_verdict === 'user_confirm' ? (
                  <AlertTriangle size={20} color="#f59e0b" />
                ) : (
                  <ShieldCheck size={20} color="#34d399" />
                )}
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {candidate.safety_verdict === 'never_delete'
                    ? 'Protected (Never Delete)'
                    : candidate.safety_verdict === 'user_confirm'
                    ? 'User Confirmation Required'
                    : 'Auto-Quarantine Eligible'}
                </span>
              </div>

              <Badge safetyVerdict={candidate.safety_verdict} />
            </div>

            {/* Allowed Reasons */}
            {candidate.allowed_reasons.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--safety-safe-text)' }}>
                  Why Quarantine Is Permitted:
                </span>
                {candidate.allowed_reasons.map((reason, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '6px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                    <CheckCircle2 size={13} color="#10b981" style={{ flexShrink: 0, marginTop: '2px' }} />
                    <span>{reason}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Blocked Reasons */}
            {candidate.blocked_reasons.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--safety-protected-text)' }}>
                  Why Quarantine Is Prohibited:
                </span>
                {candidate.blocked_reasons.map((reason, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '6px', fontSize: '11px', color: '#fca5a5' }}>
                    <Lock size={13} color="#ef4444" style={{ flexShrink: 0, marginTop: '2px' }} />
                    <span>{reason}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Elevation Trigger if blocked by permissions/elevation */}
            {onElevate && !candidate.can_quarantine && (
              <div
                style={{
                  marginTop: '6px',
                  padding: '10px 12px',
                  backgroundColor: 'rgba(249, 115, 22, 0.1)',
                  border: '1px solid rgba(249, 115, 22, 0.3)',
                  borderRadius: '4px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '8px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <ShieldAlert size={15} color="#f97316" />
                  <span style={{ fontSize: '11px', color: 'var(--text-primary)' }}>
                    Protected path requires administrator elevation
                  </span>
                </div>
                <Button
                  variant="primary"
                  size="sm"
                  leftIcon={<Shield size={12} />}
                  onClick={onElevate}
                >
                  Elevate
                </Button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Drawer Footer Actions */}
      <div
        style={{
          padding: '14px 20px',
          borderTop: '1px solid var(--border-color)',
          backgroundColor: 'rgba(0,0,0,0.2)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <Button
          variant="outline"
          size="sm"
          leftIcon={<RefreshCw size={13} />}
          isLoading={isReanalyzing}
          onClick={handleReanalyze}
          title="Query Rust core to re-evaluate file locks and metadata freshness"
        >
          Re-Analyze Item
        </Button>

        <Button variant="secondary" size="sm" onClick={onClose}>
          Close Panel
        </Button>
      </div>

      <style>{`
        @keyframes slideInRight {
          from { transform: translateX(100%); }
          to { transform: translateX(0); }
        }
      `}</style>
    </div>
  );
};
