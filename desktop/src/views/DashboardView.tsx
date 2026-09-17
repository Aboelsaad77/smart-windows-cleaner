import React, { useState, useEffect, useCallback } from 'react';
import { useApp } from '../state/AppContext';
import { Card } from '../design-system/Card';
import { Badge } from '../design-system/Badge';
import { Button } from '../design-system/Button';
import { ErrorState } from '../design-system/ErrorState';
import { formatBytes, formatDuration, formatRelativeTime } from '../utils/format';
import {
  StorageSummaryDto,
  AuditEntryDto,
  IpcError,
} from '../types/ipc';
import {
  HardDrive,
  FolderArchive,
  Search,
  ArrowRight,
  RefreshCw,
  FolderTree,
  FileText,
  KeyRound,
  Shield,
  Layers,
} from 'lucide-react';

export const DashboardView: React.FC = () => {
  const { client, systemStatus, latestScanSummary, connectionStatus, setCurrentRoute } = useApp();

  const [storageSummary, setStorageSummary] = useState<StorageSummaryDto | null>(null);
  const [recentAudits, setRecentAudits] = useState<AuditEntryDto[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [dashboardError, setDashboardError] = useState<IpcError | null>(null);

  const loadDashboardData = useCallback(async () => {
    setIsLoading(true);
    setDashboardError(null);
    try {
      const [storageData, auditData] = await Promise.all([
        client.getStorageSummary().catch(() => null),
        client.getAuditHistory({ limit: 5 }).catch(() => []),
      ]);
      setStorageSummary(storageData);
      setRecentAudits(auditData);
    } catch (err) {
      setDashboardError({
        code: 'INTERNAL_CORE_ERROR',
        message: err instanceof Error ? err.message : 'Failed to query system dashboard data',
      });
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  if (connectionStatus === 'error' || connectionStatus === 'disconnected') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
            System Intelligence Dashboard
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            Core process disconnected.
          </p>
        </div>
        <ErrorState
          error={{
            code: 'INTERNAL_CORE_ERROR',
            message: 'Native Rust core process is unreachable. Re-connect to view system dashboard.',
          }}
          onRetry={loadDashboardData}
        />
      </div>
    );
  }

  if (dashboardError) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Dashboard Query Failed
          </h1>
        </div>
        <ErrorState error={dashboardError} onRetry={loadDashboardData} />
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Header with Elevation & OS context */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
        <div>
          <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
            System Intelligence Dashboard
          </h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '3px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              {systemStatus?.os_version || 'Windows NT 64-bit'}
            </span>
            <span style={{ color: 'var(--border-color)' }}>•</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <KeyRound size={12} color={systemStatus?.is_elevated ? '#f59e0b' : 'var(--text-muted)'} />
              <span style={{ fontSize: '11px', color: systemStatus?.is_elevated ? '#f59e0b' : 'var(--text-muted)' }}>
                {systemStatus?.is_elevated ? 'Elevated Administrator' : 'Standard User (Safe Scope)'}
              </span>
            </div>
            <span style={{ color: 'var(--border-color)' }}>•</span>
            <Badge variant="safe">Safety Engine Active</Badge>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <Button variant="secondary" size="sm" leftIcon={<RefreshCw size={13} />} onClick={loadDashboardData} isLoading={isLoading}>
            Refresh
          </Button>
          <Button variant="primary" size="sm" leftIcon={<Search size={14} />} onClick={() => setCurrentRoute('scan')}>
            Scan Now
          </Button>
        </div>
      </div>

      {/* Hero Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
        {/* Metric 1: Potential Reclaimable Space (from real scan data only) */}
        <Card title="Potential Reclaimable Space" subtitle="Evaluated by Safety Engine">
          <div style={{ fontSize: '24px', fontWeight: 700, color: '#10b981' }}>
            {latestScanSummary ? formatBytes(latestScanSummary.total_reclaimable_bytes) : '0 B'}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            {latestScanSummary ? `${latestScanSummary.total_candidates_found} candidates assessed` : 'Run a scan to evaluate'}
          </div>
          {latestScanSummary && (
            <div style={{ display: 'flex', gap: '6px', marginTop: '8px', flexWrap: 'wrap' }}>
              <Badge variant="safe" title="Auto-Quarantine Eligible">
                {formatBytes(latestScanSummary.auto_eligible_bytes)} Auto
              </Badge>
              <Badge variant="review" title="User Confirmation Required">
                {formatBytes(latestScanSummary.user_confirm_bytes)} Review
              </Badge>
              <Badge variant="protected" title="Protected System Resources">
                {formatBytes(latestScanSummary.blocked_bytes)} Blocked
              </Badge>
            </div>
          )}
        </Card>

        {/* Metric 2: Quarantine Vault Footprint */}
        <Card title="Quarantine Vault" subtitle="Reversible Isolation Storage">
          <div style={{ fontSize: '24px', fontWeight: 700, color: '#38bdf8' }}>
            {formatBytes(systemStatus?.quarantine_total_bytes ?? 0)}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            {systemStatus?.quarantine_item_count ?? 0} files vaulted with SHA-256
          </div>
          <div style={{ marginTop: '10px' }}>
            <Button variant="ghost" size="sm" rightIcon={<ArrowRight size={12} />} onClick={() => setCurrentRoute('quarantine')}>
              Manage Vault
            </Button>
          </div>
        </Card>

        {/* Metric 3: Latest Scan Telemetry */}
        <Card title="Latest Scan Activity" subtitle="Inspection Provenance">
          {latestScanSummary ? (
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                {latestScanSummary.total_files_scanned.toLocaleString()} files inspected
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                Completed in {formatDuration(latestScanSummary.elapsed_ms)}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '6px' }}>
                {latestScanSummary.categories.length} categories identified
              </div>
              <div style={{ marginTop: '8px' }}>
                <Button variant="outline" size="sm" rightIcon={<ArrowRight size={12} />} onClick={() => setCurrentRoute('results')}>
                  View Removable Items
                </Button>
              </div>
            </div>
          ) : (
            <div>
              <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                No scan completed yet in this session.
              </div>
              <div style={{ marginTop: '12px' }}>
                <Button variant="primary" size="sm" onClick={() => setCurrentRoute('scan')}>
                  Start First Scan
                </Button>
              </div>
            </div>
          )}
        </Card>
      </div>

      {/* Storage and Drive Overview */}
      <Card
        title="Storage & Drive Capacity"
        subtitle="Real-time volume telemetry from native filesystem"
        actions={
          <Button variant="secondary" size="sm" rightIcon={<ArrowRight size={12} />} onClick={() => setCurrentRoute('storage')}>
            Storage Intelligence
          </Button>
        }
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {storageSummary && storageSummary.drives.length > 0 ? (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
              {storageSummary.drives.map((drive) => {
                const usedBytes = drive.total_bytes - drive.free_bytes;
                const usedPercent = Math.min(100, Math.max(0, Math.round((usedBytes / drive.total_bytes) * 100)));
                return (
                  <div
                    key={drive.mount_point}
                    style={{
                      padding: '12px 14px',
                      borderRadius: '6px',
                      backgroundColor: 'rgba(0,0,0,0.2)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <HardDrive size={16} color="#38bdf8" />
                        <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
                          Drive {drive.mount_point}
                        </span>
                      </div>
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                        {formatBytes(drive.free_bytes)} free of {formatBytes(drive.total_bytes)}
                      </span>
                    </div>

                    {/* Usage Progress Bar */}
                    <div style={{ width: '100%', height: '6px', backgroundColor: 'var(--bg-tertiary)', borderRadius: '3px', overflow: 'hidden' }}>
                      <div
                        style={{
                          width: `${usedPercent}%`,
                          height: '100%',
                          backgroundColor: usedPercent > 90 ? '#ef4444' : usedPercent > 75 ? '#f59e0b' : '#3b82f6',
                        }}
                      />
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)' }}>
                      <span>{usedPercent}% used ({formatBytes(usedBytes)})</span>
                      <span>Target root ready for scan</span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Querying volume partitions...
            </div>
          )}

          {/* WinSxS Component Store Protection Notice */}
          {storageSummary?.winsxs_protection?.is_protected && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '6px',
                backgroundColor: 'rgba(147, 51, 234, 0.1)',
                border: '1px solid rgba(147, 51, 234, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '12px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Shield size={16} color="#c084fc" />
                <span style={{ color: 'var(--text-primary)' }}>
                  <strong>Windows Component Store (WinSxS) Protection:</strong> Hard safety rules protect system dependencies from direct file deletion.
                </span>
              </div>
              <Badge variant="protected">Immune to Removal</Badge>
            </div>
          )}
        </div>
      </Card>

      {/* Two-Column Grid: Quick Navigation & Recent Audit Activity */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '12px' }}>
        {/* Navigation Quick Cards */}
        <Card title="Workflow Navigation" subtitle="Dedicated operational views">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div
              onClick={() => setCurrentRoute('scan')}
              style={{
                padding: '10px 12px',
                borderRadius: '6px',
                border: '1px solid var(--border-subtle)',
                backgroundColor: 'rgba(0,0,0,0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                cursor: 'pointer',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Search size={16} color="#3b82f6" />
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-primary)' }}>
                    Scanner Hub
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Configure Quick, Smart, or Deep filesystem analysis
                  </div>
                </div>
              </div>
              <ArrowRight size={14} color="var(--text-muted)" />
            </div>

            <div
              onClick={() => setCurrentRoute('results')}
              style={{
                padding: '10px 12px',
                borderRadius: '6px',
                border: '1px solid var(--border-subtle)',
                backgroundColor: 'rgba(0,0,0,0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                cursor: 'pointer',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Layers size={16} color="#10b981" />
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-primary)' }}>
                    Results & Explainability
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Inspect detection rules, risk factors, and safety gate reasons
                  </div>
                </div>
              </div>
              <ArrowRight size={14} color="var(--text-muted)" />
            </div>

            <div
              onClick={() => setCurrentRoute('quarantine')}
              style={{
                padding: '10px 12px',
                borderRadius: '6px',
                border: '1px solid var(--border-subtle)',
                backgroundColor: 'rgba(0,0,0,0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                cursor: 'pointer',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <FolderArchive size={16} color="#38bdf8" />
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-primary)' }}>
                    Quarantine Vault
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Verify SHA-256 integrity, restore files, or purge expired items
                  </div>
                </div>
              </div>
              <ArrowRight size={14} color="var(--text-muted)" />
            </div>

            <div
              onClick={() => setCurrentRoute('storage')}
              style={{
                padding: '10px 12px',
                borderRadius: '6px',
                border: '1px solid var(--border-subtle)',
                backgroundColor: 'rgba(0,0,0,0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                cursor: 'pointer',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <FolderTree size={16} color="#f59e0b" />
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-primary)' }}>
                    Storage Intelligence
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Drive hierarchy and directory capacity drill-down
                  </div>
                </div>
              </div>
              <ArrowRight size={14} color="var(--text-muted)" />
            </div>
          </div>
        </Card>

        {/* Recent Cleanup Activity (Audit Stream) */}
        <Card
          title="Recent Audit History"
          subtitle="Immutable operational trail from core SQLite database"
          actions={
            <Button variant="ghost" size="sm" rightIcon={<ArrowRight size={12} />} onClick={() => setCurrentRoute('logs')}>
              Full Logs
            </Button>
          }
        >
          {recentAudits.length === 0 ? (
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', padding: '20px 0', textAlign: 'center' }}>
              No operations logged in the audit database yet.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {recentAudits.map((entry) => (
                <div
                  key={entry.id}
                  style={{
                    padding: '8px 10px',
                    borderRadius: '4px',
                    backgroundColor: 'rgba(0,0,0,0.15)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    fontSize: '11px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                    <FileText size={13} color="var(--text-muted)" style={{ flexShrink: 0 }} />
                    <div style={{ minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase' }}>
                          {entry.operation}
                        </span>
                        <Badge variant={entry.success ? 'safe' : 'dangerous'}>
                          {entry.success ? 'Success' : 'Failed'}
                        </Badge>
                      </div>
                      <div
                        style={{
                          color: 'var(--text-muted)',
                          fontFamily: 'monospace',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          maxWidth: '240px',
                          marginTop: '2px',
                        }}
                        title={entry.target_path}
                      >
                        {entry.target_path}
                      </div>
                    </div>
                  </div>

                  <span style={{ color: 'var(--text-muted)', fontSize: '10px', flexShrink: 0 }}>
                    {formatRelativeTime(entry.timestamp)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};
