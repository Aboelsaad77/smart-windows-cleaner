import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { useApp } from '../state/AppContext';
import { Card } from '../design-system/Card';
import { Badge } from '../design-system/Badge';
import { Button } from '../design-system/Button';
import { Table, Column } from '../design-system/Table';
import { LoadingState } from '../design-system/LoadingState';
import { ErrorState } from '../design-system/ErrorState';
import { EmptyState } from '../design-system/EmptyState';
import {
  StorageSummaryDto,
  DriveStorageDto,
  CandidateExplainabilityDto,
} from '../types/ipc';
import { formatBytes, formatNumber } from '../utils/format';
import {
  HardDrive,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Search,
  ArrowRight,
  Info,
  Lock,
  Layers,
  RefreshCw,
  FolderLock,
  FileCheck,
} from 'lucide-react';

interface CategoryDriveBreakdown {
  category: string;
  count: number;
  totalBytes: number;
  autoEligibleBytes: number;
  reviewBytes: number;
  blockedBytes: number;
  highestRiskBand: string;
}

export const StorageView: React.FC = () => {
  const { client, setCurrentRoute } = useApp();
  const [storage, setStorage] = useState<StorageSummaryDto | null>(null);
  const [candidates, setCandidates] = useState<CandidateExplainabilityDto[]>([]);
  const [selectedDriveMount, setSelectedDriveMount] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadStorageData = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [storageData, candidateData] = await Promise.all([
        client.getStorageSummary(),
        client.getCleanupCandidates().catch(() => [] as CandidateExplainabilityDto[]),
      ]);
      setStorage(storageData);
      setCandidates(candidateData);
      if (storageData.drives.length > 0 && !selectedDriveMount) {
        setSelectedDriveMount(storageData.drives[0].mount_point);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to query physical drive storage summary';
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  }, [client, selectedDriveMount]);

  useEffect(() => {
    loadStorageData();
  }, [loadStorageData]);

  // Selected drive object
  const selectedDrive: DriveStorageDto | null = useMemo(() => {
    if (!storage || storage.drives.length === 0) return null;
    return (
      storage.drives.find((d) => d.mount_point.toLowerCase() === selectedDriveMount?.toLowerCase()) ??
      storage.drives[0]
    );
  }, [storage, selectedDriveMount]);

  // Filter candidates located on the selected drive
  const driveCandidates = useMemo(() => {
    if (!selectedDrive) return [];
    const prefix = selectedDrive.mount_point.toLowerCase();
    return candidates.filter((c) => c.path.toLowerCase().startsWith(prefix));
  }, [selectedDrive, candidates]);

  // Aggregate candidate metrics for the selected drive
  const driveAssessedMetrics = useMemo(() => {
    let totalBytes = 0;
    let autoEligibleBytes = 0;
    let reviewBytes = 0;
    let blockedBytes = 0;

    for (const c of driveCandidates) {
      totalBytes += c.size_bytes;
      if (c.safety_verdict === 'auto_quarantine' && c.can_quarantine) {
        autoEligibleBytes += c.size_bytes;
      } else if (c.safety_verdict === 'user_confirm' && c.can_quarantine) {
        reviewBytes += c.size_bytes;
      } else {
        blockedBytes += c.size_bytes;
      }
    }

    return {
      totalCount: driveCandidates.length,
      totalBytes,
      autoEligibleBytes,
      reviewBytes,
      blockedBytes,
    };
  }, [driveCandidates]);

  // Group candidates on this drive by category
  const driveCategoryBreakdown: CategoryDriveBreakdown[] = useMemo(() => {
    const map = new Map<string, CategoryDriveBreakdown>();

    for (const c of driveCandidates) {
      const cat = c.category || 'General Temp';
      let entry = map.get(cat);
      if (!entry) {
        entry = {
          category: cat,
          count: 0,
          totalBytes: 0,
          autoEligibleBytes: 0,
          reviewBytes: 0,
          blockedBytes: 0,
          highestRiskBand: 'Safe',
        };
        map.set(cat, entry);
      }
      entry.count += 1;
      entry.totalBytes += c.size_bytes;
      if (c.safety_verdict === 'auto_quarantine' && c.can_quarantine) {
        entry.autoEligibleBytes += c.size_bytes;
      } else if (c.safety_verdict === 'user_confirm' && c.can_quarantine) {
        entry.reviewBytes += c.size_bytes;
      } else {
        entry.blockedBytes += c.size_bytes;
      }

      if (c.risk_band === 'Dangerous' || entry.highestRiskBand === 'Dangerous') {
        entry.highestRiskBand = 'Dangerous';
      } else if (c.risk_band === 'Protected' || entry.highestRiskBand === 'Protected') {
        entry.highestRiskBand = 'Protected';
      } else if (c.risk_band === 'Review' && entry.highestRiskBand !== 'Dangerous' && entry.highestRiskBand !== 'Protected') {
        entry.highestRiskBand = 'Review';
      }
    }

    return Array.from(map.values()).sort((a, b) => b.totalBytes - a.totalBytes);
  }, [driveCandidates]);

  // Is this drive the system drive containing WinSxS?
  const hasWinSxs = useMemo(() => {
    if (!selectedDrive || !storage?.winsxs_protection) return false;
    return storage.winsxs_protection.path
      .toLowerCase()
      .startsWith(selectedDrive.mount_point.toLowerCase());
  }, [selectedDrive, storage]);

  // Category columns
  const categoryColumns: Column<CategoryDriveBreakdown>[] = [
    {
      key: 'category',
      header: 'Assessed Category',
      render: (row) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <FileCheck size={14} color="var(--accent-blue)" />
          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{row.category}</span>
        </div>
      ),
    },
    {
      key: 'count',
      header: 'Assessed Files',
      render: (row) => formatNumber(row.count),
    },
    {
      key: 'totalBytes',
      header: 'Total Space',
      render: (row) => (
        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
          {formatBytes(row.totalBytes)}
        </span>
      ),
    },
    {
      key: 'autoEligibleBytes',
      header: 'Auto Eligible',
      render: (row) => (
        <span style={{ color: 'var(--safety-safe-text)' }}>
          {formatBytes(row.autoEligibleBytes)}
        </span>
      ),
    },
    {
      key: 'reviewBytes',
      header: 'Requires Review',
      render: (row) => (
        <span style={{ color: 'var(--safety-review-text)' }}>
          {formatBytes(row.reviewBytes)}
        </span>
      ),
    },
    {
      key: 'highestRiskBand',
      header: 'Risk Level',
      render: (row) => (
        <Badge
          variant={
            row.highestRiskBand === 'Dangerous'
              ? 'dangerous'
              : row.highestRiskBand === 'Review'
              ? 'review'
              : row.highestRiskBand === 'Protected'
              ? 'protected'
              : 'safe'
          }
        >
          {row.highestRiskBand}
        </Badge>
      ),
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* View Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Physical Storage View
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Real physical drive allocations, zero-hallucination storage composition, and hard OS subsystem boundaries.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Button
            variant="secondary"
            size="sm"
            leftIcon={<RefreshCw size={13} />}
            onClick={loadStorageData}
          >
            Refresh Volumes
          </Button>
          <Button
            variant="primary"
            size="sm"
            leftIcon={<Search size={14} />}
            onClick={() => setCurrentRoute('scan')}
          >
            Run Scan
          </Button>
        </div>
      </div>

      {isLoading && !storage ? (
        <LoadingState label="Querying physical drive allocations and subsystem boundaries..." />
      ) : error && !storage ? (
        <ErrorState error={error} onRetry={loadStorageData} />
      ) : (
        <>
          {/* Physical Drives Grid */}
          <div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Detected Volumes ({storage?.drives.length ?? 0})
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
              {storage?.drives.map((drive) => {
                const isSelected = selectedDrive?.mount_point.toLowerCase() === drive.mount_point.toLowerCase();
                const usedBytes = drive.total_bytes - drive.free_bytes;
                const usedPercent = drive.total_bytes > 0 ? Math.round((usedBytes / drive.total_bytes) * 100) : 0;
                const freePercent = 100 - usedPercent;
                const isLowSpace = freePercent < 15;
                const isSystemDrive = drive.mount_point.toUpperCase().startsWith('C');

                // Find candidate count on this drive
                const driveCandidateCount = candidates.filter((c) =>
                  c.path.toLowerCase().startsWith(drive.mount_point.toLowerCase())
                ).length;

                return (
                  <div
                    key={drive.mount_point}
                    onClick={() => setSelectedDriveMount(drive.mount_point)}
                    style={{
                      backgroundColor: isSelected ? 'var(--bg-secondary)' : 'var(--bg-primary)',
                      border: `2px solid ${isSelected ? 'var(--accent-blue)' : 'var(--border-color)'}`,
                      borderRadius: '6px',
                      padding: '14px',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      boxShadow: isSelected ? '0 0 0 1px var(--accent-blue)' : 'none',
                    }}
                    role="button"
                    tabIndex={0}
                    aria-pressed={isSelected}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        setSelectedDriveMount(drive.mount_point);
                      }
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '10px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <div
                          style={{
                            padding: '8px',
                            borderRadius: '6px',
                            backgroundColor: isSelected ? 'rgba(59, 130, 246, 0.15)' : 'var(--bg-tertiary)',
                            color: isSelected ? 'var(--accent-blue)' : 'var(--text-secondary)',
                          }}
                        >
                          <HardDrive size={20} />
                        </div>
                        <div>
                          <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
                            Volume {drive.mount_point}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                            {isSystemDrive ? 'Windows Boot / System Volume' : 'Secondary Storage Volume'}
                          </div>
                        </div>
                      </div>
                      {isLowSpace && (
                        <Badge variant="dangerous" title="Volume has less than 15% free capacity remaining">
                          Low Space
                        </Badge>
                      )}
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '6px' }}>
                      <span style={{ color: 'var(--text-secondary)' }}>
                        Used: <strong style={{ color: 'var(--text-primary)' }}>{formatBytes(usedBytes)}</strong> ({usedPercent}%)
                      </span>
                      <span style={{ color: 'var(--text-muted)' }}>
                        Free: {formatBytes(drive.free_bytes)}
                      </span>
                    </div>

                    <div
                      style={{
                        height: '8px',
                        backgroundColor: 'var(--bg-tertiary)',
                        borderRadius: '4px',
                        overflow: 'hidden',
                        marginBottom: '10px',
                      }}
                    >
                      <div
                        style={{
                          height: '100%',
                          width: `${Math.min(100, Math.max(0, usedPercent))}%`,
                          backgroundColor: usedPercent >= 90 ? '#ef4444' : usedPercent >= 80 ? '#f59e0b' : '#3b82f6',
                          transition: 'width 0.3s ease',
                        }}
                      />
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)' }}>
                      <span>Total: {formatBytes(drive.total_bytes)}</span>
                      <span>
                        {driveCandidateCount > 0 ? (
                          <span style={{ color: 'var(--safety-safe-text)', fontWeight: 500 }}>
                            {formatNumber(driveCandidateCount)} assessed candidates
                          </span>
                        ) : (
                          <span>Unscanned</span>
                        )}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Selected Drive Drill-Down Pane */}
          {selectedDrive && (
            <Card
              title={`Drive Drill-Down: Volume ${selectedDrive.mount_point}`}
              subtitle={
                selectedDrive.mount_point.toUpperCase().startsWith('C')
                  ? 'Windows OS System Volume (Includes core bootloader, Windows servicing directories, and user profiles)'
                  : 'Physical Secondary Volume (User data, auxiliary applications, and game libraries)'
              }
            >
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                {/* Quick Metrics Bar */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                    gap: '12px',
                    padding: '14px',
                    backgroundColor: 'var(--bg-secondary)',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color)',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Total Capacity
                    </div>
                    <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px' }}>
                      {formatBytes(selectedDrive.total_bytes)}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Free Capacity
                    </div>
                    <div style={{ fontSize: '16px', fontWeight: 600, color: '#10b981', marginTop: '2px' }}>
                      {formatBytes(selectedDrive.free_bytes)}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Assessed Reclaimable
                    </div>
                    <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--accent-blue)', marginTop: '2px' }}>
                      {formatBytes(driveAssessedMetrics.totalBytes)}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Auto-Quarantine Safe
                    </div>
                    <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--safety-safe-text)', marginTop: '2px' }}>
                      {formatBytes(driveAssessedMetrics.autoEligibleBytes)}
                    </div>
                  </div>
                </div>

                {/* Deterministic Storage Composition (Zero Hallucinated Categories) */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                      Drive Storage Composition
                    </span>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      Assessed via Verified Rules (No Speculative Classifications)
                    </span>
                  </div>

                  {(() => {
                    const total = selectedDrive.total_bytes;
                    const free = selectedDrive.free_bytes;
                    const used = total - free;
                    const autoBytes = driveAssessedMetrics.autoEligibleBytes;
                    const reviewBytes = driveAssessedMetrics.reviewBytes;
                    const blockedBytes = driveAssessedMetrics.blockedBytes;
                    // Real in-use unassessed space
                    const inUseUnassessed = Math.max(0, used - (autoBytes + reviewBytes + blockedBytes));

                    const pAuto = total > 0 ? (autoBytes / total) * 100 : 0;
                    const pReview = total > 0 ? (reviewBytes / total) * 100 : 0;
                    const pBlocked = total > 0 ? (blockedBytes / total) * 100 : 0;
                    const pUnassessed = total > 0 ? (inUseUnassessed / total) * 100 : 0;
                    const pFree = total > 0 ? (free / total) * 100 : 0;

                    return (
                      <div>
                        {/* Visual Segmented Bar */}
                        <div
                          style={{
                            height: '18px',
                            backgroundColor: 'var(--bg-tertiary)',
                            borderRadius: '4px',
                            overflow: 'hidden',
                            display: 'flex',
                            border: '1px solid var(--border-color)',
                          }}
                        >
                          {pAuto > 0 && (
                            <div
                              style={{
                                width: `${pAuto}%`,
                                backgroundColor: '#22c55e',
                                transition: 'width 0.3s ease',
                              }}
                              title={`Auto-Quarantine Eligible: ${formatBytes(autoBytes)} (${pAuto.toFixed(2)}%)`}
                            />
                          )}
                          {pReview > 0 && (
                            <div
                              style={{
                                width: `${pReview}%`,
                                backgroundColor: '#eab308',
                                transition: 'width 0.3s ease',
                              }}
                              title={`Requires Review: ${formatBytes(reviewBytes)} (${pReview.toFixed(2)}%)`}
                            />
                          )}
                          {pBlocked > 0 && (
                            <div
                              style={{
                                width: `${pBlocked}%`,
                                backgroundColor: '#a855f7',
                                transition: 'width 0.3s ease',
                              }}
                              title={`Safety Blocked: ${formatBytes(blockedBytes)} (${pBlocked.toFixed(2)}%)`}
                            />
                          )}
                          {pUnassessed > 0 && (
                            <div
                              style={{
                                width: `${pUnassessed}%`,
                                backgroundColor: '#3b82f6',
                                opacity: 0.65,
                                transition: 'width 0.3s ease',
                              }}
                              title={`In-Use System & Application Files: ${formatBytes(inUseUnassessed)} (${pUnassessed.toFixed(2)}%)`}
                            />
                          )}
                          {pFree > 0 && (
                            <div
                              style={{
                                width: `${pFree}%`,
                                backgroundColor: 'var(--bg-tertiary)',
                                transition: 'width 0.3s ease',
                              }}
                              title={`Free Available Space: ${formatBytes(free)} (${pFree.toFixed(2)}%)`}
                            />
                          )}
                        </div>

                        {/* Segment Legend */}
                        <div
                          style={{
                            display: 'flex',
                            flexWrap: 'wrap',
                            gap: '16px',
                            marginTop: '10px',
                            fontSize: '11px',
                            color: 'var(--text-secondary)',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span style={{ width: '10px', height: '10px', borderRadius: '2px', backgroundColor: '#22c55e' }} />
                            <span>Auto-Eligible Reclaimable: <strong>{formatBytes(autoBytes)}</strong></span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span style={{ width: '10px', height: '10px', borderRadius: '2px', backgroundColor: '#eab308' }} />
                            <span>Review Required: <strong>{formatBytes(reviewBytes)}</strong></span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span style={{ width: '10px', height: '10px', borderRadius: '2px', backgroundColor: '#a855f7' }} />
                            <span>Safety Blocked: <strong>{formatBytes(blockedBytes)}</strong></span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span style={{ width: '10px', height: '10px', borderRadius: '2px', backgroundColor: '#3b82f6', opacity: 0.65 }} />
                            <span>In-Use Filesystem Space (Unassessed): <strong>{formatBytes(inUseUnassessed)}</strong></span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span style={{ width: '10px', height: '10px', borderRadius: '2px', backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-color)' }} />
                            <span>Free Space: <strong>{formatBytes(free)}</strong></span>
                          </div>
                        </div>
                      </div>
                    );
                  })()}
                </div>

                {/* Zero-Guessing Integrity Statement Callout */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                    padding: '12px 14px',
                    backgroundColor: 'rgba(59, 130, 246, 0.08)',
                    border: '1px solid rgba(59, 130, 246, 0.25)',
                    borderRadius: '6px',
                    fontSize: '12px',
                    color: 'var(--text-secondary)',
                    lineHeight: 1.5,
                  }}
                >
                  <Info size={16} color="var(--accent-blue)" style={{ flexShrink: 0, marginTop: '2px' }} />
                  <div>
                    <strong style={{ color: 'var(--text-primary)' }}>Deterministic Storage Transparency: </strong>
                    Smart Windows Cleaner strictly rejects arbitrary disk guessing. Unlike conventional tools that assign
                    unknown disk space to speculative labels like &ldquo;Other&rdquo;, &ldquo;Media&rdquo;, or &ldquo;Documents&rdquo; based purely on file extensions,
                    SWC only accounts for space verified by deterministic safety rules. Unassessed filesystem space remains
                    unclassified until explicitly evaluated by the Core Safety Engine.
                  </div>
                </div>

                {/* Assessed Candidates Breakdown Table on this Drive */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Layers size={14} color="var(--accent-blue)" />
                      Assessed Cleanup Rules on Volume {selectedDrive.mount_point}
                    </div>
                    {driveCandidates.length > 0 && (
                      <Button
                        variant="ghost"
                        size="sm"
                        leftIcon={<ArrowRight size={13} />}
                        onClick={() => setCurrentRoute('results')}
                      >
                        Inspect in Results View
                      </Button>
                    )}
                  </div>

                  {driveCategoryBreakdown.length > 0 ? (
                    <Table
                      data={driveCategoryBreakdown}
                      columns={categoryColumns}
                      keyExtractor={(item) => item.category}
                    />
                  ) : (
                    <EmptyState
                      title="No Candidates Assessed on this Volume"
                      description={`No cleanup candidates have been discovered on ${selectedDrive.mount_point}. Run a system scan to catalog safe reclaimable candidates.`}
                      action={
                        <Button
                          variant="primary"
                          size="sm"
                          onClick={() => setCurrentRoute('scan')}
                        >
                          Scan {selectedDrive.mount_point}
                        </Button>
                      }
                    />
                  )}
                </div>

                {/* Subsystem & Hard Protection Architecture */}
                {hasWinSxs && storage?.winsxs_protection && (
                  <div
                    style={{
                      padding: '14px',
                      backgroundColor: 'rgba(168, 85, 247, 0.08)',
                      border: '1px solid rgba(168, 85, 247, 0.3)',
                      borderRadius: '6px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                        <FolderLock size={20} color="#a855f7" style={{ flexShrink: 0, marginTop: '2px' }} />
                        <div>
                          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                            Windows Component Store Protection (WinSxS)
                          </div>
                          <div style={{ fontSize: '12px', fontFamily: 'monospace', color: 'var(--text-secondary)', marginTop: '2px' }}>
                            {storage.winsxs_protection.path}
                          </div>
                          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px', lineHeight: 1.5 }}>
                            The Windows Component Store stores assembly manifests and single-instance hardlinks to active OS files in System32.
                            Deleting files in WinSxS breaks the Windows Servicing Stack and prevents Windows Updates.
                            Smart Windows Cleaner enforces a zero-bypass hard safety rule blocking direct file deletion.
                          </p>
                          <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '6px' }}>
                            <strong>Authorized Servicing Protocol: </strong>
                            Run <code style={{ backgroundColor: 'var(--bg-tertiary)', padding: '2px 5px', borderRadius: '3px' }}>DISM.exe /Online /Cleanup-Image /StartComponentCleanup</code> via elevated command line.
                          </div>
                        </div>
                      </div>
                      <Badge variant="protected">Guaranteed Protected</Badge>
                    </div>
                  </div>
                )}

                {/* Permanent Safety Engine Exclusions Card */}
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Shield size={14} color="#10b981" />
                    Permanent Safety Engine Protection Boundaries
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '10px' }}>
                    <div style={{ padding: '10px', backgroundColor: 'var(--bg-secondary)', borderRadius: '5px', border: '1px solid var(--border-color)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
                        <Lock size={13} color="#ef4444" />
                        OS Kernel & System Binaries
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                        <code style={{ fontSize: '11px' }}>{selectedDrive.mount_point}Windows\System32</code> &amp; <code style={{ fontSize: '11px' }}>SysWOW64</code> are strictly non-deletable.
                      </div>
                    </div>

                    <div style={{ padding: '10px', backgroundColor: 'var(--bg-secondary)', borderRadius: '5px', border: '1px solid var(--border-color)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
                        <Lock size={13} color="#ef4444" />
                        Bootloader & EFI Partitions
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                        BCD configuration, UEFI firmware interfaces, and Recovery volumes are permanently excluded.
                      </div>
                    </div>

                    <div style={{ padding: '10px', backgroundColor: 'var(--bg-secondary)', borderRadius: '5px', border: '1px solid var(--border-color)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
                        <Shield size={13} color="#10b981" />
                        Application Directory Integrity
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                        Installed binaries in <code style={{ fontSize: '11px' }}>Program Files</code> require registered vendor uninstallers.
                      </div>
                    </div>

                    <div style={{ padding: '10px', backgroundColor: 'var(--bg-secondary)', borderRadius: '5px', border: '1px solid var(--border-color)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
                        <CheckCircle2 size={13} color="#10b981" />
                        Personal Data Protection
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                        User Documents, Pictures, and Desktop directories are excluded from candidate ingestion.
                      </div>
                    </div>
                  </div>
                </div>

                {/* Drive Capacity Health Assessment */}
                {(() => {
                  const freePercent = selectedDrive.total_bytes > 0
                    ? Math.round((selectedDrive.free_bytes / selectedDrive.total_bytes) * 100)
                    : 0;

                  if (freePercent < 15) {
                    return (
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          flexWrap: 'wrap',
                          gap: '10px',
                          padding: '12px',
                          backgroundColor: 'rgba(239, 68, 68, 0.08)',
                          border: '1px solid rgba(239, 68, 68, 0.3)',
                          borderRadius: '6px',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <AlertTriangle size={18} color="#ef4444" />
                          <div>
                            <div style={{ fontSize: '13px', fontWeight: 600, color: '#ef4444' }}>
                              Low Disk Space Warning ({freePercent}% Available)
                            </div>
                            <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                              Windows requires at least 15% free headroom for virtual memory paging, Windows Update staging, and filesystem journaling.
                            </div>
                          </div>
                        </div>
                        <Button
                          variant="danger"
                          size="sm"
                          leftIcon={<Search size={13} />}
                          onClick={() => setCurrentRoute('scan')}
                        >
                          Scan Drive for Cleanup
                        </Button>
                      </div>
                    );
                  }

                  return (
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '10px',
                        padding: '10px 12px',
                        backgroundColor: 'var(--bg-secondary)',
                        borderRadius: '6px',
                        border: '1px solid var(--border-color)',
                        fontSize: '12px',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      <CheckCircle2 size={15} color="#10b981" />
                      <span>
                        Volume {selectedDrive.mount_point} maintains healthy storage headroom ({freePercent}% free capacity).
                      </span>
                    </div>
                  );
                })()}
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  );
};
