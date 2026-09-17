import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useApp } from '../state/AppContext';
import { Card } from '../design-system/Card';
import { Badge } from '../design-system/Badge';
import { Button } from '../design-system/Button';
import { ProgressIndicator } from '../design-system/ProgressIndicator';
import { ConfirmationDialog } from '../design-system/ConfirmationDialog';
import { ErrorState } from '../design-system/ErrorState';
import {
  ScanSummaryDto,
  CandidateExplainabilityDto,
  IpcError,
  IpcEvent,
} from '../types/ipc';
import { IpcClientError } from '../ipc/client';
import { formatBytes, formatDuration, formatNumber } from '../utils/format';
import {
  Search,
  Zap,
  Cpu,
  Layers,
  HardDrive,
  StopCircle,
  CheckCircle2,
  AlertTriangle,
  Folder,
  ArrowRight,
  RotateCcw,
  ShieldAlert,
} from 'lucide-react';

export type ScanMode = 'quick' | 'smart' | 'deep';

export type ScanUiState =
  | 'idle'
  | 'starting'
  | 'scanning'
  | 'cancelling'
  | 'completed'
  | 'cancelled'
  | 'failed'
  | 'core_disconnected';

interface LiveCandidateItem {
  id: string;
  name: string;
  path: string;
  category: string;
  size_bytes: number;
  risk_score: number;
  risk_band: 'Safe' | 'Review' | 'Dangerous' | 'Protected';
  safety_verdict: 'auto_quarantine' | 'user_confirm' | 'never_delete';
}

export const ScanView: React.FC = () => {
  const { client, connectionStatus, setCurrentRoute, requestElevation } = useApp();

  // State Machine
  const [uiState, setUiState] = useState<ScanUiState>('idle');
  const [scanMode, setScanMode] = useState<ScanMode>('smart');
  const [availableRoots, setAvailableRoots] = useState<string[]>(['C:\\']);
  const [selectedRoots, setSelectedRoots] = useState<Set<string>>(new Set(['C:\\']));
  const [customRootInput, setCustomRootInput] = useState<string>('');

  // Active Scan Telemetry
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [filesScanned, setFilesScanned] = useState<number>(0);
  const [candidatesFound, setCandidatesFound] = useState<number>(0);
  const [reclaimableBytes, setReclaimableBytes] = useState<number>(0);
  const [elapsedMs, setElapsedMs] = useState<number>(0);
  const [currentPath, setCurrentPath] = useState<string>('');
  const [currentCategory, setCurrentCategory] = useState<string>('');
  const [progressPercent, setProgressPercent] = useState<number | undefined>(undefined);

  // Live Discovered Candidates (bounded to last 10)
  const [liveCandidates, setLiveCandidates] = useState<LiveCandidateItem[]>([]);

  // Summaries
  const [completedSummary, setCompletedSummary] = useState<ScanSummaryDto | null>(null);
  const [partialStats, setPartialStats] = useState<{
    sessionId: string;
    filesScanned: number;
    candidatesFound: number;
    reclaimableBytes: number;
    elapsedMs: number;
  } | null>(null);

  // Elevation & Errors
  const [elevationAlert, setElevationAlert] = useState<{ reason: string; scope: string } | null>(null);
  const [scanError, setScanError] = useState<IpcError | null>(null);

  // Cancellation Confirmation
  const [showCancelDialog, setShowCancelDialog] = useState<boolean>(false);

  // Throttling for high frequency events
  const lastProgressUpdateRef = useRef<number>(0);

  // Fetch available drives on mount
  useEffect(() => {
    client
      .getStorageSummary()
      .then((storage) => {
        if (storage.drives && storage.drives.length > 0) {
          const driveRoots = storage.drives.map((d) => d.mount_point);
          setAvailableRoots(driveRoots);
          setSelectedRoots(new Set(driveRoots.slice(0, 1))); // default select first drive (e.g. C:\)
        }
      })
      .catch((err) => {
        console.warn('Could not query storage summary for drive roots:', err);
      });
  }, [client]);

  // Reconnect & State Reconciliation
  const reconcileScanStatus = useCallback(async () => {
    if (connectionStatus !== 'connected') {
      if (connectionStatus === 'error' || connectionStatus === 'disconnected') {
        setUiState('core_disconnected');
      }
      return;
    }

    try {
      const status = await client.getScanStatus();
      if (status.state === 'scanning') {
        setUiState('scanning');
        setActiveSessionId(status.session_id ?? 'active-session');
        setFilesScanned(status.files_scanned);
        setCandidatesFound(status.candidates_found);
        setElapsedMs(status.elapsed_ms);
        setCurrentPath(status.current_path ?? '');
        setProgressPercent(status.progress_percent);
      } else if (status.state === 'completed' && uiState === 'scanning') {
        const summary = await client.getScanSummary();
        setCompletedSummary(summary);
        setUiState('completed');
      }
    } catch (err) {
      console.warn('Failed to reconcile scan status:', err);
    }
  }, [client, connectionStatus, uiState]);

  useEffect(() => {
    reconcileScanStatus();
  }, [reconcileScanStatus]);

  // Core Streaming Events Subscription
  useEffect(() => {
    const unsubscribe = client.onEvent((event: IpcEvent) => {
      switch (event.type) {
        case 'scan_started':
          setActiveSessionId(event.session_id);
          setFilesScanned(0);
          setCandidatesFound(0);
          setReclaimableBytes(0);
          setElapsedMs(0);
          setCurrentPath('');
          setCurrentCategory('');
          setProgressPercent(undefined);
          setLiveCandidates([]);
          setElevationAlert(null);
          setScanError(null);
          setUiState('scanning');
          break;

        case 'scan_progress': {
          const now = Date.now();
          // Throttle state update to at most once every 50ms to maintain fluid UI without lag
          if (now - lastProgressUpdateRef.current >= 50) {
            lastProgressUpdateRef.current = now;
            setFilesScanned(event.files_scanned);
            setCandidatesFound(event.candidates_found);
            setReclaimableBytes(event.estimated_reclaimable_bytes);
            setElapsedMs(event.elapsed_ms);
            setCurrentPath(event.current_path);
            setCurrentCategory(event.current_category);
          }
          break;
        }

        case 'scan_candidate_discovered': {
          const c: CandidateExplainabilityDto = event.candidate;
          const fileName = c.path.split(/[/\\]/).pop() || c.path;
          const newItem: LiveCandidateItem = {
            id: c.id,
            name: fileName,
            path: c.path,
            category: c.category,
            size_bytes: c.size_bytes,
            risk_score: c.risk_score,
            risk_band: c.risk_band,
            safety_verdict: c.safety_verdict,
          };
          setLiveCandidates((prev) => [newItem, ...prev.slice(0, 9)]);
          break;
        }

        case 'scan_completed':
          setFilesScanned(event.summary.total_files_scanned);
          setCandidatesFound(event.summary.total_candidates_found);
          setReclaimableBytes(event.summary.total_reclaimable_bytes);
          setElapsedMs(event.summary.elapsed_ms);
          setCompletedSummary(event.summary);
          setUiState('completed');
          break;

        case 'scan_cancelled':
          setPartialStats({
            sessionId: event.session_id,
            filesScanned: event.partial_summary.total_files_scanned,
            candidatesFound: event.partial_summary.total_candidates_found,
            reclaimableBytes: event.partial_summary.total_reclaimable_bytes,
            elapsedMs: event.partial_summary.elapsed_ms,
          });
          setUiState('cancelled');
          break;

        case 'elevation_required':
          setElevationAlert({
            reason: event.reason,
            scope: event.action_attempted,
          });
          break;

        case 'diagnostic_message':
          if (event.level === 'error') {
            setScanError({
              code: 'INTERNAL_CORE_ERROR',
              message: event.message,
            });
          }
          break;

        default:
          break;
      }
    });

    return () => {
      unsubscribe();
    };
  }, [client]);

  // Root Toggles
  const toggleRoot = (root: string) => {
    setSelectedRoots((prev) => {
      const next = new Set(prev);
      if (next.has(root)) {
        if (next.size > 1) {
          next.delete(root);
        }
      } else {
        next.add(root);
      }
      return next;
    });
  };

  const handleAddCustomRoot = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = customRootInput.trim();
    if (trimmed && !availableRoots.includes(trimmed)) {
      setAvailableRoots((prev) => [...prev, trimmed]);
      setSelectedRoots((prev) => new Set(prev).add(trimmed));
      setCustomRootInput('');
    }
  };

  // Start Scan Action
  const handleStartScan = async () => {
    if (selectedRoots.size === 0) return;

    setUiState('starting');
    setScanError(null);
    setElevationAlert(null);

    const roots = Array.from(selectedRoots);

    try {
      const response = await client.startScan({
        mode: scanMode,
        roots,
      });
      setActiveSessionId(response.session_id);
      // Wait for scan_started event to transition to 'scanning', or transition directly
      setUiState('scanning');
    } catch (err) {
      setUiState('failed');
      if (err instanceof IpcClientError) {
        setScanError({
          code: err.code,
          message: err.message,
          details: err.details,
        });
      } else {
        setScanError({
          code: 'INTERNAL_CORE_ERROR',
          message: err instanceof Error ? err.message : String(err),
        });
      }
    }
  };

  // Cancel Scan Action
  const handleConfirmCancel = async () => {
    setShowCancelDialog(false);
    if (!activeSessionId) return;

    setUiState('cancelling');
    try {
      await client.cancelScan(activeSessionId);
      // The scan_cancelled event will transition uiState to 'cancelled'
    } catch (err) {
      if (err instanceof IpcClientError) {
        // If scan was already completed before cancellation took effect
        if (err.code === 'STATE_DRIFT' || err.message.includes('completed')) {
          setUiState('completed');
          return;
        }
        setScanError({
          code: err.code,
          message: err.message,
          details: err.details,
        });
      } else {
        setScanError({
          code: 'INTERNAL_CORE_ERROR',
          message: err instanceof Error ? err.message : String(err),
        });
      }
      setUiState('failed');
    }
  };

  const handleResetToIdle = () => {
    setUiState('idle');
    setActiveSessionId(null);
    setFilesScanned(0);
    setCandidatesFound(0);
    setReclaimableBytes(0);
    setElapsedMs(0);
    setCurrentPath('');
    setCurrentCategory('');
    setProgressPercent(undefined);
    setLiveCandidates([]);
    setCompletedSummary(null);
    setPartialStats(null);
    setScanError(null);
    setElevationAlert(null);
  };

  // RENDER: Core Disconnected
  if (uiState === 'core_disconnected' || connectionStatus === 'disconnected') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Filesystem Scan
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            Scanner control is paused because the native core is offline.
          </p>
        </div>
        <ErrorState
          error={{
            code: 'INTERNAL_CORE_ERROR',
            message: 'Native Rust core process is unreachable. Re-establish connection before scanning.',
          }}
          onRetry={reconcileScanStatus}
        />
      </div>
    );
  }

  // RENDER: Failed State
  if (uiState === 'failed' && scanError) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Scan Execution Interrupted
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            The scanner encountered a structured core error.
          </p>
        </div>
        <ErrorState
          error={scanError}
          onRetry={handleResetToIdle}
          onRequestElevation={requestElevation}
        />
        <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
          <Button variant="secondary" leftIcon={<RotateCcw size={14} />} onClick={handleResetToIdle}>
            Return to Scan Configuration
          </Button>
        </div>
      </div>
    );
  }

  // RENDER: Completed Summary Screen
  if (uiState === 'completed' && completedSummary) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <CheckCircle2 size={20} color="#10b981" />
              <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Scan Completed Successfully
              </h1>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Session <code style={{ fontFamily: 'monospace', color: '#93c5fd' }}>{completedSummary.session_id}</code> finished in {formatDuration(completedSummary.elapsed_ms)}.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <Button variant="secondary" leftIcon={<RotateCcw size={14} />} onClick={handleResetToIdle}>
              Run New Scan
            </Button>
            <Button
              variant="primary"
              rightIcon={<ArrowRight size={14} />}
              onClick={() => setCurrentRoute('results')}
            >
              View Cleanup Candidates
            </Button>
          </div>
        </div>

        {/* Top Summary Metrics */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
          <Card title="Files Inspected" subtitle="Native traversal total">
            <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--text-primary)' }}>
              {formatNumber(completedSummary.total_files_scanned)}
            </div>
          </Card>

          <Card title="Candidates Identified" subtitle="Discovered removal targets">
            <div style={{ fontSize: '22px', fontWeight: 700, color: '#38bdf8' }}>
              {formatNumber(completedSummary.total_candidates_found)}
            </div>
          </Card>

          <Card title="Potential Reclaimable Space" subtitle="Assessed candidate capacity">
            <div style={{ fontSize: '22px', fontWeight: 700, color: '#10b981' }}>
              {formatBytes(completedSummary.total_reclaimable_bytes)}
            </div>
          </Card>

          <Card title="Inspection Duration" subtitle="Total elapsed time">
            <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--text-primary)' }}>
              {formatDuration(completedSummary.elapsed_ms)}
            </div>
          </Card>
        </div>

        {/* Safety Engine Eligibility Breakdown */}
        <Card title="Safety Engine Assessment Breakdown" subtitle="Calculated without destructive alterations">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
            <div style={{ padding: '12px', backgroundColor: 'rgba(6, 78, 59, 0.25)', border: '1px solid var(--safety-safe-border)', borderRadius: '6px' }}>
              <Badge variant="safe">Auto-Quarantine Eligible</Badge>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--safety-safe-text)', marginTop: '8px' }}>
                {formatBytes(completedSummary.auto_eligible_bytes)}
              </div>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                Low risk temporary files and expired application caches.
              </p>
            </div>

            <div style={{ padding: '12px', backgroundColor: 'rgba(69, 26, 3, 0.25)', border: '1px solid var(--safety-review-border)', borderRadius: '6px' }}>
              <Badge variant="review">User Confirmation Required</Badge>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--safety-review-text)', marginTop: '8px' }}>
                {formatBytes(completedSummary.user_confirm_bytes)}
              </div>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                Installers, ambiguous caches, or large userland files.
              </p>
            </div>

            <div style={{ padding: '12px', backgroundColor: 'rgba(46, 16, 101, 0.25)', border: '1px solid var(--safety-protected-border)', borderRadius: '6px' }}>
              <Badge variant="protected">Protected / Never Delete</Badge>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--safety-protected-text)', marginTop: '8px' }}>
                {formatBytes(completedSummary.blocked_bytes)}
              </div>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                Protected system resources, active binaries, or excluded paths.
              </p>
            </div>
          </div>
        </Card>

        {/* Category Breakdown */}
        {completedSummary.categories && completedSummary.categories.length > 0 && (
          <Card title="Category Distribution" subtitle="Classified candidate groupings">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {completedSummary.categories.map((cat) => (
                <div
                  key={cat.category}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 12px',
                    backgroundColor: 'rgba(0,0,0,0.15)',
                    borderRadius: '4px',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <Folder size={16} color="#3b82f6" />
                    <span style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-primary)' }}>
                      {cat.category}
                    </span>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      ({cat.count} files)
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {formatBytes(cat.total_bytes)}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}
      </div>
    );
  }

  // RENDER: Cancelled State (Partial Statistics Preserved)
  if (uiState === 'cancelled') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <AlertTriangle size={20} color="#f59e0b" />
              <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Scan Cancelled by User
              </h1>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              The scan process was safely stopped. Discovered candidate statistics were preserved.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <Button variant="secondary" leftIcon={<RotateCcw size={14} />} onClick={handleResetToIdle}>
              Configure New Scan
            </Button>
            {partialStats && partialStats.candidatesFound > 0 && (
              <Button
                variant="outline"
                rightIcon={<ArrowRight size={14} />}
                onClick={() => setCurrentRoute('results')}
              >
                View Discovered Candidates ({partialStats.candidatesFound})
              </Button>
            )}
          </div>
        </div>

        {partialStats && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
            <Card title="Files Inspected Before Stop" subtitle="Partial coverage">
              <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--text-primary)' }}>
                {formatNumber(partialStats.filesScanned)}
              </div>
            </Card>

            <Card title="Candidates Preserved" subtitle="Discovered up to cancellation">
              <div style={{ fontSize: '22px', fontWeight: 700, color: '#38bdf8' }}>
                {formatNumber(partialStats.candidatesFound)}
              </div>
            </Card>

            <Card title="Reclaimable Space Assessed" subtitle="Found prior to stop">
              <div style={{ fontSize: '22px', fontWeight: 700, color: '#10b981' }}>
                {formatBytes(partialStats.reclaimableBytes)}
              </div>
            </Card>

            <Card title="Elapsed Active Time" subtitle="Inspection time">
              <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--text-primary)' }}>
                {formatDuration(partialStats.elapsedMs)}
              </div>
            </Card>
          </div>
        )}
      </div>
    );
  }

  // RENDER: Active Scan View (Scanning / Starting / Cancelling)
  if (uiState === 'scanning' || uiState === 'starting' || uiState === 'cancelling') {
    const isCancelling = uiState === 'cancelling';

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
                {isCancelling ? 'Cancelling Filesystem Scan...' : 'Scan In Progress'}
              </h1>
              <Badge variant={isCancelling ? 'review' : 'info'}>
                {isCancelling ? 'Cancelling' : scanMode.toUpperCase()}
              </Badge>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Session ID: <code style={{ fontFamily: 'monospace', color: '#93c5fd' }}>{activeSessionId ?? 'negotiating'}</code>
            </p>
          </div>

          <Button
            variant="danger"
            size="md"
            leftIcon={<StopCircle size={15} />}
            disabled={isCancelling}
            isLoading={isCancelling}
            onClick={() => setShowCancelDialog(true)}
          >
            {isCancelling ? 'Cancelling...' : 'Cancel Scan'}
          </Button>
        </div>

        {/* Elevation Alert Banner if emitted during scan */}
        {elevationAlert && (
          <div
            style={{
              padding: '12px 16px',
              borderRadius: '6px',
              border: '1px solid #f97316',
              backgroundColor: 'rgba(59, 37, 5, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ShieldAlert size={20} color="#f97316" />
              <div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#fed7aa' }}>
                  Administrator Elevation Required for Protected Scope
                </div>
                <div style={{ fontSize: '12px', color: '#fdba74', marginTop: '2px' }}>
                  {elevationAlert.reason} ({elevationAlert.scope})
                </div>
              </div>
            </div>
            <Button variant="primary" size="sm" onClick={requestElevation}>
              Request Elevation
            </Button>
          </div>
        )}

        {/* Live Progress Indicator: Strict Invariant: No fake percentages! */}
        <Card>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <ProgressIndicator
              progressPercent={progressPercent}
              statusLabel={
                isCancelling
                  ? 'Signalling core to abort traversal...'
                  : `Traversing: ${currentCategory || 'Analyzing directories...'}`
              }
              detailLabel={`${formatNumber(filesScanned)} files inspected`}
            />

            {currentPath && (
              <div
                title={currentPath}
                style={{
                  fontSize: '11px',
                  fontFamily: 'monospace',
                  color: 'var(--text-muted)',
                  backgroundColor: 'rgba(0,0,0,0.2)',
                  padding: '6px 10px',
                  borderRadius: '4px',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                {currentPath}
              </div>
            )}
          </div>
        </Card>

        {/* Live Scan Telemetry Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px' }}>
          <Card title="Files Scanned" subtitle="Real-time count">
            <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)' }}>
              {formatNumber(filesScanned)}
            </div>
          </Card>

          <Card title="Candidates Found" subtitle="Target candidates">
            <div style={{ fontSize: '20px', fontWeight: 700, color: '#38bdf8' }}>
              {formatNumber(candidatesFound)}
            </div>
          </Card>

          <Card title="Estimated Reclaimable" subtitle="Assessed potential">
            <div style={{ fontSize: '20px', fontWeight: 700, color: '#10b981' }}>
              {formatBytes(reclaimableBytes)}
            </div>
          </Card>

          <Card title="Active Elapsed Time" subtitle="Timer">
            <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)' }}>
              {formatDuration(elapsedMs)}
            </div>
          </Card>
        </div>

        {/* Live Candidate Discovery Stream */}
        <Card
          title="Live Candidate Discovery Stream"
          subtitle="Files evaluated by Safety Engine rules in real time (Read-only)"
        >
          {liveCandidates.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)', fontSize: '13px' }}>
              Evaluating filesystem structures. Candidates will stream here as discovered.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {liveCandidates.map((candidate) => (
                <div
                  key={candidate.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 12px',
                    backgroundColor: 'rgba(0,0,0,0.2)',
                    borderRadius: '4px',
                    border: '1px solid var(--border-subtle)',
                    fontSize: '12px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0, flex: 1 }}>
                    <Folder size={15} color="#60a5fa" style={{ flexShrink: 0 }} />
                    <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
                      <span
                        style={{
                          color: 'var(--text-primary)',
                          fontWeight: 500,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                        title={candidate.path}
                      >
                        {candidate.name}
                      </span>
                      <span
                        style={{
                          fontSize: '11px',
                          color: 'var(--text-muted)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {candidate.category}
                      </span>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexShrink: 0, marginLeft: '12px' }}>
                    <span style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                      {formatBytes(candidate.size_bytes)}
                    </span>
                    <Badge riskBand={candidate.risk_band}>
                      {candidate.risk_band} ({candidate.risk_score})
                    </Badge>
                    <Badge safetyVerdict={candidate.safety_verdict} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Cancellation Confirmation Dialog */}
        <ConfirmationDialog
          isOpen={showCancelDialog}
          title="Cancel Active Scan?"
          message="Stopping the scan now will safely halt traversal. All candidates assessed up to this point will be preserved in partial statistics."
          confirmLabel="Cancel Scan Now"
          cancelLabel="Resume Scan"
          variant="danger"
          onClose={() => setShowCancelDialog(false)}
          onConfirm={handleConfirmCancel}
        />
      </div>
    );
  }

  // RENDER: Scan Configuration Screen (Idle)
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div>
        <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
          Configure Filesystem Scan
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
          Select scan depth and target partitions. All operations are non-destructive and verified by the Safety Engine.
        </p>
      </div>

      {/* Mode Selection Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px' }}>
        {/* Quick Scan */}
        <div
          onClick={() => setScanMode('quick')}
          style={{
            border: scanMode === 'quick' ? '1px solid #3b82f6' : '1px solid var(--border-color)',
            backgroundColor: scanMode === 'quick' ? 'rgba(37, 99, 235, 0.1)' : 'var(--bg-secondary)',
            borderRadius: '8px',
            padding: '16px',
            cursor: 'pointer',
            transition: 'border-color 0.15s ease, background-color 0.15s ease',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Zap size={18} color="#eab308" />
              <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Quick Scan
              </h3>
            </div>
            {scanMode === 'quick' && <Badge variant="info">Selected</Badge>}
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            Fast targeted inspection of known temporary caches, browser residue, and crash dumps.
          </p>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            • Zero deep content hashing
            <br />• Minimal I/O footprint
          </div>
        </div>

        {/* Smart Scan (Recommended) */}
        <div
          onClick={() => setScanMode('smart')}
          style={{
            border: scanMode === 'smart' ? '1px solid #3b82f6' : '1px solid var(--border-color)',
            backgroundColor: scanMode === 'smart' ? 'rgba(37, 99, 235, 0.1)' : 'var(--bg-secondary)',
            borderRadius: '8px',
            padding: '16px',
            cursor: 'pointer',
            transition: 'border-color 0.15s ease, background-color 0.15s ease',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
            position: 'relative',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Cpu size={18} color="#3b82f6" />
              <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Smart Scan
              </h3>
            </div>
            {scanMode === 'smart' ? (
              <Badge variant="info">Selected</Badge>
            ) : (
              <Badge variant="safe">Recommended</Badge>
            )}
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            Balanced heuristic scan with PE byte inspection for executables, registry attribution, and deletion-risk scoring.
          </p>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            • PE header inspection from bytes
            <br />• Software ownership verification
          </div>
        </div>

        {/* Deep Scan */}
        <div
          onClick={() => setScanMode('deep')}
          style={{
            border: scanMode === 'deep' ? '1px solid #3b82f6' : '1px solid var(--border-color)',
            backgroundColor: scanMode === 'deep' ? 'rgba(37, 99, 235, 0.1)' : 'var(--bg-secondary)',
            borderRadius: '8px',
            padding: '16px',
            cursor: 'pointer',
            transition: 'border-color 0.15s ease, background-color 0.15s ease',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Layers size={18} color="#a855f7" />
              <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Deep Scan
              </h3>
            </div>
            {scanMode === 'deep' && <Badge variant="info">Selected</Badge>}
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            Comprehensive recursive filesystem walk, PE byte inspection for all files regardless of extension, and hashing.
          </p>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            • Full recursive tree traversal
            <br />• Thorough byte inspection
          </div>
        </div>
      </div>

      {/* Target Drive Roots Selection */}
      <Card
        title="Target Partitions & Directories"
        subtitle="Select one or more volume roots to scan"
        actions={
          <Badge variant="neutral">
            {selectedRoots.size} {selectedRoots.size === 1 ? 'Root Selected' : 'Roots Selected'}
          </Badge>
        }
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px' }}>
            {availableRoots.map((root) => {
              const isSelected = selectedRoots.has(root);
              return (
                <label
                  key={root}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    padding: '8px 14px',
                    backgroundColor: isSelected ? 'rgba(37, 99, 235, 0.15)' : 'rgba(0,0,0,0.15)',
                    border: isSelected ? '1px solid #3b82f6' : '1px solid var(--border-color)',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    fontSize: '13px',
                    fontWeight: 500,
                    userSelect: 'none',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => toggleRoot(root)}
                    style={{ cursor: 'pointer' }}
                  />
                  <HardDrive size={15} color={isSelected ? '#3b82f6' : 'var(--text-muted)'} />
                  <span>{root}</span>
                </label>
              );
            })}
          </div>

          {/* Add custom path */}
          <form onSubmit={handleAddCustomRoot} style={{ display: 'flex', gap: '8px', maxWidth: '420px' }}>
            <input
              type="text"
              placeholder="e.g. C:\Users\Username\Downloads"
              value={customRootInput}
              onChange={(e) => setCustomRootInput(e.target.value)}
              style={{
                flex: 1,
                padding: '6px 10px',
                borderRadius: '4px',
                border: '1px solid var(--border-color)',
                backgroundColor: 'var(--bg-primary)',
                color: 'var(--text-primary)',
                fontSize: '12px',
                outline: 'none',
              }}
            />
            <Button variant="outline" size="sm" type="submit">
              Add Path
            </Button>
          </form>
        </div>
      </Card>

      {/* Start Scan Execution Bar */}
      <div
        style={{
          padding: '16px 20px',
          backgroundColor: 'var(--bg-secondary)',
          border: '1px solid var(--border-color)',
          borderRadius: '8px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Ready to initiate {scanMode.toUpperCase()} scan
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Scope: {Array.from(selectedRoots).join(', ')}
          </div>
        </div>

        <Button
          variant="primary"
          size="lg"
          leftIcon={<Search size={16} />}
          disabled={selectedRoots.size === 0 || connectionStatus !== 'connected'}
          onClick={handleStartScan}
        >
          Start Scan
        </Button>
      </div>
    </div>
  );
};
