import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useApp } from '../state/AppContext';
import { Card } from '../design-system/Card';
import { Badge } from '../design-system/Badge';
import { Button } from '../design-system/Button';
import { EmptyState } from '../design-system/EmptyState';
import { ErrorState } from '../design-system/ErrorState';
import { ExplainabilityDrawer } from '../components/ExplainabilityDrawer';
import {
  CandidateExplainabilityDto,
  RiskBand,
  SafetyVerdict,
  IpcError,
} from '../types/ipc';
import { formatBytes, formatDuration, formatNumber } from '../utils/format';
import {
  ListFilter,
  Search,
  Lock,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  FolderArchive,
  CheckCircle2,
  AlertTriangle,
  XCircle,
} from 'lucide-react';
import { ConfirmationDialog } from '../design-system/ConfirmationDialog';
import { Modal } from '../design-system/Modal';
import { QuarantineOperationResultDto } from '../types/ipc';

export type SortField = 'size' | 'risk_score' | 'name' | 'category' | 'safety_verdict';

export const ResultsView: React.FC = () => {
  const { client, connectionStatus, latestScanSummary, setCurrentRoute, openElevationModal } = useApp();

  const [candidates, setCandidates] = useState<CandidateExplainabilityDto[]>([]);
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set());
  const [activeCandidateDetail, setActiveCandidateDetail] = useState<CandidateExplainabilityDto | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [resultsError, setResultsError] = useState<IpcError | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedRiskBand, setSelectedRiskBand] = useState<string>('All');
  const [selectedVerdict, setSelectedVerdict] = useState<string>('All');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [filterLargeOnly, setFilterLargeOnly] = useState<boolean>(false);

  // Sorting
  const [sortField, setSortField] = useState<SortField>('size');
  const [sortAsc, setSortAsc] = useState<boolean>(false);

  // Pagination
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 25;

  // Quarantine Execution & Feedback State
  const [isConfirmingQuarantine, setIsConfirmingQuarantine] = useState<boolean>(false);
  const [isQuarantining, setIsQuarantining] = useState<boolean>(false);
  const [quarantineResult, setQuarantineResult] = useState<QuarantineOperationResultDto | null>(null);

  // Load cleanup candidates from IPC Core
  const loadCandidates = useCallback(async () => {
    setIsLoading(true);
    setResultsError(null);
    try {
      const data = await client.getCleanupCandidates();
      setCandidates(data);
      // Synchronize pre-selected items from core
      const preselected = new Set<string>();
      data.forEach((c) => {
        if (c.selected && c.can_quarantine && c.safety_verdict !== 'never_delete') {
          preselected.add(c.path);
        }
      });
      setSelectedPaths(preselected);
    } catch (err) {
      setResultsError({
        code: 'INTERNAL_CORE_ERROR',
        message: err instanceof Error ? err.message : 'Failed to query cleanup candidates from core',
      });
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  useEffect(() => {
    loadCandidates();
  }, [loadCandidates]);

  // Handle re-analyzing a single candidate on demand (State Drift / Lock check)
  const handleReanalyzeCandidate = async (path: string): Promise<CandidateExplainabilityDto | void> => {
    try {
      const updated = await client.requestAnalysis(path);
      setCandidates((prev) => prev.map((c) => (c.path === path ? updated : c)));
      if (activeCandidateDetail?.path === path) {
        setActiveCandidateDetail(updated);
      }
      return updated;
    } catch (err) {
      console.error('Failed to re-analyze candidate:', err);
    }
  };

  // Distinct Categories for filter dropdown
  const uniqueCategories = useMemo(() => {
    const cats = new Set<string>();
    candidates.forEach((c) => {
      if (c.category) cats.add(c.category);
    });
    return Array.from(cats).sort();
  }, [candidates]);

  // Filtered & Sorted Candidates
  const filteredCandidates = useMemo(() => {
    return candidates.filter((item) => {
      // Search query filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const fileName = item.path.split(/[/\\]/).pop()?.toLowerCase() || '';
        const matchesName = fileName.includes(query);
        const matchesPath = item.path.toLowerCase().includes(query);
        const matchesApp = item.app_owner?.toLowerCase().includes(query) ?? false;
        const matchesCategory = item.category.toLowerCase().includes(query);
        const matchesRule = item.local_rules.some((r) => r.rule_id.toLowerCase().includes(query));

        if (!matchesName && !matchesPath && !matchesApp && !matchesCategory && !matchesRule) {
          return false;
        }
      }

      // Risk Band filter
      if (selectedRiskBand !== 'All' && item.risk_band !== selectedRiskBand) {
        return false;
      }

      // Verdict filter
      if (selectedVerdict !== 'All' && item.safety_verdict !== selectedVerdict) {
        return false;
      }

      // Category filter
      if (selectedCategory !== 'All' && item.category !== selectedCategory) {
        return false;
      }

      // Large files only (> 100 MB = 104,857,600 bytes)
      if (filterLargeOnly && item.size_bytes < 104857600) {
        return false;
      }

      return true;
    });
  }, [candidates, searchQuery, selectedRiskBand, selectedVerdict, selectedCategory, filterLargeOnly]);

  const sortedCandidates = useMemo(() => {
    return [...filteredCandidates].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'size':
          comparison = a.size_bytes - b.size_bytes;
          break;
        case 'risk_score':
          comparison = a.risk_score - b.risk_score;
          break;
        case 'name': {
          const nameA = a.path.split(/[/\\]/).pop() || '';
          const nameB = b.path.split(/[/\\]/).pop() || '';
          comparison = nameA.localeCompare(nameB);
          break;
        }
        case 'category':
          comparison = a.category.localeCompare(b.category);
          break;
        case 'safety_verdict':
          comparison = a.safety_verdict.localeCompare(b.safety_verdict);
          break;
        default:
          comparison = 0;
      }
      return sortAsc ? comparison : -comparison;
    });
  }, [filteredCandidates, sortField, sortAsc]);

  // Paginated chunk
  const totalPages = Math.max(1, Math.ceil(sortedCandidates.length / pageSize));
  const paginatedCandidates = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return sortedCandidates.slice(start, start + pageSize);
  }, [sortedCandidates, currentPage, pageSize]);

  // Summary Metrics (Derived from core data only)
  const totalReclaimableBytes = useMemo(() => {
    return candidates.reduce((acc, item) => {
      return item.can_quarantine ? acc + item.size_bytes : acc;
    }, 0);
  }, [candidates]);

  const selectedStats = useMemo(() => {
    let count = 0;
    let bytes = 0;
    candidates.forEach((c) => {
      if (selectedPaths.has(c.path)) {
        count += 1;
        bytes += c.size_bytes;
      }
    });
    return { count, bytes };
  }, [candidates, selectedPaths]);

  const verdictDistribution = useMemo(() => {
    let autoCount = 0;
    let reviewCount = 0;
    let protectedCount = 0;
    candidates.forEach((c) => {
      if (c.safety_verdict === 'auto_quarantine') autoCount += 1;
      else if (c.safety_verdict === 'user_confirm') reviewCount += 1;
      else if (c.safety_verdict === 'never_delete') protectedCount += 1;
    });
    return { autoCount, reviewCount, protectedCount };
  }, [candidates]);

  // Selection Actions: Never allow selecting never_delete items
  const handleToggleCandidate = async (candidate: CandidateExplainabilityDto) => {
    if (candidate.safety_verdict === 'never_delete' || !candidate.can_quarantine) {
      return; // Absolute safety invariant: Protected items cannot be selected
    }

    const nextSelected = !selectedPaths.has(candidate.path);

    // Optimistically update local selection
    setSelectedPaths((prev) => {
      const next = new Set(prev);
      if (nextSelected) next.add(candidate.path);
      else next.delete(candidate.path);
      return next;
    });

    try {
      await client.selectCandidate(candidate.path, nextSelected);
    } catch (err) {
      console.error('Failed to update candidate selection on core:', err);
      // Rollback on error
      setSelectedPaths((prev) => {
        const next = new Set(prev);
        if (nextSelected) next.delete(candidate.path);
        else next.add(candidate.path);
        return next;
      });
    }
  };

  const handleSelectAllEligible = async (select: boolean) => {
    try {
      const filter = {
        safety_verdict: selectedVerdict !== 'All' ? (selectedVerdict as SafetyVerdict) : undefined,
        risk_band: selectedRiskBand !== 'All' ? (selectedRiskBand as RiskBand) : undefined,
        category: selectedCategory !== 'All' ? selectedCategory : undefined,
      };

      await client.selectAllCandidates(select, filter);

      setSelectedPaths((prev) => {
        const next = new Set(prev);
        filteredCandidates.forEach((c) => {
          // Never select never_delete
          if (c.can_quarantine && c.safety_verdict !== 'never_delete') {
            if (select) next.add(c.path);
            else next.delete(c.path);
          }
        });
        return next;
      });
    } catch (err) {
      console.error('Failed to select all candidates via IPC:', err);
    }
  };

  // Execute Quarantine on Selected Items via Native Core
  const handleExecuteQuarantine = async () => {
    setIsConfirmingQuarantine(false);
    setIsQuarantining(true);
    try {
      const pathsToQuarantine = Array.from(selectedPaths);
      const result = await client.quarantineSelected(pathsToQuarantine);
      setQuarantineResult(result);

      // Reconcile local candidates: remove successfully quarantined items
      const quarantinedPaths = new Set(result.quarantined.map((item) => item.original_path));
      setCandidates((prev) => prev.filter((c) => !quarantinedPaths.has(c.path)));
      setSelectedPaths((prev) => {
        const next = new Set(prev);
        quarantinedPaths.forEach((p) => next.delete(p));
        return next;
      });
    } catch (err) {
      console.error('Failed to execute quarantine on core:', err);
      setResultsError({
        code: 'QUARANTINE_FAILED',
        message: err instanceof Error ? err.message : 'Quarantine operation failed on core',
      });
    } finally {
      setIsQuarantining(false);
    }
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false); // default descending for numbers
    }
    setCurrentPage(1);
  };

  // RENDER: Core Disconnected State
  if (connectionStatus === 'error' || connectionStatus === 'disconnected') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Cleanup Candidates & Explainability
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            Results display is offline because the native core is unreachable.
          </p>
        </div>
        <ErrorState
          error={{
            code: 'INTERNAL_CORE_ERROR',
            message: 'Native Rust core process is unreachable. Re-connect to view candidates.',
          }}
          onRetry={loadCandidates}
        />
      </div>
    );
  }

  // RENDER: Results Error State
  if (resultsError) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Results Retrieval Failed
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            Could not retrieve candidate data from the core session.
          </p>
        </div>
        <ErrorState error={resultsError} onRetry={loadCandidates} />
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Cleanup Candidates & Explainability
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            Transparent assessment evaluated by the Safety Engine. Every score and verdict is authoritative.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <Button variant="secondary" size="sm" leftIcon={<RefreshCw size={13} />} onClick={loadCandidates}>
            Refresh Results
          </Button>
          <Button variant="primary" size="sm" onClick={() => setCurrentRoute('scan')}>
            New Scan
          </Button>
        </div>
      </div>

      {/* Summary Metrics Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
        <Card title="Potential Reclaimable Space" subtitle="Safety-approved candidates">
          <div style={{ fontSize: '22px', fontWeight: 700, color: '#10b981' }}>
            {formatBytes(totalReclaimableBytes)}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            From {candidates.length} assessed candidates
          </div>
        </Card>

        <Card title="Safety Verdict Breakdown" subtitle="Authoritative core distribution">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
            <Badge variant="safe" title="Auto-Quarantine Eligible">
              {verdictDistribution.autoCount} Auto
            </Badge>
            <Badge variant="review" title="User Confirmation Required">
              {verdictDistribution.reviewCount} Review
            </Badge>
            <Badge variant="protected" title="Protected System Resources">
              {verdictDistribution.protectedCount} Protected
            </Badge>
          </div>
        </Card>

        <Card title="Active Selection" subtitle="Prepared for quarantine review">
          <div style={{ fontSize: '22px', fontWeight: 700, color: selectedStats.count > 0 ? '#38bdf8' : 'var(--text-muted)' }}>
            {selectedStats.count} items ({formatBytes(selectedStats.bytes)})
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Protected items excluded automatically
          </div>
        </Card>

        {latestScanSummary && (
          <Card title="Scan Provenance" subtitle={`Session: ${latestScanSummary.session_id.slice(0, 12)}`}>
            <div style={{ fontSize: '12px', color: 'var(--text-primary)', fontWeight: 500 }}>
              Elapsed: {formatDuration(latestScanSummary.elapsed_ms)} • {formatNumber(latestScanSummary.total_files_scanned)} files
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Categories: {latestScanSummary.categories?.length ?? 0} identified
            </div>
          </Card>
        )}
      </div>

      {/* Filter and Search Bar */}
      <Card>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', alignItems: 'center', justifyContent: 'space-between' }}>
            {/* Search Input */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: '260px', flex: 1 }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  backgroundColor: 'var(--bg-primary)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '6px',
                  padding: '6px 10px',
                  width: '100%',
                }}
              >
                <Search size={15} color="var(--text-muted)" />
                <input
                  type="text"
                  placeholder="Search by file name, path, application owner, or rule ID..."
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setCurrentPage(1);
                  }}
                  style={{
                    border: 'none',
                    outline: 'none',
                    background: 'transparent',
                    color: 'var(--text-primary)',
                    fontSize: '12px',
                    width: '100%',
                  }}
                />
              </div>
            </div>

            {/* Verdict Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Verdict:</span>
              <select
                value={selectedVerdict}
                onChange={(e) => {
                  setSelectedVerdict(e.target.value);
                  setCurrentPage(1);
                }}
                style={{
                  backgroundColor: 'var(--bg-primary)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '4px',
                  padding: '5px 8px',
                  fontSize: '12px',
                  outline: 'none',
                }}
              >
                <option value="All">All Verdicts</option>
                <option value="auto_quarantine">Auto Quarantine</option>
                <option value="user_confirm">User Confirm</option>
                <option value="never_delete">Never Delete (Protected)</option>
              </select>
            </div>

            {/* Risk Band Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Risk:</span>
              <select
                value={selectedRiskBand}
                onChange={(e) => {
                  setSelectedRiskBand(e.target.value);
                  setCurrentPage(1);
                }}
                style={{
                  backgroundColor: 'var(--bg-primary)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '4px',
                  padding: '5px 8px',
                  fontSize: '12px',
                  outline: 'none',
                }}
              >
                <option value="All">All Bands</option>
                <option value="Safe">Safe (0–34)</option>
                <option value="Review">Review (35–59)</option>
                <option value="Dangerous">Dangerous (60–85)</option>
                <option value="Protected">Protected (86–100)</option>
              </select>
            </div>

            {/* Category Filter */}
            {uniqueCategories.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Category:</span>
                <select
                  value={selectedCategory}
                  onChange={(e) => {
                    setSelectedCategory(e.target.value);
                    setCurrentPage(1);
                  }}
                  style={{
                    backgroundColor: 'var(--bg-primary)',
                    color: 'var(--text-primary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '4px',
                    padding: '5px 8px',
                    fontSize: '12px',
                    outline: 'none',
                  }}
                >
                  <option value="All">All Categories</option>
                  {uniqueCategories.map((cat) => (
                    <option key={cat} value={cat}>
                      {cat}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* Large files toggle */}
            <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--text-secondary)', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={filterLargeOnly}
                onChange={(e) => {
                  setFilterLargeOnly(e.target.checked);
                  setCurrentPage(1);
                }}
              />
              <span>&gt; 100 MB only</span>
            </label>
          </div>

          {/* Selection Actions & Batch Controls */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              paddingTop: '10px',
              borderTop: '1px solid var(--border-subtle)',
              fontSize: '12px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Button variant="outline" size="sm" onClick={() => handleSelectAllEligible(true)}>
                Select All Eligible
              </Button>
              <Button variant="ghost" size="sm" onClick={() => handleSelectAllEligible(false)}>
                Deselect All
              </Button>
              <span style={{ color: 'var(--text-muted)' }}>
                Showing {filteredCandidates.length} of {candidates.length} candidates
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>
                {selectedStats.count} selected ({formatBytes(selectedStats.bytes)})
              </span>
              <Button
                variant="primary"
                size="sm"
                disabled={selectedStats.count === 0}
                isLoading={isQuarantining}
                leftIcon={<FolderArchive size={14} />}
                onClick={() => setIsConfirmingQuarantine(true)}
                title="Safely move selected files into the reversible Quarantine Vault"
              >
                Quarantine Selected ({selectedStats.count})
              </Button>
            </div>
          </div>
        </div>
      </Card>

      {/* Candidate Table */}
      {candidates.length === 0 && !isLoading ? (
        <EmptyState
          icon={<ListFilter size={36} />}
          title="No Candidates Found"
          description="The last scan did not locate any removable files. Run a Smart or Deep scan to analyze storage locations."
          action={
            <Button variant="primary" onClick={() => setCurrentRoute('scan')}>
              Initiate Scan
            </Button>
          }
        />
      ) : filteredCandidates.length === 0 ? (
        <EmptyState
          icon={<Search size={36} />}
          title="No Matching Candidates"
          description="No candidate files matched your active search query or filter selection."
          action={
            <Button
              variant="secondary"
              onClick={() => {
                setSearchQuery('');
                setSelectedRiskBand('All');
                setSelectedVerdict('All');
                setSelectedCategory('All');
                setFilterLargeOnly(false);
              }}
            >
              Clear Filters
            </Button>
          }
        />
      ) : (
        <div
          style={{
            border: '1px solid var(--border-color)',
            borderRadius: '6px',
            overflow: 'hidden',
            backgroundColor: 'var(--bg-secondary)',
          }}
        >
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead>
              <tr style={{ backgroundColor: 'rgba(0,0,0,0.25)', borderBottom: '1px solid var(--border-color)' }}>
                <th style={{ width: '40px', padding: '10px 12px', textAlign: 'center' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Sel</span>
                </th>
                <th
                  onClick={() => handleSort('name')}
                  style={{
                    padding: '10px 14px',
                    textAlign: 'left',
                    fontWeight: 600,
                    color: sortField === 'name' ? '#38bdf8' : 'var(--text-secondary)',
                    cursor: 'pointer',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <span>File Name & Path</span>
                    <ArrowUpDown size={12} />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('category')}
                  style={{
                    padding: '10px 14px',
                    textAlign: 'left',
                    fontWeight: 600,
                    color: sortField === 'category' ? '#38bdf8' : 'var(--text-secondary)',
                    width: '140px',
                    cursor: 'pointer',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <span>Category</span>
                    <ArrowUpDown size={12} />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('size')}
                  style={{
                    padding: '10px 14px',
                    textAlign: 'right',
                    fontWeight: 600,
                    color: sortField === 'size' ? '#38bdf8' : 'var(--text-secondary)',
                    width: '110px',
                    cursor: 'pointer',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '4px' }}>
                    <span>Size</span>
                    <ArrowUpDown size={12} />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('risk_score')}
                  style={{
                    padding: '10px 14px',
                    textAlign: 'center',
                    fontWeight: 600,
                    color: sortField === 'risk_score' ? '#38bdf8' : 'var(--text-secondary)',
                    width: '110px',
                    cursor: 'pointer',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '4px' }}>
                    <span>Risk Score</span>
                    <ArrowUpDown size={12} />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('safety_verdict')}
                  style={{
                    padding: '10px 14px',
                    textAlign: 'center',
                    fontWeight: 600,
                    color: sortField === 'safety_verdict' ? '#38bdf8' : 'var(--text-secondary)',
                    width: '180px',
                    cursor: 'pointer',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '4px' }}>
                    <span>Safety Verdict</span>
                    <ArrowUpDown size={12} />
                  </div>
                </th>
                <th style={{ width: '80px', padding: '10px 12px', textAlign: 'center' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Action</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {paginatedCandidates.map((candidate) => {
                const isSelected = selectedPaths.has(candidate.path);
                const isProtected = candidate.safety_verdict === 'never_delete' || !candidate.can_quarantine;
                const fileName = candidate.path.split(/[/\\]/).pop() || candidate.path;

                return (
                  <tr
                    key={candidate.path}
                    onClick={() => setActiveCandidateDetail(candidate)}
                    style={{
                      borderBottom: '1px solid var(--border-subtle)',
                      backgroundColor: isSelected ? 'rgba(37, 99, 235, 0.08)' : 'transparent',
                      cursor: 'pointer',
                      transition: 'background-color 0.1s ease',
                    }}
                  >
                    {/* Checkbox: Strict rule: Protected items cannot be selected */}
                    <td
                      onClick={(e) => e.stopPropagation()}
                      style={{ padding: '10px 12px', textAlign: 'center', verticalAlign: 'middle' }}
                    >
                      {isProtected ? (
                        <span title="Protected by Safety Engine: Cannot be selected for removal">
                          <Lock size={14} color="#a855f7" />
                        </span>
                      ) : (
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => handleToggleCandidate(candidate)}
                          style={{ cursor: 'pointer' }}
                        />
                      )}
                    </td>

                    {/* File Name & Path */}
                    <td style={{ padding: '10px 14px', verticalAlign: 'middle', maxWidth: '320px' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span
                            style={{
                              color: 'var(--text-primary)',
                              fontWeight: 500,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                            title={fileName}
                          >
                            {fileName}
                          </span>
                          {candidate.app_owner && (
                            <span
                              style={{
                                fontSize: '10px',
                                padding: '1px 5px',
                                borderRadius: '3px',
                                backgroundColor: 'var(--bg-tertiary)',
                                color: 'var(--text-secondary)',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}
                              title={`Attributed App: ${candidate.app_owner}`}
                            >
                              {candidate.app_owner}
                            </span>
                          )}
                        </div>
                        <span
                          style={{
                            fontSize: '11px',
                            color: 'var(--text-muted)',
                            fontFamily: 'monospace',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            marginTop: '2px',
                          }}
                          title={candidate.path}
                        >
                          {candidate.path}
                        </span>
                      </div>
                    </td>

                    {/* Category */}
                    <td style={{ padding: '10px 14px', verticalAlign: 'middle', color: 'var(--text-secondary)' }}>
                      <span style={{ fontSize: '12px' }}>{candidate.category}</span>
                    </td>

                    {/* Size */}
                    <td style={{ padding: '10px 14px', verticalAlign: 'middle', textAlign: 'right' }}>
                      <span style={{ fontFamily: 'monospace', fontWeight: 500, color: 'var(--text-primary)' }}>
                        {formatBytes(candidate.size_bytes)}
                      </span>
                    </td>

                    {/* Risk Score & Band */}
                    <td style={{ padding: '10px 14px', verticalAlign: 'middle', textAlign: 'center' }}>
                      <Badge riskBand={candidate.risk_band} title={`Risk score: ${candidate.risk_score} / 100`}>
                        {candidate.risk_score}
                      </Badge>
                    </td>

                    {/* Safety Verdict */}
                    <td style={{ padding: '10px 14px', verticalAlign: 'middle', textAlign: 'center' }}>
                      <Badge safetyVerdict={candidate.safety_verdict} />
                    </td>

                    {/* Inspect Action */}
                    <td
                      onClick={(e) => {
                        e.stopPropagation();
                        setActiveCandidateDetail(candidate);
                      }}
                      style={{ padding: '10px 12px', textAlign: 'center', verticalAlign: 'middle' }}
                    >
                      <Button variant="ghost" size="sm" title="View transparent explainability breakdown">
                        Why?
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {/* Pagination Controls */}
          {totalPages > 1 && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '10px 16px',
                borderTop: '1px solid var(--border-color)',
                backgroundColor: 'rgba(0,0,0,0.15)',
                fontSize: '12px',
              }}
            >
              <span style={{ color: 'var(--text-muted)' }}>
                Page {currentPage} of {totalPages} ({filteredCandidates.length} total items)
              </span>

              <div style={{ display: 'flex', gap: '8px' }}>
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={currentPage === 1}
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  leftIcon={<ChevronLeft size={14} />}
                >
                  Previous
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={currentPage === totalPages}
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  rightIcon={<ChevronRight size={14} />}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Explainability Drawer */}
      <ExplainabilityDrawer
        candidate={activeCandidateDetail}
        onClose={() => setActiveCandidateDetail(null)}
        onReanalyze={handleReanalyzeCandidate}
        onElevate={() => openElevationModal(`Elevation requested to inspect/quarantine protected item: ${activeCandidateDetail?.path}`)}
      />

      {/* Quarantine Confirmation Dialog */}
      {isConfirmingQuarantine && (
        <ConfirmationDialog
          isOpen={true}
          title={`Quarantine ${selectedStats.count} Selected Files?`}
          message={
            `You are about to isolate ${selectedStats.count} files (${formatBytes(selectedStats.bytes)}) into the Quarantine Vault.\n\n` +
            `• Files will be protected and preserved with cryptographic SHA-256 hashes.\n` +
            `• You can restore these items to their original filesystem paths at any time before expiration.\n` +
            `• All operations pass through the Rust Safety Engine and Preflight validation.`
          }
          confirmLabel={`Quarantine ${selectedStats.count} Files`}
          cancelLabel="Cancel"
          variant="primary"
          onConfirm={handleExecuteQuarantine}
          onClose={() => setIsConfirmingQuarantine(false)}
        />
      )}

      {/* Quarantine Operation Result Modal */}
      {quarantineResult && (
        <Modal
          isOpen={true}
          onClose={() => setQuarantineResult(null)}
          title="Quarantine Operation Result"
          width="600px"
          footer={
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <Button variant="secondary" onClick={() => setQuarantineResult(null)}>
                Dismiss
              </Button>
              <Button
                variant="primary"
                leftIcon={<FolderArchive size={14} />}
                onClick={() => {
                  setQuarantineResult(null);
                  setCurrentRoute('quarantine');
                }}
              >
                Open Quarantine Vault
              </Button>
            </div>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', fontSize: '13px' }}>
            {/* Counts Row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px' }}>
              <div
                style={{
                  padding: '10px',
                  borderRadius: '6px',
                  backgroundColor: 'rgba(16, 185, 129, 0.1)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  textAlign: 'center',
                }}
              >
                <div style={{ fontSize: '18px', fontWeight: 700, color: '#10b981' }}>
                  {quarantineResult.quarantined.length}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Successfully Vaulted</div>
              </div>

              <div
                style={{
                  padding: '10px',
                  borderRadius: '6px',
                  backgroundColor: 'rgba(245, 158, 11, 0.1)',
                  border: '1px solid rgba(245, 158, 11, 0.3)',
                  textAlign: 'center',
                }}
              >
                <div style={{ fontSize: '18px', fontWeight: 700, color: '#f59e0b' }}>
                  {quarantineResult.blocked.length}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Safety Blocked</div>
              </div>

              <div
                style={{
                  padding: '10px',
                  borderRadius: '6px',
                  backgroundColor: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  textAlign: 'center',
                }}
              >
                <div style={{ fontSize: '18px', fontWeight: 700, color: '#ef4444' }}>
                  {quarantineResult.failed.length}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Errors / Failed</div>
              </div>
            </div>

            {/* Quarantined items details */}
            {quarantineResult.quarantined.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: '#10b981' }}>
                  Vaulted Files ({quarantineResult.quarantined.length})
                </span>
                <div
                  style={{
                    maxHeight: '120px',
                    overflowY: 'auto',
                    backgroundColor: 'rgba(0,0,0,0.2)',
                    padding: '8px',
                    borderRadius: '4px',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  {quarantineResult.quarantined.map((item) => (
                    <div key={item.item_id} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}>
                      <CheckCircle2 size={12} color="#10b981" />
                      <span style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                        {item.original_path}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Blocked items details (Never hide the reason behind a block!) */}
            {quarantineResult.blocked.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: '#f59e0b' }}>
                  Safety Blocked Items ({quarantineResult.blocked.length})
                </span>
                <div
                  style={{
                    maxHeight: '120px',
                    overflowY: 'auto',
                    backgroundColor: 'rgba(0,0,0,0.2)',
                    padding: '8px',
                    borderRadius: '4px',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  {quarantineResult.blocked.map((item, idx) => (
                    <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: '2px', fontSize: '11px', paddingBottom: '4px', borderBottom: '1px solid var(--border-subtle)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <AlertTriangle size={12} color="#f59e0b" />
                        <span style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                          {item.path}
                        </span>
                      </div>
                      <span style={{ color: '#fed7aa', marginLeft: '18px' }}>Reason: {item.reason}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Failed items details */}
            {quarantineResult.failed.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: '#ef4444' }}>
                  Execution Failures ({quarantineResult.failed.length})
                </span>
                <div
                  style={{
                    maxHeight: '120px',
                    overflowY: 'auto',
                    backgroundColor: 'rgba(0,0,0,0.2)',
                    padding: '8px',
                    borderRadius: '4px',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  {quarantineResult.failed.map((item, idx) => (
                    <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: '2px', fontSize: '11px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <XCircle size={12} color="#ef4444" />
                        <span style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                          {item.path}
                        </span>
                      </div>
                      <span style={{ color: '#fca5a5', marginLeft: '18px' }}>Error: {item.error}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
};
