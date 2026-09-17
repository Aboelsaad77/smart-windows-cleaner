import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { useApp } from '../state/AppContext';
import { Card } from '../design-system/Card';
import { Table, Column } from '../design-system/Table';
import { Badge } from '../design-system/Badge';
import { Button } from '../design-system/Button';
import { Modal } from '../design-system/Modal';
import { LoadingState } from '../design-system/LoadingState';
import { ErrorState } from '../design-system/ErrorState';
import { EmptyState } from '../design-system/EmptyState';
import { AuditEntryDto, AuditFilter } from '../types/ipc';
import { formatRelativeTime, formatDate, formatNumber } from '../utils/format';
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Search,
  RefreshCw,
  Copy,
  Check,
  Database,
  Eye,
} from 'lucide-react';

export const LogsView: React.FC = () => {
  const { client } = useApp();
  const [logs, setLogs] = useState<AuditEntryDto[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [operationFilter, setOperationFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'success' | 'failed'>('all');
  const [limit, setLimit] = useState<number>(100);

  // Detail Modal
  const [selectedEntry, setSelectedEntry] = useState<AuditEntryDto | null>(null);
  const [isCopied, setIsCopied] = useState<boolean>(false);
  const [isExportCopied, setIsExportCopied] = useState<boolean>(false);

  const loadAuditLogs = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const filter: AuditFilter = { limit };
      if (operationFilter !== 'all') {
        filter.action = operationFilter;
      }
      const entries = await client.getAuditHistory(filter);
      setLogs(entries);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to retrieve audit ledger from core';
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  }, [client, limit, operationFilter]);

  useEffect(() => {
    loadAuditLogs();
  }, [loadAuditLogs]);

  // Filtered in-memory entries based on search query and status
  const filteredLogs = useMemo(() => {
    return logs.filter((entry) => {
      // Search filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesPath = entry.target_path.toLowerCase().includes(query);
        const matchesOp = entry.operation.toLowerCase().includes(query);
        const matchesDetails = entry.details?.toLowerCase().includes(query) ?? false;
        if (!matchesPath && !matchesOp && !matchesDetails) {
          return false;
        }
      }

      // Status filter
      if (statusFilter === 'success' && !entry.success) return false;
      if (statusFilter === 'failed' && entry.success) return false;

      return true;
    });
  }, [logs, searchQuery, statusFilter]);

  // Aggregate Metrics
  const stats = useMemo(() => {
    const total = logs.length;
    let successful = 0;
    let failed = 0;
    let quarantines = 0;
    let restores = 0;
    let purges = 0;
    let scans = 0;

    for (const entry of logs) {
      if (entry.success) successful++;
      else failed++;

      const op = (entry.operation || '').toLowerCase();
      if (op.includes('quarantine')) quarantines++;
      else if (op.includes('restore')) restores++;
      else if (op.includes('purge') || op.includes('delete')) purges++;
      else if (op.includes('scan')) scans++;
    }

    return { total, successful, failed, quarantines, restores, purges, scans };
  }, [logs]);

  // Copy full audit trail as JSON
  const handleExportJson = useCallback(() => {
    const jsonStr = JSON.stringify(filteredLogs, null, 2);
    navigator.clipboard.writeText(jsonStr).then(() => {
      setIsExportCopied(true);
      setTimeout(() => setIsExportCopied(false), 2000);
    });
  }, [filteredLogs]);

  // Copy single path
  const handleCopyPath = useCallback((path: string) => {
    navigator.clipboard.writeText(path).then(() => {
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2000);
    });
  }, []);

  const getOperationBadge = (op: string) => {
    const lower = op.toLowerCase();
    if (lower.includes('quarantine')) {
      return <Badge variant="review">{op}</Badge>;
    }
    if (lower.includes('restore')) {
      return <Badge variant="info">{op}</Badge>;
    }
    if (lower.includes('purge') || lower.includes('delete')) {
      return <Badge variant="dangerous">{op}</Badge>;
    }
    if (lower.includes('scan')) {
      return <Badge variant="safe">{op}</Badge>;
    }
    return <Badge variant="neutral">{op}</Badge>;
  };

  const columns: Column<AuditEntryDto>[] = [
    {
      key: 'timestamp',
      header: 'Time',
      width: '130px',
      render: (entry) => (
        <div style={{ display: 'flex', flexDirection: 'column' }} title={entry.timestamp}>
          <span style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-primary)' }}>
            {formatRelativeTime(entry.timestamp)}
          </span>
          <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
            {entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : 'N/A'}
          </span>
        </div>
      ),
    },
    {
      key: 'operation',
      header: 'Operation',
      width: '140px',
      render: (entry) => getOperationBadge(entry.operation),
    },
    {
      key: 'target_path',
      header: 'Target Path',
      render: (entry) => (
        <span
          style={{
            fontFamily: 'monospace',
            fontSize: '12px',
            color: 'var(--text-secondary)',
            wordBreak: 'break-all',
          }}
          title={entry.target_path}
        >
          {entry.target_path}
        </span>
      ),
    },
    {
      key: 'success',
      header: 'Status',
      width: '110px',
      render: (entry) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          {entry.success ? (
            <>
              <CheckCircle2 size={14} color="#10b981" />
              <span style={{ fontSize: '12px', color: '#10b981', fontWeight: 500 }}>Success</span>
            </>
          ) : (
            <>
              <XCircle size={14} color="#ef4444" />
              <span style={{ fontSize: '12px', color: '#ef4444', fontWeight: 500 }}>Failed</span>
            </>
          )}
        </div>
      ),
    },
    {
      key: 'details',
      header: 'Audit Receipt Details',
      render: (entry) => (
        <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
          {entry.details || '—'}
        </span>
      ),
    },
    {
      key: 'actions',
      header: '',
      width: '70px',
      render: (entry) => (
        <Button
          variant="ghost"
          size="sm"
          leftIcon={<Eye size={12} />}
          onClick={(e) => {
            e.stopPropagation();
            setSelectedEntry(entry);
          }}
          title="Inspect Audit Record"
        >
          View
        </Button>
      ),
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Audit & Security Logs
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Chronological audit trail of all filesystem discovery, quarantine, restoration, and purge operations with SHA-256 file receipts.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Button
            variant="secondary"
            size="sm"
            leftIcon={isExportCopied ? <Check size={13} color="#10b981" /> : <Copy size={13} />}
            onClick={handleExportJson}
            title="Copy filtered audit entries to clipboard as structured JSON"
          >
            {isExportCopied ? 'Copied JSON' : 'Export JSON'}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            leftIcon={<RefreshCw size={13} />}
            onClick={loadAuditLogs}
          >
            Refresh
          </Button>
        </div>
      </div>

      {/* KPI Ribbon */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '10px' }}>
        <div style={{ padding: '12px 14px', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Total Audit Records
          </div>
          <div style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px' }}>
            {formatNumber(stats.total)}
          </div>
        </div>

        <div style={{ padding: '12px 14px', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Successful Operations
          </div>
          <div style={{ fontSize: '18px', fontWeight: 600, color: '#10b981', marginTop: '2px' }}>
            {formatNumber(stats.successful)}
          </div>
        </div>

        <div style={{ padding: '12px 14px', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Failed / Blocked
          </div>
          <div style={{ fontSize: '18px', fontWeight: 600, color: stats.failed > 0 ? '#ef4444' : 'var(--text-muted)', marginTop: '2px' }}>
            {formatNumber(stats.failed)}
          </div>
        </div>

        <div style={{ padding: '12px 14px', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Vault Quarantines
          </div>
          <div style={{ fontSize: '18px', fontWeight: 600, color: 'var(--accent-blue)', marginTop: '2px' }}>
            {formatNumber(stats.quarantines)}
          </div>
        </div>

        <div style={{ padding: '12px 14px', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Restored Files
          </div>
          <div style={{ fontSize: '18px', fontWeight: 600, color: '#38bdf8', marginTop: '2px' }}>
            {formatNumber(stats.restores)}
          </div>
        </div>
      </div>

      {/* SHA-256 Verified Audit Journal Banner */}
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: '12px',
          padding: '12px 16px',
          backgroundColor: 'rgba(16, 185, 129, 0.08)',
          border: '1px solid rgba(16, 185, 129, 0.3)',
          borderRadius: '6px',
        }}
      >
        <ShieldCheck size={20} color="#10b981" style={{ flexShrink: 0, marginTop: '2px' }} />
        <div>
          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
            SHA-256 Verified Audit Journal
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '3px', lineHeight: 1.5 }}>
            Every scan discovery, quarantine relocation, restoration, and purge action is recorded in the
            Core&rsquo;s local SQLite audit database (<code style={{ backgroundColor: 'var(--bg-tertiary)', padding: '1px 4px', borderRadius: '3px' }}>audit.db</code>).
            All file movements record pre-execution SHA-256 content hashes and operation receipts for verifiable integrity tracking and forensic accountability.
          </p>
        </div>
      </div>

      {/* Search and Filters Toolbar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
          padding: '12px 14px',
          backgroundColor: 'var(--bg-secondary)',
          borderRadius: '6px',
          border: '1px solid var(--border-color)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: '240px' }}>
          <Search size={15} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="Search audit records by target path, operation, or details..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              backgroundColor: 'var(--bg-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: '4px',
              padding: '6px 10px',
              fontSize: '13px',
              color: 'var(--text-primary)',
              width: '100%',
              outline: 'none',
            }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {/* Operation Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Operation:</span>
            <select
              value={operationFilter}
              onChange={(e) => setOperationFilter(e.target.value)}
              style={{
                backgroundColor: 'var(--bg-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '4px',
                padding: '4px 8px',
                fontSize: '12px',
                color: 'var(--text-primary)',
                cursor: 'pointer',
              }}
            >
              <option value="all">All Operations</option>
              <option value="quarantine">Quarantine</option>
              <option value="restore">Restore</option>
              <option value="purge">Purge</option>
              <option value="scan">Scan</option>
            </select>
          </div>

          {/* Status Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as 'all' | 'success' | 'failed')}
              style={{
                backgroundColor: 'var(--bg-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '4px',
                padding: '4px 8px',
                fontSize: '12px',
                color: 'var(--text-primary)',
                cursor: 'pointer',
              }}
            >
              <option value="all">All Outcomes</option>
              <option value="success">Success Only</option>
              <option value="failed">Failed / Blocked Only</option>
            </select>
          </div>

          {/* Limit selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Limit:</span>
            <select
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
              style={{
                backgroundColor: 'var(--bg-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '4px',
                padding: '4px 8px',
                fontSize: '12px',
                color: 'var(--text-primary)',
                cursor: 'pointer',
              }}
            >
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={250}>250</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main Ledger Table */}
      {isLoading && logs.length === 0 ? (
        <LoadingState label="Loading audit history ledger..." />
      ) : error && logs.length === 0 ? (
        <ErrorState error={error} onRetry={loadAuditLogs} />
      ) : filteredLogs.length > 0 ? (
        <Card
          title={`Audit Trail (${formatNumber(filteredLogs.length)} ${filteredLogs.length === 1 ? 'record' : 'records'})`}
          subtitle="Chronological read-only event stream from core database"
        >
          <Table
            columns={columns}
            data={filteredLogs}
            keyExtractor={(entry) => String(entry.id)}
            onRowClick={(entry) => setSelectedEntry(entry)}
          />
        </Card>
      ) : (
        <EmptyState
          title="No Matching Audit Records"
          description={
            searchQuery || operationFilter !== 'all' || statusFilter !== 'all'
              ? 'No audit entries matched the current search query or filter criteria.'
              : 'No audit records have been generated yet in this session.'
          }
          action={
            searchQuery || operationFilter !== 'all' || statusFilter !== 'all' ? (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  setSearchQuery('');
                  setOperationFilter('all');
                  setStatusFilter('all');
                }}
              >
                Clear Filters
              </Button>
            ) : undefined
          }
        />
      )}

      {/* Detail Record Modal */}
      {selectedEntry && (
        <Modal
          isOpen={!!selectedEntry}
          onClose={() => setSelectedEntry(null)}
          title={`Audit Record #${selectedEntry.id}: ${selectedEntry.operation.toUpperCase()}`}
          description={`Logged at ${formatDate(selectedEntry.timestamp)}`}
          footer={
            <Button variant="secondary" size="sm" onClick={() => setSelectedEntry(null)}>
              Close
            </Button>
          }
          width="580px"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <div style={{ padding: '10px', backgroundColor: 'var(--bg-primary)', borderRadius: '4px', border: '1px solid var(--border-color)' }}>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Execution Status
                </div>
                <div style={{ marginTop: '4px' }}>
                  {selectedEntry.success ? (
                    <Badge variant="safe">Success</Badge>
                  ) : (
                    <Badge variant="dangerous">Failed / Blocked</Badge>
                  )}
                </div>
              </div>

              <div style={{ padding: '10px', backgroundColor: 'var(--bg-primary)', borderRadius: '4px', border: '1px solid var(--border-color)' }}>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Operation Type
                </div>
                <div style={{ marginTop: '4px' }}>
                  {getOperationBadge(selectedEntry.operation)}
                </div>
              </div>
            </div>

            <div>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                Target Filesystem Path
              </div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 10px',
                  backgroundColor: 'var(--bg-primary)',
                  borderRadius: '4px',
                  border: '1px solid var(--border-color)',
                  fontFamily: 'monospace',
                  fontSize: '12px',
                  color: 'var(--text-primary)',
                  wordBreak: 'break-all',
                }}
              >
                <span>{selectedEntry.target_path}</span>
                <Button
                  variant="ghost"
                  size="sm"
                  leftIcon={isCopied ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                  onClick={() => handleCopyPath(selectedEntry.target_path)}
                  title="Copy path"
                >
                  {isCopied ? 'Copied' : 'Copy'}
                </Button>
              </div>
            </div>

            <div>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                Operation Details &amp; Execution Output
              </div>
              <div
                style={{
                  padding: '10px',
                  backgroundColor: 'var(--bg-primary)',
                  borderRadius: '4px',
                  border: '1px solid var(--border-color)',
                  fontSize: '12px',
                  color: 'var(--text-primary)',
                  lineHeight: 1.5,
                }}
              >
                {selectedEntry.details || 'No additional technical details recorded for this entry.'}
              </div>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 12px',
                backgroundColor: 'rgba(59, 130, 246, 0.08)',
                border: '1px solid rgba(59, 130, 246, 0.2)',
                borderRadius: '4px',
                fontSize: '11px',
                color: 'var(--text-secondary)',
              }}
            >
              <Database size={14} color="var(--accent-blue)" />
              <span>
                Immutable record permanently stored in <code style={{ fontSize: '11px' }}>audit.db</code>. Record ID #{selectedEntry.id}.
              </span>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
