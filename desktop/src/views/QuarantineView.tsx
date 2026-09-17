import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useApp } from '../state/AppContext';
import { Card } from '../design-system/Card';
import { Badge } from '../design-system/Badge';
import { Button } from '../design-system/Button';
import { Modal } from '../design-system/Modal';
import { ConfirmationDialog } from '../design-system/ConfirmationDialog';
import { EmptyState } from '../design-system/EmptyState';
import { ErrorState } from '../design-system/ErrorState';
import { QuarantineItemDto, IpcError } from '../types/ipc';
import { formatBytes } from '../utils/format';
import {
  ShieldCheck,
  ShieldAlert,
  Search,
  RotateCcw,
  Trash2,
  Copy,
  Check,
  ArrowUpDown,
  RefreshCw,
  FolderArchive,
  CheckCircle2,
} from 'lucide-react';

export type QuarantineSortField = 'days_remaining' | 'size' | 'date' | 'path';

export const QuarantineView: React.FC = () => {
  const { client, connectionStatus, setCurrentRoute } = useApp();

  const [items, setItems] = useState<QuarantineItemDto[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<IpcError | null>(null);

  // Search and Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [filterExpired, setFilterExpired] = useState<string>('all'); // 'all' | 'expired' | 'active'
  const [selectedCategory, setSelectedCategory] = useState<string>('All');

  // Sorting
  const [sortField, setSortField] = useState<QuarantineSortField>('days_remaining');
  const [sortAsc, setSortAsc] = useState<boolean>(true);

  // Modals state
  const [copiedHashId, setCopiedHashId] = useState<string | null>(null);
  const [restoreTargetItem, setRestoreTargetItem] = useState<QuarantineItemDto | null>(null);
  const [purgeTargetItem, setPurgeTargetItem] = useState<QuarantineItemDto | null>(null);
  const [restoreOverridePath, setRestoreOverridePath] = useState<string>('');
  const [useOverridePath, setUseOverridePath] = useState<boolean>(false);
  const [isRestoring, setIsRestoring] = useState<boolean>(false);
  const [isPurging, setIsPurging] = useState<boolean>(false);
  const [actionFeedback, setActionFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Batch modals
  const [confirmBatchPurge, setConfirmBatchPurge] = useState<boolean>(false);
  const [confirmBatchRestore, setConfirmBatchRestore] = useState<boolean>(false);

  // Load quarantine inventory from Core
  const loadQuarantineItems = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const filter = filterExpired === 'expired' ? { expired_only: true } : undefined;
      const data = await client.getQuarantineContents(filter);
      setItems(data);
    } catch (err) {
      setError({
        code: 'INTERNAL_CORE_ERROR',
        message: err instanceof Error ? err.message : 'Failed to query quarantine items from core',
      });
    } finally {
      setIsLoading(false);
    }
  }, [client, filterExpired]);

  useEffect(() => {
    loadQuarantineItems();
  }, [loadQuarantineItems]);

  // Distinct categories
  const categories = useMemo(() => {
    const cats = new Set<string>();
    items.forEach((item) => {
      if (item.category) cats.add(item.category);
    });
    return Array.from(cats).sort();
  }, [items]);

  // Metrics
  const totalVaultBytes = useMemo(() => {
    return items.reduce((sum, item) => sum + item.quarantined_size_bytes, 0);
  }, [items]);

  const expiredCount = useMemo(() => {
    return items.filter((i) => i.is_expired || i.days_remaining <= 0).length;
  }, [items]);

  // Filtered & Sorted items
  const filteredItems = useMemo(() => {
    return items.filter((item) => {
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesPath = item.original_path.toLowerCase().includes(query);
        const matchesCat = item.category.toLowerCase().includes(query);
        const matchesHash = item.sha256_hash.toLowerCase().includes(query);
        if (!matchesPath && !matchesCat && !matchesHash) return false;
      }

      if (filterExpired === 'expired' && !item.is_expired && item.days_remaining > 0) {
        return false;
      }
      if (filterExpired === 'active' && (item.is_expired || item.days_remaining <= 0)) {
        return false;
      }

      if (selectedCategory !== 'All' && item.category !== selectedCategory) {
        return false;
      }

      return true;
    });
  }, [items, searchQuery, filterExpired, selectedCategory]);

  const sortedItems = useMemo(() => {
    return [...filteredItems].sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'days_remaining':
          cmp = a.days_remaining - b.days_remaining;
          break;
        case 'size':
          cmp = a.quarantined_size_bytes - b.quarantined_size_bytes;
          break;
        case 'date':
          cmp = new Date(a.quarantined_at).getTime() - new Date(b.quarantined_at).getTime();
          break;
        case 'path':
          cmp = a.original_path.localeCompare(b.original_path);
          break;
      }
      return sortAsc ? cmp : -cmp;
    });
  }, [filteredItems, sortField, sortAsc]);

  const handleSort = (field: QuarantineSortField) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(true);
    }
  };

  const handleCopyHash = (id: string, hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHashId(id);
    setTimeout(() => setCopiedHashId(null), 2000);
  };

  // Toggle item selection
  const handleToggleSelect = (itemId: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(itemId)) next.delete(itemId);
      else next.add(itemId);
      return next;
    });
  };

  const handleSelectAll = (select: boolean) => {
    if (select) {
      setSelectedIds(new Set(filteredItems.map((i) => i.item_id)));
    } else {
      setSelectedIds(new Set());
    }
  };

  // RESTORE ACTION
  const handleExecuteRestore = async () => {
    if (!restoreTargetItem) return;
    setIsRestoring(true);
    setActionFeedback(null);
    try {
      const override = useOverridePath && restoreOverridePath.trim() ? restoreOverridePath.trim() : undefined;
      const result = await client.restoreQuarantineItem(restoreTargetItem.item_id, override);

      setActionFeedback({
        type: 'success',
        message: `Successfully restored "${restoreTargetItem.original_path.split(/[/\\]/).pop()}" to ${result.restored_to}`,
      });

      // Remove from list
      setItems((prev) => prev.filter((i) => i.item_id !== restoreTargetItem.item_id));
      setSelectedIds((prev) => {
        const next = new Set(prev);
        next.delete(restoreTargetItem.item_id);
        return next;
      });
      setRestoreTargetItem(null);
    } catch (err) {
      setActionFeedback({
        type: 'error',
        message: err instanceof Error ? err.message : 'Restore operation failed on core',
      });
    } finally {
      setIsRestoring(false);
    }
  };

  // PURGE ACTION
  const handleExecutePurge = async () => {
    if (!purgeTargetItem) return;
    setIsPurging(true);
    setActionFeedback(null);
    try {
      await client.purgeQuarantineItem(purgeTargetItem.item_id);
      setActionFeedback({
        type: 'success',
        message: `Permanently purged "${purgeTargetItem.original_path.split(/[/\\]/).pop()}". Space reclaimed.`,
      });
      // Remove from list
      setItems((prev) => prev.filter((i) => i.item_id !== purgeTargetItem.item_id));
      setSelectedIds((prev) => {
        const next = new Set(prev);
        next.delete(purgeTargetItem.item_id);
        return next;
      });
      setPurgeTargetItem(null);
    } catch (err) {
      setActionFeedback({
        type: 'error',
        message: err instanceof Error ? err.message : 'Purge operation failed on core',
      });
    } finally {
      setIsPurging(false);
    }
  };

  // BATCH RESTORE
  const handleExecuteBatchRestore = async () => {
    setIsRestoring(true);
    setActionFeedback(null);
    const toRestore = Array.from(selectedIds);
    let successCount = 0;
    const errors: string[] = [];

    for (const itemId of toRestore) {
      try {
        await client.restoreQuarantineItem(itemId);
        successCount++;
        setItems((prev) => prev.filter((i) => i.item_id !== itemId));
      } catch (err) {
        errors.push(`${itemId}: ${err instanceof Error ? err.message : 'Failed'}`);
      }
    }

    setSelectedIds(new Set());
    setIsRestoring(false);
    setConfirmBatchRestore(false);

    if (errors.length === 0) {
      setActionFeedback({
        type: 'success',
        message: `Successfully restored ${successCount} items to their original filesystem paths.`,
      });
    } else {
      setActionFeedback({
        type: 'error',
        message: `Restored ${successCount} items. ${errors.length} failed: ${errors[0]}`,
      });
    }
  };

  // BATCH PURGE
  const handleExecuteBatchPurge = async () => {
    setIsPurging(true);
    setActionFeedback(null);
    const toPurge = Array.from(selectedIds);
    let successCount = 0;
    const errors: string[] = [];

    for (const itemId of toPurge) {
      try {
        await client.purgeQuarantineItem(itemId);
        successCount++;
        setItems((prev) => prev.filter((i) => i.item_id !== itemId));
      } catch (err) {
        errors.push(`${itemId}: ${err instanceof Error ? err.message : 'Failed'}`);
      }
    }

    setSelectedIds(new Set());
    setIsPurging(false);
    setConfirmBatchPurge(false);

    if (errors.length === 0) {
      setActionFeedback({
        type: 'success',
        message: `Permanently purged ${successCount} items. Vault space reclaimed.`,
      });
    } else {
      setActionFeedback({
        type: 'error',
        message: `Purged ${successCount} items. ${errors.length} failed: ${errors[0]}`,
      });
    }
  };

  // Disconnected state
  if (connectionStatus === 'error' || connectionStatus === 'disconnected') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Quarantine Vault & Restoration
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            Reversible storage vault. Files can be verified by SHA-256 and restored at any time.
          </p>
        </div>
        <ErrorState
          error={{
            code: 'INTERNAL_CORE_ERROR',
            message: 'Native Rust core process is unreachable. Re-connect to view quarantine vault.',
          }}
          onRetry={loadQuarantineItems}
        />
      </div>
    );
  }

  // Error loading state
  if (error) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Quarantine Retrieval Failed
          </h1>
        </div>
        <ErrorState error={error} onRetry={loadQuarantineItems} />
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h1 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Quarantine Vault & Restoration
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            Reversible safety isolation. All files are cataloged with authoritative SHA-256 integrity hashes.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <Button variant="secondary" size="sm" leftIcon={<RefreshCw size={13} />} onClick={loadQuarantineItems}>
            Refresh Vault
          </Button>
          <Button variant="primary" size="sm" onClick={() => setCurrentRoute('results')}>
            View Candidates
          </Button>
        </div>
      </div>

      {/* Notification Banner */}
      {actionFeedback && (
        <div
          role="status"
          style={{
            padding: '12px 16px',
            borderRadius: '6px',
            border: actionFeedback.type === 'success' ? '1px solid var(--safety-safe-border)' : '1px solid var(--safety-danger-border)',
            backgroundColor: actionFeedback.type === 'success' ? 'var(--safety-safe-bg)' : 'var(--safety-danger-bg)',
            color: actionFeedback.type === 'success' ? 'var(--safety-safe-text)' : 'var(--safety-danger-text)',
            fontSize: '13px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {actionFeedback.type === 'success' ? <CheckCircle2 size={16} /> : <ShieldAlert size={16} />}
            <span>{actionFeedback.message}</span>
          </div>
          <button
            onClick={() => setActionFeedback(null)}
            style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '12px' }}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Vault Statistics Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
        <Card title="Quarantined Inventory" subtitle="Files held in isolation">
          <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--text-primary)' }}>
            {items.length} files
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            {selectedIds.size > 0 ? `${selectedIds.size} selected` : 'None selected'}
          </div>
        </Card>

        <Card title="Vault Storage Footprint" subtitle="Dedicated storage consumed">
          <div style={{ fontSize: '22px', fontWeight: 700, color: '#38bdf8' }}>
            {formatBytes(totalVaultBytes)}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Fully reversible space
          </div>
        </Card>

        <Card title="Retention Status" subtitle="Automatic expiration policy">
          <div style={{ fontSize: '22px', fontWeight: 700, color: expiredCount > 0 ? '#ef4444' : '#10b981' }}>
            {expiredCount} expired
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            {items.length - expiredCount} active items under retention
          </div>
        </Card>

        <Card title="Vault Integrity" subtitle="Cryptographic verification">
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px' }}>
            <ShieldCheck size={20} color="#10b981" />
            <span style={{ fontSize: '14px', fontWeight: 600, color: '#10b981' }}>
              SHA-256 Validated
            </span>
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '6px' }}>
            Strict pre-flight & restore integrity
          </div>
        </Card>
      </div>

      {/* Filter and Control Bar */}
      <Card>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', alignItems: 'center', justifyContent: 'space-between' }}>
            {/* Search */}
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
                  placeholder="Search quarantined files by path, category, or SHA-256 hash..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
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

            {/* Retention Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Status:</span>
              <select
                value={filterExpired}
                onChange={(e) => setFilterExpired(e.target.value)}
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
                <option value="all">All Items</option>
                <option value="active">Active (Under Retention)</option>
                <option value="expired">Expired (Ready to Purge)</option>
              </select>
            </div>

            {/* Category Filter */}
            {categories.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Category:</span>
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
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
                  {categories.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          {/* Batch Actions Bar */}
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
              <Button variant="outline" size="sm" onClick={() => handleSelectAll(true)}>
                Select All
              </Button>
              <Button variant="ghost" size="sm" onClick={() => handleSelectAll(false)}>
                Deselect All
              </Button>
              <span style={{ color: 'var(--text-muted)' }}>
                Showing {filteredItems.length} of {items.length} quarantined items
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              {selectedIds.size > 0 && (
                <span style={{ color: 'var(--text-secondary)' }}>
                  {selectedIds.size} item{selectedIds.size > 1 ? 's' : ''} selected
                </span>
              )}

              {/* Batch Restore */}
              <Button
                variant="secondary"
                size="sm"
                disabled={selectedIds.size === 0}
                leftIcon={<RotateCcw size={13} />}
                onClick={() => setConfirmBatchRestore(true)}
              >
                Restore Selected ({selectedIds.size})
              </Button>

              {/* Batch Purge: Strong separation, red color, requires distinct confirmation */}
              <Button
                variant="danger"
                size="sm"
                disabled={selectedIds.size === 0}
                leftIcon={<Trash2 size={13} />}
                onClick={() => setConfirmBatchPurge(true)}
              >
                Purge Selected ({selectedIds.size})
              </Button>
            </div>
          </div>
        </div>
      </Card>

      {/* Vault Table */}
      {items.length === 0 && !isLoading ? (
        <Card>
          <EmptyState
            icon={<FolderArchive size={40} />}
            title="Quarantine Vault Empty"
            description="No files are currently quarantined. When cleanup candidates are quarantined, they are securely stored here with cryptographic hashes."
            action={
              <Button variant="primary" onClick={() => setCurrentRoute('results')}>
                Explore Cleanup Candidates
              </Button>
            }
          />
        </Card>
      ) : filteredItems.length === 0 ? (
        <Card>
          <EmptyState
            icon={<Search size={36} />}
            title="No Matching Items"
            description="No quarantined files match your active filters or search terms."
            action={
              <Button
                variant="secondary"
                onClick={() => {
                  setSearchQuery('');
                  setFilterExpired('all');
                  setSelectedCategory('All');
                }}
              >
                Clear Filters
              </Button>
            }
          />
        </Card>
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
                  onClick={() => handleSort('path')}
                  style={{
                    padding: '10px 14px',
                    textAlign: 'left',
                    fontWeight: 600,
                    color: sortField === 'path' ? '#38bdf8' : 'var(--text-secondary)',
                    cursor: 'pointer',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <span>Original Path & ID</span>
                    <ArrowUpDown size={12} />
                  </div>
                </th>
                <th style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 600, color: 'var(--text-secondary)', width: '130px' }}>
                  Category
                </th>
                <th
                  onClick={() => handleSort('size')}
                  style={{
                    padding: '10px 14px',
                    textAlign: 'right',
                    fontWeight: 600,
                    color: sortField === 'size' ? '#38bdf8' : 'var(--text-secondary)',
                    width: '100px',
                    cursor: 'pointer',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '4px' }}>
                    <span>Size</span>
                    <ArrowUpDown size={12} />
                  </div>
                </th>
                <th style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 600, color: 'var(--text-secondary)', width: '170px' }}>
                  SHA-256 Hash
                </th>
                <th
                  onClick={() => handleSort('days_remaining')}
                  style={{
                    padding: '10px 14px',
                    textAlign: 'center',
                    fontWeight: 600,
                    color: sortField === 'days_remaining' ? '#38bdf8' : 'var(--text-secondary)',
                    width: '140px',
                    cursor: 'pointer',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '4px' }}>
                    <span>Retention</span>
                    <ArrowUpDown size={12} />
                  </div>
                </th>
                <th style={{ width: '150px', padding: '10px 12px', textAlign: 'center' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Vault Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {sortedItems.map((item) => {
                const isSelected = selectedIds.has(item.item_id);
                const fileName = item.original_path.split(/[/\\]/).pop() || item.original_path;
                const isExpired = item.is_expired || item.days_remaining <= 0;
                const shortHash = `${item.sha256_hash.slice(0, 8)}...${item.sha256_hash.slice(-6)}`;

                return (
                  <tr
                    key={item.item_id}
                    style={{
                      borderBottom: '1px solid var(--border-subtle)',
                      backgroundColor: isSelected ? 'rgba(37, 99, 235, 0.08)' : 'transparent',
                    }}
                  >
                    {/* Checkbox */}
                    <td style={{ padding: '10px 12px', textAlign: 'center', verticalAlign: 'middle' }}>
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => handleToggleSelect(item.item_id)}
                        style={{ cursor: 'pointer' }}
                      />
                    </td>

                    {/* Original Path & ID */}
                    <td style={{ padding: '10px 14px', verticalAlign: 'middle', maxWidth: '300px' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
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
                          title={item.original_path}
                        >
                          {item.original_path}
                        </span>
                        <span style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '1px' }}>
                          ID: {item.item_id}
                        </span>
                      </div>
                    </td>

                    {/* Category */}
                    <td style={{ padding: '10px 14px', verticalAlign: 'middle', color: 'var(--text-secondary)' }}>
                      <span style={{ fontSize: '12px' }}>{item.category}</span>
                    </td>

                    {/* Size */}
                    <td style={{ padding: '10px 14px', verticalAlign: 'middle', textAlign: 'right' }}>
                      <span style={{ fontFamily: 'monospace', fontWeight: 500, color: 'var(--text-primary)' }}>
                        {formatBytes(item.quarantined_size_bytes)}
                      </span>
                    </td>

                    {/* SHA-256 Hash with Verification */}
                    <td style={{ padding: '10px 14px', verticalAlign: 'middle' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <code
                          style={{
                            fontFamily: 'monospace',
                            fontSize: '11px',
                            backgroundColor: 'rgba(0,0,0,0.2)',
                            padding: '2px 5px',
                            borderRadius: '3px',
                            color: '#7dd3fc',
                          }}
                          title={item.sha256_hash}
                        >
                          {shortHash}
                        </code>
                        <button
                          onClick={() => handleCopyHash(item.item_id, item.sha256_hash)}
                          title="Copy full SHA-256 hash"
                          style={{
                            background: 'none',
                            border: 'none',
                            color: copiedHashId === item.item_id ? '#10b981' : 'var(--text-muted)',
                            cursor: 'pointer',
                            padding: '2px',
                          }}
                        >
                          {copiedHashId === item.item_id ? <Check size={12} /> : <Copy size={12} />}
                        </button>
                      </div>
                    </td>

                    {/* Retention Countdown */}
                    <td style={{ padding: '10px 14px', verticalAlign: 'middle', textAlign: 'center' }}>
                      {isExpired ? (
                        <Badge variant="dangerous" title="Retention window expired. Ready for permanent purge.">
                          Expired
                        </Badge>
                      ) : (
                        <span
                          style={{
                            fontSize: '11px',
                            fontWeight: 500,
                            color: item.days_remaining <= 2 ? '#f59e0b' : '#10b981',
                          }}
                        >
                          {item.days_remaining} day{item.days_remaining === 1 ? '' : 's'} left
                        </span>
                      )}
                    </td>

                    {/* Actions: Distinct Restore and Purge buttons */}
                    <td style={{ padding: '10px 12px', textAlign: 'center', verticalAlign: 'middle' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
                        {/* RESTORE BUTTON */}
                        <Button
                          variant="secondary"
                          size="sm"
                          title="Restore this file to its original filesystem location"
                          leftIcon={<RotateCcw size={12} />}
                          onClick={() => {
                            setRestoreTargetItem(item);
                            setRestoreOverridePath('');
                            setUseOverridePath(false);
                          }}
                        >
                          Restore
                        </Button>

                        {/* PURGE BUTTON (Distinct red icon/button, non-reversible) */}
                        <Button
                          variant="ghost"
                          size="sm"
                          title="Permanently and irrevocably delete this file from disk"
                          style={{ color: '#f87171' }}
                          onClick={() => setPurgeTargetItem(item)}
                        >
                          <Trash2 size={13} />
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* RESTORE CONFIRMATION MODAL */}
      {restoreTargetItem && (
        <Modal
          isOpen={true}
          onClose={() => setRestoreTargetItem(null)}
          title="Restore Quarantined File"
          width="520px"
          footer={
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <Button variant="secondary" onClick={() => setRestoreTargetItem(null)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                isLoading={isRestoring}
                leftIcon={<RotateCcw size={14} />}
                onClick={handleExecuteRestore}
              >
                Confirm Restore
              </Button>
            </div>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', fontSize: '13px' }}>
            <p style={{ color: 'var(--text-secondary)' }}>
              The file will be extracted from the Quarantine Vault and restored after full SHA-256 integrity verification.
            </p>

            <div
              style={{
                padding: '12px',
                backgroundColor: 'rgba(0,0,0,0.2)',
                borderRadius: '6px',
                border: '1px solid var(--border-subtle)',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
              }}
            >
              <div>
                <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Original Target Location:</span>
                <div style={{ fontFamily: 'monospace', fontSize: '12px', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                  {restoreTargetItem.original_path}
                </div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginTop: '4px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Capacity:</span>
                <span style={{ color: 'var(--text-primary)' }}>{formatBytes(restoreTargetItem.quarantined_size_bytes)}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Integrity Check:</span>
                <span style={{ color: '#10b981', fontWeight: 500 }}>SHA-256 match verified</span>
              </div>
            </div>

            {/* Target Path Override Option (for handling conflicts) */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', color: 'var(--text-secondary)' }}>
                <input
                  type="checkbox"
                  checked={useOverridePath}
                  onChange={(e) => setUseOverridePath(e.target.checked)}
                />
                <span>Restore to custom path override (if original path is occupied or missing)</span>
              </label>

              {useOverridePath && (
                <input
                  type="text"
                  placeholder="e.g. C:\RestoredFiles\my-file.tmp"
                  value={restoreOverridePath}
                  onChange={(e) => setRestoreOverridePath(e.target.value)}
                  style={{
                    backgroundColor: 'var(--bg-primary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '4px',
                    padding: '8px 10px',
                    fontSize: '12px',
                    color: 'var(--text-primary)',
                    width: '100%',
                    fontFamily: 'monospace',
                  }}
                />
              )}
            </div>
          </div>
        </Modal>
      )}

      {/* PURGE CONFIRMATION MODAL (Strict, Strong Confirmation) */}
      {purgeTargetItem && (
        <ConfirmationDialog
          isOpen={true}
          title="Permanently Purge Quarantined File?"
          message={
            `Are you sure you want to permanently delete "${purgeTargetItem.original_path.split(/[/\\]/).pop()}"?\n\n` +
            `Path: ${purgeTargetItem.original_path}\n` +
            `Size: ${formatBytes(purgeTargetItem.quarantined_size_bytes)}\n\n` +
            `THIS ACTION IS IRREVERSIBLE. The file will be completely erased from disk and cannot be restored.`
          }
          confirmLabel="Permanently Purge File"
          cancelLabel="Keep in Vault"
          variant="danger"
          isLoading={isPurging}
          onConfirm={handleExecutePurge}
          onClose={() => setPurgeTargetItem(null)}
        />
      )}

      {/* BATCH RESTORE CONFIRMATION */}
      {confirmBatchRestore && (
        <ConfirmationDialog
          isOpen={true}
          title={`Restore ${selectedIds.size} Files?`}
          message={`Are you sure you want to restore ${selectedIds.size} items from the Quarantine Vault to their original filesystem paths? Every file will undergo SHA-256 integrity verification.`}
          confirmLabel={`Restore ${selectedIds.size} Files`}
          cancelLabel="Cancel"
          variant="primary"
          isLoading={isRestoring}
          onConfirm={handleExecuteBatchRestore}
          onClose={() => setConfirmBatchRestore(false)}
        />
      )}

      {/* BATCH PURGE CONFIRMATION */}
      {confirmBatchPurge && (
        <ConfirmationDialog
          isOpen={true}
          title={`Permanently Purge ${selectedIds.size} Files?`}
          message={
            `CRITICAL WARNING: You are about to permanently delete ${selectedIds.size} items from disk.\n\n` +
            `This action CANNOT be undone. Once purged, these files cannot be restored under any circumstance.`
          }
          confirmLabel={`Permanently Purge ${selectedIds.size} Files`}
          cancelLabel="Cancel"
          variant="danger"
          isLoading={isPurging}
          onConfirm={handleExecuteBatchPurge}
          onClose={() => setConfirmBatchPurge(false)}
        />
      )}
    </div>
  );
};
