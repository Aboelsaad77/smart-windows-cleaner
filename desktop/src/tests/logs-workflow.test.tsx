import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { LogsView } from '../views/LogsView';
import { AppProvider } from '../state/AppContext';
import { MockTransport } from '../ipc/transport';
import { IpcClient } from '../ipc/client';
import { IpcRequest, IpcResponse, AuditEntryDto } from '../types/ipc';

describe('M3.8: Audit & Security Logs Workflow', () => {
  let transport: MockTransport;
  let client: IpcClient;

  const mockAudits: AuditEntryDto[] = [
    {
      id: 1,
      timestamp: '2026-09-16T18:00:00.000Z',
      operation: 'quarantine',
      target_path: 'C:\\Users\\User\\AppData\\Local\\Temp\\chrome_cache.tmp',
      success: true,
      details: 'Moved to vault. SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    },
    {
      id: 2,
      timestamp: '2026-09-16T18:05:00.000Z',
      operation: 'restore',
      target_path: 'C:\\Users\\User\\AppData\\Local\\Temp\\chrome_cache.tmp',
      success: true,
      details: 'Restored from vault to original location. Hash verified.',
    },
    {
      id: 3,
      timestamp: '2026-09-16T18:10:00.000Z',
      operation: 'purge',
      target_path: 'C:\\Users\\User\\AppData\\Local\\Temp\\dead_crash.dmp',
      success: true,
      details: 'Permanently removed from quarantine storage.',
    },
    {
      id: 4,
      timestamp: '2026-09-16T18:15:00.000Z',
      operation: 'quarantine',
      target_path: 'C:\\Windows\\System32\\critical_driver.sys',
      success: false,
      details: 'Safety Engine blocked modification: Protected System Resource (SR-001)',
    },
  ];

  beforeEach(() => {
    transport = new MockTransport();
    client = new IpcClient({ transport });

    // Mock clipboard
    Object.assign(navigator, {
      clipboard: {
        writeText: vi.fn().mockImplementation(() => Promise.resolve()),
      },
    });

    transport.registerHandler('get_audit_history', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: mockAudits,
    }));
  });

  const renderLogs = () => {
    return render(
      <AppProvider client={client} initialRoute="logs">
        <LogsView />
      </AppProvider>
    );
  };

  it('renders header, audit integrity banner, and KPI summary', async () => {
    renderLogs();

    await waitFor(() => {
      expect(screen.getByText('Audit & Security Logs')).toBeInTheDocument();
    });

    // Audit integrity banner
    expect(screen.getByText('SHA-256 Verified Audit Journal')).toBeInTheDocument();
    expect(screen.getByText(/local SQLite audit database/i)).toBeInTheDocument();

    // KPIs: 4 total, 3 successful, 1 failed, 2 quarantines, 1 restore
    expect(screen.getByText('Total Audit Records')).toBeInTheDocument();
    expect(screen.getByText('Successful Operations')).toBeInTheDocument();
    expect(screen.getByText('Failed / Blocked')).toBeInTheDocument();
    expect(screen.getByText('4')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getAllByText('1').length).toBe(2);
  });

  it('renders table entries with formatted operations, paths, and status', async () => {
    renderLogs();

    await waitFor(() => {
      expect(screen.getByText('Audit Trail (4 records)')).toBeInTheDocument();
    });

    // Targets
    expect(screen.getAllByText(/chrome_cache\.tmp/i).length).toBe(2);
    expect(screen.getByText(/dead_crash\.dmp/i)).toBeInTheDocument();
    expect(screen.getByText(/critical_driver\.sys/i)).toBeInTheDocument();

    // Success and Failed counts
    expect(screen.getAllByText('Success').length).toBe(3);
    expect(screen.getByText('Failed')).toBeInTheDocument();
  });

  it('filters audit records by search query', async () => {
    renderLogs();

    await waitFor(() => {
      expect(screen.getByText('Audit Trail (4 records)')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText(/Search audit records/i);
    fireEvent.change(searchInput, { target: { value: 'dead_crash' } });

    // Should only match item 3
    expect(screen.getByText(/dead_crash\.dmp/i)).toBeInTheDocument();
    expect(screen.queryByText(/critical_driver\.sys/i)).not.toBeInTheDocument();
  });

  it('filters audit records by status', async () => {
    renderLogs();

    await waitFor(() => {
      expect(screen.getByText('Audit Trail (4 records)')).toBeInTheDocument();
    });

    // Change status select to failed only
    const statusSelect = screen.getByDisplayValue('All Outcomes');
    fireEvent.change(statusSelect, { target: { value: 'failed' } });

    // Only the failed driver quarantine should be shown
    expect(screen.getByText(/critical_driver\.sys/i)).toBeInTheDocument();
    expect(screen.queryByText(/dead_crash\.dmp/i)).not.toBeInTheDocument();
    expect(screen.getByText('Audit Trail (1 record)')).toBeInTheDocument();
  });

  it('opens detail inspection modal on view click and displays technical details', async () => {
    renderLogs();

    await waitFor(() => {
      expect(screen.getByText('Audit Trail (4 records)')).toBeInTheDocument();
    });

    // Click on row or view button
    const viewButton = screen.getAllByTitle('Inspect Audit Record')[0];
    fireEvent.click(viewButton);

    // Modal opens for record #1
    await waitFor(() => {
      expect(screen.getByText(/Audit Record #1: QUARANTINE/i)).toBeInTheDocument();
      expect(screen.getAllByText(/SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855/i).length).toBe(2);
      expect(screen.getByText(/Immutable record permanently stored in/i)).toBeInTheDocument();
    });

    // Close modal
    const closeBtn = screen.getByRole('button', { name: /^Close$/i });
    fireEvent.click(closeBtn);

    await waitFor(() => {
      expect(screen.queryByText(/Audit Record #1: QUARANTINE/i)).not.toBeInTheDocument();
    });
  });

  it('handles empty search results and clears filters', async () => {
    renderLogs();

    await waitFor(() => {
      expect(screen.getByText('Audit Trail (4 records)')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText(/Search audit records/i);
    fireEvent.change(searchInput, { target: { value: 'nonexistent_file_pattern_xyz' } });

    // Empty state
    expect(screen.getByText('No Matching Audit Records')).toBeInTheDocument();

    const clearButton = screen.getByRole('button', { name: /Clear Filters/i });
    fireEvent.click(clearButton);

    // Records restored
    await waitFor(() => {
      expect(screen.getByText('Audit Trail (4 records)')).toBeInTheDocument();
    });
  });

  it('copies audit log as JSON to clipboard on export', async () => {
    renderLogs();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Export JSON/i })).toBeInTheDocument();
    });

    const exportBtn = screen.getByRole('button', { name: /Export JSON/i });
    fireEvent.click(exportBtn);

    await waitFor(() => {
      expect(navigator.clipboard.writeText).toHaveBeenCalled();
      expect(screen.getByText('Copied JSON')).toBeInTheDocument();
    });
  });

  it('renders error state when audit query fails', async () => {
    transport.registerHandler('get_audit_history', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'error',
      error: {
        code: 'INTERNAL_ERROR',
        message: 'SQLite database locked or corrupted: audit.db',
      },
    }));

    renderLogs();

    await waitFor(() => {
      expect(screen.getByText(/Core Operation Error/i)).toBeInTheDocument();
      expect(screen.getByText(/SQLite database locked or corrupted/i)).toBeInTheDocument();
    });
  });
});
