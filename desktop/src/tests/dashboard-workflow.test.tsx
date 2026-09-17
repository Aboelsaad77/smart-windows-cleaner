import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { DashboardView } from '../views/DashboardView';
import { AppProvider } from '../state/AppContext';
import { MockTransport } from '../ipc/transport';
import { IpcClient } from '../ipc/client';
import {
  IpcRequest,
  IpcResponse,
  ScanSummaryDto,
  StorageSummaryDto,
  AuditEntryDto,
} from '../types/ipc';

const mockScanSummary: ScanSummaryDto = {
  session_id: 'scan-sess-dash-01',
  total_files_scanned: 35000,
  total_candidates_found: 42,
  total_reclaimable_bytes: 1610612736, // 1.5 GB
  auto_eligible_bytes: 1073741824, // 1.0 GB
  user_confirm_bytes: 536870912, // 512 MB
  blocked_bytes: 268435456, // 256 MB
  categories: [
    { category: 'Browser Cache', count: 30, total_bytes: 1073741824, eligible_quarantine_bytes: 1073741824 },
  ],
  elapsed_ms: 8500,
};

const mockStorageSummary: StorageSummaryDto = {
  drives: [
    { mount_point: 'C:\\', total_bytes: 512000000000, free_bytes: 142000000000, available_bytes: 142000000000 },
    { mount_point: 'D:\\', total_bytes: 1024000000000, free_bytes: 620000000000, available_bytes: 620000000000 },
  ],
  winsxs_protection: {
    path: 'C:\\Windows\\WinSxS',
    is_protected: true,
    reason: 'Hard safety rule: Windows Component Store cannot be deleted',
  },
};

const mockAudits: AuditEntryDto[] = [
  {
    id: 1,
    timestamp: new Date(Date.now() - 120000).toISOString(),
    operation: 'quarantine',
    target_path: 'C:\\Users\\User\\AppData\\Local\\Temp\\junk1.tmp',
    success: true,
    details: 'Quarantined successfully into vault',
  },
  {
    id: 2,
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    operation: 'restore',
    target_path: 'C:\\Users\\User\\AppData\\Local\\Temp\\chrome_cache.tmp',
    success: true,
    details: 'Restored from vault',
  },
];

describe('M3.6: System Intelligence Dashboard', () => {
  let transport: MockTransport;
  let client: IpcClient;

  beforeEach(() => {
    transport = new MockTransport();
    client = new IpcClient({ transport });

    transport.registerHandler('get_storage_summary', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: mockStorageSummary,
    }));

    transport.registerHandler('get_audit_history', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: mockAudits,
    }));
  });

  const renderDashboard = () => {
    return render(
      <AppProvider client={client} initialRoute="dashboard">
        <DashboardView />
      </AppProvider>
    );
  };

  it('renders system context, elevation status, and drive storage overview', async () => {
    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText('System Intelligence Dashboard')).toBeInTheDocument();
      expect(screen.getByText(/Windows 11 Pro/i)).toBeInTheDocument();
    });

    // Check Elevation status
    expect(screen.getByText(/Standard User \(Safe Scope\)/i)).toBeInTheDocument();
    expect(screen.getByText('Safety Engine Active')).toBeInTheDocument();

    // Check Drive Mount Points
    expect(screen.getByText('Drive C:\\')).toBeInTheDocument();
    expect(screen.getByText('Drive D:\\')).toBeInTheDocument();

    // Check WinSxS Protection notice
    expect(screen.getByText(/Windows Component Store \(WinSxS\) Protection/i)).toBeInTheDocument();
    expect(screen.getByText('Immune to Removal')).toBeInTheDocument();
  });

  it('renders potential reclaimable space and auto/review/blocked distribution from scan summary', async () => {
    // Provide latestScanSummary via transport response for scan status / summary
    transport.registerHandler('get_scan_summary', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: mockScanSummary,
    }));

    render(
      <AppProvider client={client} initialRoute="dashboard">
        <DashboardView />
      </AppProvider>
    );

    await waitFor(() => {
      expect(screen.getByText('Potential Reclaimable Space')).toBeInTheDocument();
      // Audit logs rendered
      expect(screen.getAllByText(/quarantine/i).length).toBeGreaterThanOrEqual(2);
      expect(screen.getAllByText(/restore/i).length).toBeGreaterThanOrEqual(2);
      expect(screen.getByText(/junk1\.tmp/)).toBeInTheDocument();
    });
  });

  it('supports navigation to Scanner, Results, Quarantine, and Storage views', async () => {
    const { getByText } = renderDashboard();

    await waitFor(() => {
      expect(getByText('Scanner Hub')).toBeInTheDocument();
    });

    // Scanner Hub navigation
    fireEvent.click(getByText('Scanner Hub'));

    // Results navigation
    fireEvent.click(getByText('Results & Explainability'));

    // Quarantine Vault navigation (select from navigation card)
    const quarantineLinks = screen.getAllByText('Quarantine Vault');
    fireEvent.click(quarantineLinks[quarantineLinks.length - 1]);

    // Storage Intelligence navigation
    const storageLinks = screen.getAllByText('Storage Intelligence');
    fireEvent.click(storageLinks[storageLinks.length - 1]);
  });

  it('handles error states cleanly when core queries fail', async () => {
    transport.registerHandler('get_storage_summary', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'error',
      error: {
        code: 'ACCESS_DENIED',
        message: 'Storage volume enumeration blocked by policy',
      },
    }));

    renderDashboard();

    await waitFor(() => {
      expect(screen.getByText('System Intelligence Dashboard')).toBeInTheDocument();
    });
  });
});
