import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { StorageView } from '../views/StorageView';
import { AppProvider } from '../state/AppContext';
import { MockTransport } from '../ipc/transport';
import { IpcClient } from '../ipc/client';
import {
  IpcRequest,
  IpcResponse,
  StorageSummaryDto,
  CandidateExplainabilityDto,
} from '../types/ipc';

describe('M3.7: Physical Storage & Subsystem Intelligence View', () => {
  let transport: MockTransport;
  let client: IpcClient;

  const mockStorageData: StorageSummaryDto = {
    drives: [
      {
        mount_point: 'C:\\',
        total_bytes: 512000000000, // 512 GB
        free_bytes: 64000000000,   // 64 GB (~12.5% free -> low space warning)
        available_bytes: 64000000000,
      },
      {
        mount_point: 'D:\\',
        total_bytes: 1024000000000, // 1 TB
        free_bytes: 600000000000,   // 600 GB (~58% free)
        available_bytes: 600000000000,
      },
    ],
    winsxs_protection: {
      path: 'C:\\Windows\\WinSxS',
      is_protected: true,
      reason: 'Windows Component Store protected by hard safety rule',
    },
  };

  const mockCandidates: CandidateExplainabilityDto[] = [
    {
      id: 'c1',
      path: 'C:\\Windows\\Temp\\temp1.log',
      size_bytes: 1200000000, // 1.2 GB
      category: 'Windows Temp',
      risk_score: 10,
      risk_band: 'Safe',
      risk_factors: [],
      local_rules: [],
      safety_verdict: 'auto_quarantine',
      can_quarantine: true,
      allowed_reasons: ['In temp folder'],
      blocked_reasons: [],
      is_pe: false,
      is_signed: false,
      is_in_use: false,
      is_hidden_or_system: false,
      selected: true,
    },
    {
      id: 'c2',
      path: 'C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\data_0',
      size_bytes: 3400000000, // 3.4 GB
      category: 'Browser Cache',
      risk_score: 15,
      risk_band: 'Safe',
      risk_factors: [],
      local_rules: [],
      safety_verdict: 'auto_quarantine',
      can_quarantine: true,
      allowed_reasons: ['Verified browser cache'],
      blocked_reasons: [],
      is_pe: false,
      is_signed: false,
      is_in_use: false,
      is_hidden_or_system: false,
      selected: true,
    },
    {
      id: 'c3',
      path: 'D:\\Games\\OldDump\\crash.dmp',
      size_bytes: 800000000, // 800 MB
      category: 'Crash Dumps',
      risk_score: 40,
      risk_band: 'Review',
      risk_factors: [],
      local_rules: [],
      safety_verdict: 'user_confirm',
      can_quarantine: true,
      allowed_reasons: ['Crash dump file'],
      blocked_reasons: [],
      is_pe: false,
      is_signed: false,
      is_in_use: false,
      is_hidden_or_system: false,
      selected: false,
    },
  ];

  beforeEach(() => {
    transport = new MockTransport();
    client = new IpcClient({ transport });

    transport.registerHandler('get_storage_summary', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: mockStorageData,
    }));

    transport.registerHandler('get_cleanup_candidates', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: mockCandidates,
    }));
  });

  const renderStorage = () => {
    return render(
      <AppProvider client={client} initialRoute="storage">
        <StorageView />
      </AppProvider>
    );
  };

  it('renders all detected physical volumes and handles drive drilldown', async () => {
    renderStorage();

    // Header
    await waitFor(() => {
      expect(screen.getByText('Physical Storage View')).toBeInTheDocument();
    });

    // Both detected volumes are rendered
    expect(screen.getByText('Volume C:\\')).toBeInTheDocument();
    expect(screen.getByText('Volume D:\\')).toBeInTheDocument();

    // Default drilldown is C:\
    expect(screen.getByText(/Drive Drill-Down: Volume C:\\/)).toBeInTheDocument();

    // Click on Volume D:\ to switch drilldown
    const driveDButton = screen.getByRole('button', { name: /Volume D:\\/i });
    fireEvent.click(driveDButton);

    // Drilldown title updates to Volume D:\
    await waitFor(() => {
      expect(screen.getByText(/Drive Drill-Down: Volume D:\\/)).toBeInTheDocument();
    });
  });

  it('enforces deterministic storage without arbitrary categorizations', async () => {
    renderStorage();

    await waitFor(() => {
      expect(screen.getByText('Deterministic Storage Transparency:')).toBeInTheDocument();
    });

    // Zero-guessing explanation is present
    expect(
      screen.getByText(/SWC only accounts for space verified by deterministic safety rules/i)
    ).toBeInTheDocument();

    // Legend shows verified unassessed space label rather than "Other" or "Media"
    expect(screen.getByText(/In-Use Filesystem Space \(Unassessed\):/i)).toBeInTheDocument();
  });

  it('aggregates real candidate metrics on selected drive', async () => {
    renderStorage();

    // C:\ has 2 candidates: Windows Temp (1.2 GB) and Browser Cache (3.4 GB)
    await waitFor(() => {
      expect(screen.getByText('Windows Temp')).toBeInTheDocument();
      expect(screen.getByText('Browser Cache')).toBeInTheDocument();
    });

    // Crash Dumps is on D:\ so it shouldn't be under C:\ breakdown
    expect(screen.queryByText('Crash Dumps')).not.toBeInTheDocument();

    // Drilldown to D:\
    fireEvent.click(screen.getByRole('button', { name: /Volume D:\\/i }));

    await waitFor(() => {
      expect(screen.getByText('Crash Dumps')).toBeInTheDocument();
    });
    // Windows Temp shouldn't be in D:\ table
    expect(screen.queryByText('Windows Temp')).not.toBeInTheDocument();
  });

  it('displays Component Store (WinSxS) protection details for C:\\ and hides it for D:\\', async () => {
    renderStorage();

    await waitFor(() => {
      expect(screen.getByText('Windows Component Store Protection (WinSxS)')).toBeInTheDocument();
      expect(screen.getByText('C:\\Windows\\WinSxS')).toBeInTheDocument();
    });

    // Explains hard safety rule and DISM servicing
    expect(
      screen.getByText(/Deleting files in WinSxS breaks the Windows Servicing Stack/i)
    ).toBeInTheDocument();
    expect(screen.getByText(/DISM\.exe \/Online \/Cleanup-Image \/StartComponentCleanup/i)).toBeInTheDocument();

    // When switching to D:\, WinSxS protection card should not be displayed
    fireEvent.click(screen.getByRole('button', { name: /Volume D:\\/i }));

    await waitFor(() => {
      expect(screen.queryByText('Windows Component Store Protection (WinSxS)')).not.toBeInTheDocument();
    });
  });

  it('shows low disk space warning when volume free space is under 15%', async () => {
    renderStorage();

    // C:\ has 64 GB free of 512 GB (~12.5% free), triggering Low Space alert
    await waitFor(() => {
      expect(screen.getAllByText(/Low Space/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/Low Disk Space Warning/i)).toBeInTheDocument();
    });

    // D:\ has 600 GB of 1024 GB free (~58% free) -> healthy headroom
    fireEvent.click(screen.getByRole('button', { name: /Volume D:\\/i }));

    await waitFor(() => {
      expect(screen.getByText(/maintains healthy storage headroom/i)).toBeInTheDocument();
    });
  });

  it('renders permanent safety engine protection boundaries', async () => {
    renderStorage();

    await waitFor(() => {
      expect(screen.getByText('Permanent Safety Engine Protection Boundaries')).toBeInTheDocument();
      expect(screen.getByText('OS Kernel & System Binaries')).toBeInTheDocument();
      expect(screen.getByText('Bootloader & EFI Partitions')).toBeInTheDocument();
      expect(screen.getByText('Application Directory Integrity')).toBeInTheDocument();
      expect(screen.getByText('Personal Data Protection')).toBeInTheDocument();
    });
  });

  it('handles empty candidates state on unscanned drive', async () => {
    // Provide empty candidates
    transport.registerHandler('get_cleanup_candidates', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: [],
    }));

    renderStorage();

    await waitFor(() => {
      expect(screen.getByText('No Candidates Assessed on this Volume')).toBeInTheDocument();
      expect(
        screen.getByText(/No cleanup candidates have been discovered on C:\\/i)
      ).toBeInTheDocument();
    });
  });

  it('renders error state when physical storage query fails', async () => {
    transport.registerHandler('get_storage_summary', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'error',
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Direct volume handle query failed: Access Denied',
      },
    }));

    renderStorage();

    await waitFor(() => {
      expect(screen.getByText(/Core Operation Error/i)).toBeInTheDocument();
      expect(
        screen.getByText(/Direct volume handle query failed: Access Denied/i)
      ).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Retry Action/i })).toBeInTheDocument();
    });
  });
});
