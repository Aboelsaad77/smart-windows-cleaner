import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { App } from '../App';
import { IpcClient } from '../ipc/client';
import { MockTransport } from '../ipc/transport';
import {
  IpcRequest,
  IpcResponse,
  CandidateExplainabilityDto,
  ScanSummaryDto,
} from '../types/ipc';

describe('M3.3 — Scan Workflow & State Machine', () => {
  it('allows scan mode selection (Quick, Smart, Deep) and updates selected mode', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    render(<App client={client} initialRoute="scan" />);

    await waitFor(() => {
      expect(screen.getByText('Core Connected')).toBeInTheDocument();
      expect(screen.getByText('Configure Filesystem Scan')).toBeInTheDocument();
    });

    // Verify Smart Scan is default selected mode
    expect(screen.getByText(/Ready to initiate SMART scan/i)).toBeInTheDocument();

    // Select Quick Scan
    const quickCard = screen.getByText('Quick Scan').closest('div');
    expect(quickCard).toBeInTheDocument();
    fireEvent.click(quickCard!);

    expect(screen.getByText(/Ready to initiate QUICK scan/i)).toBeInTheDocument();
    // Now Smart Scan shows Recommended
    expect(screen.getByText('Recommended')).toBeInTheDocument();

    // Select Deep Scan
    const deepCard = screen.getByText('Deep Scan').closest('div');
    expect(deepCard).toBeInTheDocument();
    fireEvent.click(deepCard!);

    expect(screen.getByText(/Ready to initiate DEEP scan/i)).toBeInTheDocument();
  });

  it('handles target roots and custom directory additions', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    render(<App client={client} initialRoute="scan" />);

    await waitFor(() => {
      expect(screen.getByText('Core Connected')).toBeInTheDocument();
      expect(screen.getByText('Configure Filesystem Scan')).toBeInTheDocument();
    });

    // C:\ should be detected from get_storage_summary
    await waitFor(() => {
      expect(screen.getByText('C:\\')).toBeInTheDocument();
    });

    // Add custom path
    const input = screen.getByPlaceholderText(/e\.g\. C:\\Users/i);
    fireEvent.change(input, { target: { value: 'E:\\Games' } });
    fireEvent.click(screen.getByRole('button', { name: /add path/i }));

    expect(screen.getByText('E:\\Games')).toBeInTheDocument();
    expect(screen.getByText(/2 Roots Selected/i)).toBeInTheDocument();
  });

  it('initiates scan via start_scan command and displays returned session ID', async () => {
    const transport = new MockTransport();
    let startCommandReceived: unknown = null;

    transport.registerHandler('start_scan', (req: IpcRequest): IpcResponse => {
      startCommandReceived = req.payload;
      return {
        id: req.id,
        status: 'ok',
        data: { session_id: 'scan-sess-xyz123' },
      };
    });

    const client = new IpcClient({ transport });
    render(<App client={client} initialRoute="scan" />);

    await waitFor(() => {
      expect(screen.getByText('Core Connected')).toBeInTheDocument();
      expect(screen.getByText('Configure Filesystem Scan')).toBeInTheDocument();
    });

    const startBtn = screen.getByRole('button', { name: /start scan/i });
    fireEvent.click(startBtn);

    await waitFor(() => {
      expect(screen.getByText('Scan In Progress')).toBeInTheDocument();
      expect(screen.getByText(/scan-sess-xyz123/)).toBeInTheDocument();
    });

    expect(startCommandReceived).toEqual({
      mode: 'smart',
      roots: ['C:\\'],
    });
  });

  it('updates live scan telemetry on progress events and enforces NO fake percentages', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    render(<App client={client} initialRoute="scan" />);

    await waitFor(() => {
      expect(screen.getByText('Core Connected')).toBeInTheDocument();
      expect(screen.getByText('Configure Filesystem Scan')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /start scan/i }));

    await waitFor(() => {
      expect(screen.getByText('Scan In Progress')).toBeInTheDocument();
    });

    // Emit scan_progress event with NO progress_percent (indeterminate)
    act(() => {
      transport.emit({
        type: 'scan_progress',
        session_id: 'scan-sess-xyz123',
        elapsed_ms: 3500,
        files_scanned: 18420,
        candidates_found: 14,
        estimated_reclaimable_bytes: 524288000, // 500 MB
        current_path: 'C:\\Windows\\Temp\\cache_01.tmp',
        current_category: 'System Temp',
      });
    });

    await waitFor(() => {
      expect(screen.getByText('18,420')).toBeInTheDocument();
      expect(screen.getByText('14')).toBeInTheDocument();
      expect(screen.getByText(/500(\.0)? MB/)).toBeInTheDocument();
      expect(screen.getByText(/cache_01\.tmp/)).toBeInTheDocument();
    });

    // Invariant check: Ensure NO fake/guessed percentage is displayed
    const progressText = screen.getByText(/18,420 files inspected/i);
    expect(progressText).toBeInTheDocument();
    // There must be no percentage symbol displayed for indeterminate progress
    expect(screen.queryByText(/%\s*$/)).not.toBeInTheDocument();
  });

  it('streams candidate discoveries with risk and safety badges and NO destructive actions', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    render(<App client={client} initialRoute="scan" />);

    await waitFor(() => {
      expect(screen.getByText('Core Connected')).toBeInTheDocument();
      expect(screen.getByText('Configure Filesystem Scan')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /start scan/i }));

    await waitFor(() => {
      expect(screen.getByText('Scan In Progress')).toBeInTheDocument();
    });

    const mockCandidate: CandidateExplainabilityDto = {
      id: 'cand-1',
      path: 'C:\\Users\\User\\AppData\\Local\\Temp\\junk-log.tmp',
      size_bytes: 10485760, // 10 MB
      category: 'User Temp',
      risk_score: 25,
      risk_band: 'Safe',
      risk_factors: [],
      local_rules: [],
      safety_verdict: 'auto_quarantine',
      can_quarantine: true,
      allowed_reasons: ['User temp directory item older than 7 days'],
      blocked_reasons: [],
      is_pe: false,
      is_signed: false,
      is_in_use: false,
      is_hidden_or_system: false,
      selected: false,
    };

    act(() => {
      transport.emit({
        type: 'scan_candidate_discovered',
        candidate: mockCandidate,
      });
    });

    await waitFor(() => {
      expect(screen.getByText('junk-log.tmp')).toBeInTheDocument();
      expect(screen.getByText(/Safe \(25\)/i)).toBeInTheDocument();
      expect(screen.getByText('Auto Quarantine')).toBeInTheDocument();
    });

    // Strictly verify NO destructive actions (Delete / Quarantine / Remove buttons) exist in live stream
    expect(screen.queryByRole('button', { name: /delete/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /quarantine item/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /clean/i })).not.toBeInTheDocument();
  });

  it('executes cancellation flow, confirms with user, and preserves partial statistics', async () => {
    const transport = new MockTransport();
    let cancelCalledWith: unknown = null;

    transport.registerHandler('cancel_scan', (req: IpcRequest): IpcResponse => {
      cancelCalledWith = req.payload;
      return {
        id: req.id,
        status: 'ok',
        data: { session_id: 'scan-sess-cancel' },
      };
    });

    const client = new IpcClient({ transport });
    render(<App client={client} initialRoute="scan" />);

    await waitFor(() => {
      expect(screen.getByText('Core Connected')).toBeInTheDocument();
      expect(screen.getByText('Configure Filesystem Scan')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /start scan/i }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /cancel scan/i })).toBeInTheDocument();
    });

    // Trigger Cancel Dialog
    fireEvent.click(screen.getByRole('button', { name: /cancel scan/i }));
    expect(screen.getByText('Cancel Active Scan?')).toBeInTheDocument();

    // Confirm cancel
    fireEvent.click(screen.getByRole('button', { name: /cancel scan now/i }));

    await waitFor(() => {
      expect(cancelCalledWith).toEqual({ session_id: expect.any(String) });
    });

    // Core emits scan_cancelled
    act(() => {
      transport.emit({
        type: 'scan_cancelled',
        session_id: 'scan-sess-cancel',
        partial_summary: {
          session_id: 'scan-sess-cancel',
          total_files_scanned: 5400,
          total_candidates_found: 8,
          total_reclaimable_bytes: 209715200, // 200 MB
          auto_eligible_bytes: 104857600,
          user_confirm_bytes: 104857600,
          blocked_bytes: 0,
          categories: [],
          elapsed_ms: 4200,
        },
      });
    });

    await waitFor(() => {
      expect(screen.getByText('Scan Cancelled by User')).toBeInTheDocument();
      expect(screen.getByText('5,400')).toBeInTheDocument();
      expect(screen.getByText('8')).toBeInTheDocument();
      expect(screen.getByText(/200(\.0)? MB/)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /configure new scan/i })).toBeInTheDocument();
    });
  });

  it('renders completed summary screen on scan_completed with accurate breakdowns and navigation', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    render(<App client={client} initialRoute="scan" />);

    await waitFor(() => {
      expect(screen.getByText('Core Connected')).toBeInTheDocument();
      expect(screen.getByText('Configure Filesystem Scan')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /start scan/i }));

    await waitFor(() => {
      expect(screen.getByText('Scan In Progress')).toBeInTheDocument();
    });

    const mockSummary: ScanSummaryDto = {
      session_id: 'scan-final-summary-99',
      total_files_scanned: 45200,
      total_candidates_found: 128,
      total_reclaimable_bytes: 3221225472, // 3.0 GB
      auto_eligible_bytes: 2147483648,     // 2.0 GB
      user_confirm_bytes: 1073741824,     // 1.0 GB
      blocked_bytes: 536870912,           // 512 MB
      categories: [
        { category: 'Browser Caches', count: 96, total_bytes: 2147483648, eligible_quarantine_bytes: 2147483648 },
        { category: 'System Crash Dumps', count: 32, total_bytes: 1073741824, eligible_quarantine_bytes: 1073741824 },
      ],
      elapsed_ms: 12450,
    };

    act(() => {
      transport.emit({
        type: 'scan_completed',
        summary: mockSummary,
      });
    });

    await waitFor(() => {
      expect(screen.getByText('Scan Completed Successfully')).toBeInTheDocument();
      expect(screen.getByText('45,200')).toBeInTheDocument();
      expect(screen.getByText('128')).toBeInTheDocument();
      expect(screen.getByText(/3(\.00)? GB/)).toBeInTheDocument();
      expect(screen.getByText('Browser Caches')).toBeInTheDocument();
      expect(screen.getByText('System Crash Dumps')).toBeInTheDocument();
    });

    // Navigation button to Results
    const viewCandidatesBtn = screen.getByRole('button', { name: /view cleanup candidates/i });
    expect(viewCandidatesBtn).toBeInTheDocument();
    fireEvent.click(viewCandidatesBtn);

    // Results view should now be displayed
    await waitFor(() => {
      expect(screen.getByText('Cleanup Candidates & Explainability')).toBeInTheDocument();
    });
  });

  it('handles elevation_required event with clear scope explanation and elevation trigger', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    render(<App client={client} initialRoute="scan" />);

    await waitFor(() => {
      expect(screen.getByText('Core Connected')).toBeInTheDocument();
      expect(screen.getByText('Configure Filesystem Scan')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /start scan/i }));

    await waitFor(() => {
      expect(screen.getByText('Scan In Progress')).toBeInTheDocument();
    });

    act(() => {
      transport.emit({
        type: 'elevation_required',
        reason: 'Protected Windows component folder inspection requires UAC elevation',
        action_attempted: 'C:\\Windows\\System32\\DriverStore',
      });
    });

    await waitFor(() => {
      expect(screen.getByText(/Administrator Elevation Required for Protected Scope/i)).toBeInTheDocument();
      expect(screen.getAllByText(/Protected Windows component folder inspection/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText(/DriverStore/i).length).toBeGreaterThanOrEqual(1);
    });
  });

  it('reconciles local state seamlessly if reconnected to an active running scan', async () => {
    const transport = new MockTransport();

    // Core is already in scanning state when UI mounts
    transport.registerHandler('get_scan_status', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: {
        state: 'scanning',
        session_id: 'reconnected-sess-001',
        files_scanned: 9820,
        candidates_found: 7,
        elapsed_ms: 6100,
        current_path: 'C:\\Program Files\\App\\cache',
      },
    }));

    const client = new IpcClient({ transport });
    render(<App client={client} initialRoute="scan" />);

    await waitFor(() => {
      expect(screen.getByText('Core Connected')).toBeInTheDocument();
      expect(screen.getByText('Scan In Progress')).toBeInTheDocument();
      expect(screen.getByText(/reconnected-sess-001/)).toBeInTheDocument();
      expect(screen.getByText('9,820')).toBeInTheDocument();
    });
  });

  it('surfaces structured ErrorState on scan initialization failure', async () => {
    const transport = new MockTransport();

    transport.registerHandler('start_scan', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'error',
      error: {
        code: 'ACCESS_DENIED',
        message: 'The requested drive path cannot be opened for inspection without elevation.',
      },
    }));

    const client = new IpcClient({ transport });
    render(<App client={client} initialRoute="scan" />);

    await waitFor(() => {
      expect(screen.getByText('Core Connected')).toBeInTheDocument();
      expect(screen.getByText('Configure Filesystem Scan')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /start scan/i }));

    await waitFor(() => {
      expect(screen.getByText('Scan Execution Interrupted')).toBeInTheDocument();
      expect(screen.getByText('Access Denied')).toBeInTheDocument();
      expect(screen.getByText('ACCESS_DENIED')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /return to scan configuration/i })).toBeInTheDocument();
    });
  });
});
