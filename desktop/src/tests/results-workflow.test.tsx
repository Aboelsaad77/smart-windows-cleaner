import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ResultsView } from '../views/ResultsView';
import { AppProvider } from '../state/AppContext';
import { MockTransport } from '../ipc/transport';
import { IpcClient } from '../ipc/client';
import {
  IpcRequest,
  IpcResponse,
  CandidateExplainabilityDto,
} from '../types/ipc';

const mockCandidates: CandidateExplainabilityDto[] = [
  {
    id: 'cand-chrome-1',
    path: 'C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\data_0',
    category: 'Browser Cache',
    size_bytes: 52428800, // 50 MB
    risk_score: 15,
    risk_band: 'Safe',
    safety_verdict: 'auto_quarantine',
    app_owner: 'Google Chrome',
    app_confidence: 'publisher_directory',
    is_pe: false,
    is_signed: false,
    is_in_use: false,
    is_hidden_or_system: false,
    selected: true,
    can_quarantine: true,
    local_rules: [
      {
        rule_id: 'RULE-CHROME-CACHE',
        category: 'Browser Cache',
        confidence: 'high',
        reclaim_estimate_bytes: 52428800,
      },
    ],
    risk_factors: [
      {
        name: 'BrowserCache',
        weight: 15,
        reason: 'Safe browser cache file recreated automatically',
      },
    ],
    allowed_reasons: [
      'Matches known disposable pattern in local rules',
      'Path does not intersect with system critical roots',
      'No active process file lock detected',
    ],
    blocked_reasons: [],
  },
  {
    id: 'cand-system-hive',
    path: 'C:\\Windows\\System32\\config\\SYSTEM',
    category: 'System Registry Hive',
    size_bytes: 15728640, // 15 MB
    risk_score: 100,
    risk_band: 'Protected',
    safety_verdict: 'never_delete',
    app_owner: 'Microsoft Windows',
    app_confidence: 'direct_key',
    is_pe: false,
    is_signed: true,
    is_in_use: true,
    is_hidden_or_system: true,
    selected: false,
    can_quarantine: false,
    local_rules: [],
    risk_factors: [
      {
        name: 'SystemCriticalHive',
        weight: 100,
        reason: 'Windows System registry hive is vital for OS boot',
      },
      {
        name: 'ActiveProcessLock',
        weight: 30,
        reason: 'Exclusive handle held by SYSTEM kernel process',
      },
    ],
    allowed_reasons: [],
    blocked_reasons: [
      'Prohibited path: File resides within C:\\Windows\\System32',
      'Active exclusive file handle lock held by kernel',
      'Marked as critical system file: deletion causes OS failure',
    ],
  },
  {
    id: 'cand-installer-exe',
    path: 'C:\\Users\\User\\AppData\\Local\\Temp\\installer.exe',
    category: 'Temporary Executable',
    size_bytes: 125829120, // 120 MB
    risk_score: 45,
    risk_band: 'Review',
    safety_verdict: 'user_confirm',
    app_owner: 'Unknown Installer',
    app_confidence: 'heuristic',
    is_pe: true,
    is_signed: false,
    is_in_use: false,
    is_hidden_or_system: false,
    selected: false,
    can_quarantine: true,
    local_rules: [
      {
        rule_id: 'RULE-TEMP-EXE',
        category: 'Temporary Executable',
        confidence: 'medium',
        reclaim_estimate_bytes: 125829120,
      },
    ],
    risk_factors: [
      {
        name: 'ExecutableBinary',
        weight: 35,
        reason: 'Binary PE executable located in temp folder',
      },
      {
        name: 'UnsignedBinary',
        weight: 10,
        reason: 'File lacks Authenticode signature',
      },
    ],
    allowed_reasons: [
      'Located in user temporary directory',
      'No active lock detected',
    ],
    blocked_reasons: [],
  },
];

describe('M3.4: Results & Explainability Workflow', () => {
  let transport: MockTransport;
  let client: IpcClient;

  beforeEach(() => {
    transport = new MockTransport();
    client = new IpcClient({ transport });

    // Default mock response: returns our 3 diverse candidates
    transport.registerHandler('get_cleanup_candidates', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: mockCandidates,
    }));
  });

  const renderResults = () => {
    return render(
      <AppProvider client={client}>
        <ResultsView />
      </AppProvider>
    );
  };

  it('renders summary metrics, candidates table, and calculated reclaimable space', async () => {
    renderResults();

    await waitFor(() => {
      // 50 MB + 120 MB eligible (System hive can_quarantine is false) = 170 MB
      expect(screen.getByText('Potential Reclaimable Space')).toBeInTheDocument();
      expect(screen.getByText(/170(\.0)? MB/)).toBeInTheDocument();
    });

    // Check Candidate rows rendered
    expect(screen.getByText('data_0')).toBeInTheDocument();
    expect(screen.getByText('SYSTEM')).toBeInTheDocument();
    expect(screen.getByText('installer.exe')).toBeInTheDocument();

    // Check Safety badges rendered (in filter options and candidate rows)
    expect(screen.getAllByText('Auto Quarantine').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('Protected (Never Delete)')).toBeInTheDocument();
    expect(screen.getAllByText('User Confirm').length).toBeGreaterThanOrEqual(2);
  });

  it('filters candidates by search query across path, owner, and category', async () => {
    renderResults();

    await waitFor(() => {
      expect(screen.getByText('data_0')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText(/search by file name/i);

    // Search for "Chrome"
    fireEvent.change(searchInput, { target: { value: 'Chrome' } });

    expect(screen.getByText('data_0')).toBeInTheDocument();
    expect(screen.queryByText('SYSTEM')).not.toBeInTheDocument();
    expect(screen.queryByText('installer.exe')).not.toBeInTheDocument();

    // Clear search
    fireEvent.change(searchInput, { target: { value: '' } });
    expect(screen.getByText('SYSTEM')).toBeInTheDocument();
  });

  it('filters candidates by safety verdict', async () => {
    renderResults();

    await waitFor(() => {
      expect(screen.getByText('SYSTEM')).toBeInTheDocument();
    });

    const selects = screen.getAllByRole('combobox');
    const verdictSelect = selects[0]; // first dropdown is Verdict

    // Select never_delete
    fireEvent.change(verdictSelect, { target: { value: 'never_delete' } });

    expect(screen.getByText('SYSTEM')).toBeInTheDocument();
    expect(screen.queryByText('data_0')).not.toBeInTheDocument();
    expect(screen.queryByText('installer.exe')).not.toBeInTheDocument();
  });

  it('filters candidates by > 100 MB large files checkbox', async () => {
    renderResults();

    await waitFor(() => {
      expect(screen.getByText('data_0')).toBeInTheDocument();
    });

    const largeCheckbox = screen.getByLabelText(/> 100 MB only/i);
    fireEvent.click(largeCheckbox);

    // installer.exe is 120 MB, data_0 is 50 MB, SYSTEM is 15 MB
    expect(screen.getByText('installer.exe')).toBeInTheDocument();
    expect(screen.queryByText('data_0')).not.toBeInTheDocument();
    expect(screen.queryByText('SYSTEM')).not.toBeInTheDocument();
  });

  it('enforces safety invariant: Protected items cannot be selected and display padlock', async () => {
    renderResults();

    await waitFor(() => {
      expect(screen.getByText('SYSTEM')).toBeInTheDocument();
    });

    // Check for lock icon title on protected system item
    const lockTitles = screen.getAllByTitle(/protected by safety engine/i);
    expect(lockTitles.length).toBeGreaterThan(0);

    // There should only be 2 selectable checkboxes for the 3 candidates (Chrome and Temp installer)
    const checkboxes = screen.getAllByRole('checkbox');
    // Note: includes the large files filter checkbox + 2 item checkboxes = 3
    expect(checkboxes.length).toBe(3);
  });

  it('selecting an eligible candidate calls IPC selectCandidate', async () => {
    const selectSpy = vi.spyOn(client, 'selectCandidate');
    renderResults();

    await waitFor(() => {
      expect(screen.getByText('installer.exe')).toBeInTheDocument();
    });

    // Find checkbox for installer.exe
    const installerRow = screen.getByText('installer.exe').closest('tr');
    expect(installerRow).not.toBeNull();

    const checkbox = installerRow?.querySelector('input[type="checkbox"]');
    expect(checkbox).not.toBeNull();

    fireEvent.click(checkbox!);

    expect(selectSpy).toHaveBeenCalledWith(
      'C:\\Users\\User\\AppData\\Local\\Temp\\installer.exe',
      true
    );
  });

  it('select all eligible selects only quarantine-eligible items, never protected items', async () => {
    const selectAllSpy = vi.spyOn(client, 'selectAllCandidates');
    renderResults();

    await waitFor(() => {
      expect(screen.getByText('Select All Eligible')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Select All Eligible'));

    expect(selectAllSpy).toHaveBeenCalledWith(true, expect.anything());

    // Active Selection summary should reflect 2 items (Chrome + Installer, SYSTEM excluded)
    await waitFor(() => {
      expect(screen.getByText(/2 selected/i)).toBeInTheDocument();
    });
  });

  it('clicking a candidate row opens ExplainabilityDrawer displaying provenance, rules, risk factors, and safety reasons', async () => {
    renderResults();

    await waitFor(() => {
      expect(screen.getByText('data_0')).toBeInTheDocument();
    });

    // Click Chrome item row
    fireEvent.click(screen.getByText('data_0'));

    // Drawer opens
    await waitFor(() => {
      expect(screen.getByRole('dialog', { name: /candidate explainability details/i })).toBeInTheDocument();
    });

    // Provenance
    expect(screen.getByText('Identity & Provenance')).toBeInTheDocument();
    expect(screen.getAllByText('Google Chrome').length).toBeGreaterThanOrEqual(2);

    // Detection Evidence
    expect(screen.getByText('RULE-CHROME-CACHE')).toBeInTheDocument();

    // Risk Factors
    expect(screen.getByText('BrowserCache')).toBeInTheDocument();
    expect(screen.getByText('Safe browser cache file recreated automatically')).toBeInTheDocument();

    // Safety Gate
    expect(screen.getByText('Why Quarantine Is Permitted:')).toBeInTheDocument();
    expect(screen.getByText('Matches known disposable pattern in local rules')).toBeInTheDocument();

    // Close drawer
    fireEvent.click(screen.getByLabelText(/close explainability panel/i));
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
  });

  it('ExplainabilityDrawer for protected item explicitly shows blocked reasons without hiding reasons', async () => {
    renderResults();

    await waitFor(() => {
      expect(screen.getByText('SYSTEM')).toBeInTheDocument();
    });

    // Click System file row
    fireEvent.click(screen.getByText('SYSTEM'));

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    // Safety Engine reasons why it CANNOT be quarantined
    expect(screen.getByText('Why Quarantine Is Prohibited:')).toBeInTheDocument();
    expect(screen.getByText(/Prohibited path: File resides within C:\\Windows\\System32/)).toBeInTheDocument();
    expect(screen.getByText(/Active exclusive file handle lock held by kernel/)).toBeInTheDocument();
    expect(screen.getByText(/Marked as critical system file: deletion causes OS failure/)).toBeInTheDocument();
  });

  it('re-analyzing a candidate invokes requestAnalysis on core and updates candidate state', async () => {
    const requestAnalysisSpy = vi.spyOn(client, 'requestAnalysis');

    const updatedCandidate: CandidateExplainabilityDto = {
      ...mockCandidates[2],
      risk_score: 55, // updated score
      allowed_reasons: ['Re-analyzed: fresh timestamp verified'],
    };

    transport.registerHandler('request_analysis', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: updatedCandidate,
    }));

    renderResults();

    await waitFor(() => {
      expect(screen.getByText('installer.exe')).toBeInTheDocument();
    });

    // Open drawer for installer.exe
    fireEvent.click(screen.getByText('installer.exe'));

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    // Click Re-Analyze Item
    const reanalyzeBtn = screen.getByText('Re-Analyze Item');
    fireEvent.click(reanalyzeBtn);

    await waitFor(() => {
      expect(requestAnalysisSpy).toHaveBeenCalledWith(
        'C:\\Users\\User\\AppData\\Local\\Temp\\installer.exe'
      );
      expect(screen.getByText('Re-analyzed: fresh timestamp verified')).toBeInTheDocument();
    });
  });

  it('renders clean empty state when no candidates found', async () => {
    transport.registerHandler('get_cleanup_candidates', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: [],
    }));
    renderResults();

    await waitFor(() => {
      expect(screen.getByText('No Candidates Found')).toBeInTheDocument();
    });
  });

  it('renders error state when IPC call fails', async () => {
    transport.registerHandler('get_cleanup_candidates', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'error',
      error: {
        code: 'INTERNAL_CORE_ERROR',
        message: 'IPC socket connection dropped',
      },
    }));

    renderResults();

    await waitFor(() => {
      expect(screen.getByText('Results Retrieval Failed')).toBeInTheDocument();
      expect(screen.getByText('IPC socket connection dropped')).toBeInTheDocument();
    });
  });
});
