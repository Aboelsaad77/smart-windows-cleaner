import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QuarantineView } from '../views/QuarantineView';
import { ResultsView } from '../views/ResultsView';
import { AppProvider } from '../state/AppContext';
import { MockTransport } from '../ipc/transport';
import { IpcClient } from '../ipc/client';
import {
  IpcRequest,
  IpcResponse,
  QuarantineItemDto,
  CandidateExplainabilityDto,
} from '../types/ipc';

const mockVaultItems: QuarantineItemDto[] = [
  {
    item_id: 'q-item-1',
    original_path: 'C:\\Users\\User\\AppData\\Local\\Temp\\chrome_cache.tmp',
    category: 'Browser Cache',
    quarantined_size_bytes: 15728640, // 15 MB
    sha256_hash: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    quarantined_at: '2026-09-10T12:00:00Z',
    retention_days: 7,
    days_remaining: 5,
    is_expired: false,
  },
  {
    item_id: 'q-item-2',
    original_path: 'C:\\Windows\\Temp\\old_crash.dmp',
    category: 'Crash Dump',
    quarantined_size_bytes: 104857600, // 100 MB
    sha256_hash: 'cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34',
    quarantined_at: '2026-09-01T08:00:00Z',
    retention_days: 7,
    days_remaining: 0,
    is_expired: true,
  },
];

const mockCandidates: CandidateExplainabilityDto[] = [
  {
    id: 'cand-1',
    path: 'C:\\Users\\User\\AppData\\Local\\Temp\\junk-to-quarantine.tmp',
    category: 'User Temp',
    size_bytes: 20971520, // 20 MB
    risk_score: 20,
    risk_band: 'Safe',
    safety_verdict: 'auto_quarantine',
    app_owner: 'Test App',
    app_confidence: 'direct_key',
    is_pe: false,
    is_signed: false,
    is_in_use: false,
    is_hidden_or_system: false,
    selected: true,
    can_quarantine: true,
    local_rules: [],
    risk_factors: [],
    allowed_reasons: ['User temporary file'],
    blocked_reasons: [],
  },
];

describe('M3.5: Quarantine Vault & Restoration Lifecycle', () => {
  let transport: MockTransport;
  let client: IpcClient;

  beforeEach(() => {
    transport = new MockTransport();
    client = new IpcClient({ transport });

    transport.registerHandler('get_quarantine_contents', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: mockVaultItems,
    }));
  });

  const renderQuarantine = () => {
    return render(
      <AppProvider client={client} initialRoute="quarantine">
        <QuarantineView />
      </AppProvider>
    );
  };

  it('renders quarantine vault inventory with SHA-256 hashes and retention countdowns', async () => {
    renderQuarantine();

    await waitFor(() => {
      expect(screen.getByText('Quarantine Vault & Restoration')).toBeInTheDocument();
      expect(screen.getByText('chrome_cache.tmp')).toBeInTheDocument();
      expect(screen.getByText('old_crash.dmp')).toBeInTheDocument();
    });

    // Check Metrics Cards
    expect(screen.getByText('2 files')).toBeInTheDocument();
    expect(screen.getByText('1 expired')).toBeInTheDocument();
    expect(screen.getByText(/115(\.0)? MB/)).toBeInTheDocument();

    // Check retention statuses
    expect(screen.getByText('5 days left')).toBeInTheDocument();
    expect(screen.getByText('Expired')).toBeInTheDocument();

    // Check SHA-256 display
    expect(screen.getByText(/ba7816bf/)).toBeInTheDocument();
  });

  it('filters quarantined items by active vs expired status', async () => {
    renderQuarantine();

    await waitFor(() => {
      expect(screen.getByText('chrome_cache.tmp')).toBeInTheDocument();
    });

    const selects = screen.getAllByRole('combobox');
    const statusSelect = selects[0]; // first combobox is status

    // Filter to expired only
    await waitFor(() => {
      fireEvent.change(statusSelect, { target: { value: 'expired' } });
    });

    await waitFor(() => {
      expect(screen.getByText('old_crash.dmp')).toBeInTheDocument();
      expect(screen.queryByText('chrome_cache.tmp')).not.toBeInTheDocument();
    });

    // Filter to active only
    await waitFor(() => {
      fireEvent.change(statusSelect, { target: { value: 'active' } });
    });

    await waitFor(() => {
      expect(screen.getByText('chrome_cache.tmp')).toBeInTheDocument();
      expect(screen.queryByText('old_crash.dmp')).not.toBeInTheDocument();
    });
  });

  it('executes individual file restore with confirmation', async () => {
    const restoreSpy = vi.spyOn(client, 'restoreQuarantineItem');
    renderQuarantine();

    await waitFor(() => {
      expect(screen.getByText('chrome_cache.tmp')).toBeInTheDocument();
    });

    // Target the row-level Restore button via title
    const rowRestoreButtons = screen.getAllByTitle(/restore this file to its original/i);
    expect(rowRestoreButtons.length).toBe(2);

    // Click restore on the chrome_cache.tmp row
    fireEvent.click(rowRestoreButtons[1]); // chrome_cache is second row when sorted by days_remaining ascending (5 days vs 0 days)

    // Modal opens
    await waitFor(() => {
      expect(screen.getByText('Restore Quarantined File')).toBeInTheDocument();
      expect(screen.getAllByText(/chrome_cache\.tmp/).length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('SHA-256 match verified')).toBeInTheDocument();
    });

    // Confirm restore
    fireEvent.click(screen.getByRole('button', { name: /confirm restore/i }));

    await waitFor(() => {
      expect(restoreSpy).toHaveBeenCalledWith('q-item-1', undefined);
      expect(screen.getByText(/successfully restored "chrome_cache\.tmp"/i)).toBeInTheDocument();
    });

    // Item removed from table
    expect(screen.queryByText('chrome_cache.tmp')).not.toBeInTheDocument();
  });

  it('supports path override during restore to handle collisions', async () => {
    const restoreSpy = vi.spyOn(client, 'restoreQuarantineItem');
    renderQuarantine();

    await waitFor(() => {
      expect(screen.getByText('chrome_cache.tmp')).toBeInTheDocument();
    });

    const rowRestoreButtons = screen.getAllByTitle(/restore this file to its original/i);
    fireEvent.click(rowRestoreButtons[1]); // chrome_cache.tmp

    await waitFor(() => {
      expect(screen.getByText('Restore Quarantined File')).toBeInTheDocument();
    });

    // Check the override checkbox specifically
    const overrideCheckbox = screen.getByLabelText(/restore to custom path override/i);
    fireEvent.click(overrideCheckbox);

    const overrideInput = screen.getByPlaceholderText(/e\.g\. C:\\RestoredFiles/i);
    fireEvent.change(overrideInput, { target: { value: 'D:\\Restored\\cache.tmp' } });

    // Confirm restore
    fireEvent.click(screen.getByRole('button', { name: /confirm restore/i }));

    await waitFor(() => {
      expect(restoreSpy).toHaveBeenCalledWith('q-item-1', 'D:\\Restored\\cache.tmp');
    });
  });

  it('executes individual file purge with strong non-reversible confirmation', async () => {
    const purgeSpy = vi.spyOn(client, 'purgeQuarantineItem');
    renderQuarantine();

    await waitFor(() => {
      expect(screen.getByText('old_crash.dmp')).toBeInTheDocument();
    });

    // Purge buttons (Trash icon buttons)
    const purgeButtons = screen.getAllByTitle(/permanently and irrevocably delete/i);
    expect(purgeButtons.length).toBe(2);

    // Row 0 is old_crash.dmp (0 days remaining)
    fireEvent.click(purgeButtons[0]);

    // Confirmation dialog opens with strong warning
    await waitFor(() => {
      expect(screen.getByText('Permanently Purge Quarantined File?')).toBeInTheDocument();
      expect(screen.getByText(/THIS ACTION IS IRREVERSIBLE/i)).toBeInTheDocument();
    });

    // Confirm purge
    fireEvent.click(screen.getByRole('button', { name: 'Permanently Purge File' }));

    await waitFor(() => {
      expect(purgeSpy).toHaveBeenCalledWith('q-item-2');
      expect(screen.getByText(/permanently purged "old_crash\.dmp"/i)).toBeInTheDocument();
    });

    expect(screen.queryByText('old_crash.dmp')).not.toBeInTheDocument();
  });

  it('supports batch restore for selected items', async () => {
    const restoreSpy = vi.spyOn(client, 'restoreQuarantineItem');
    renderQuarantine();

    await waitFor(() => {
      expect(screen.getByText('Select All')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Select All'));

    const batchRestoreBtn = screen.getByRole('button', { name: /restore selected \(2\)/i });
    fireEvent.click(batchRestoreBtn);

    await waitFor(() => {
      expect(screen.getByText('Restore 2 Files?')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Restore 2 Files' }));

    await waitFor(() => {
      expect(restoreSpy).toHaveBeenCalledTimes(2);
      expect(screen.getByText(/successfully restored 2 items/i)).toBeInTheDocument();
    });
  });

  it('supports batch purge for selected items', async () => {
    const purgeSpy = vi.spyOn(client, 'purgeQuarantineItem');
    renderQuarantine();

    await waitFor(() => {
      expect(screen.getByText('Select All')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Select All'));

    const batchPurgeBtn = screen.getByRole('button', { name: /purge selected \(2\)/i });
    fireEvent.click(batchPurgeBtn);

    await waitFor(() => {
      expect(screen.getByText('Permanently Purge 2 Files?')).toBeInTheDocument();
      expect(screen.getByText(/CRITICAL WARNING: You are about to permanently delete 2 items/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Permanently Purge 2 Files' }));

    await waitFor(() => {
      expect(purgeSpy).toHaveBeenCalledTimes(2);
      expect(screen.getByText(/permanently purged 2 items/i)).toBeInTheDocument();
    });
  });

  it('results view triggers quarantine confirmation and renders structured results modal with blocked reasons', async () => {
    // Setup candidate in Results
    transport.registerHandler('get_cleanup_candidates', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: mockCandidates,
    }));

    // Mock quarantine_selected returning 1 quarantined, 1 blocked with explicit reason
    transport.registerHandler('quarantine_selected', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: {
        quarantined: [
          {
            item_id: 'q-item-new-1',
            original_path: 'C:\\Users\\User\\AppData\\Local\\Temp\\junk-to-quarantine.tmp',
            category: 'User Temp',
            quarantined_size_bytes: 20971520,
            sha256_hash: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
            quarantined_at: '2026-09-16T12:00:00Z',
            retention_days: 7,
            days_remaining: 7,
            is_expired: false,
          },
        ],
        blocked: [
          {
            path: 'C:\\Windows\\System32\\driver.sys',
            reason: 'Safety preflight: File is protected system driver',
          },
        ],
        failed: [],
      },
    }));

    render(
      <AppProvider client={client} initialRoute="results">
        <ResultsView />
      </AppProvider>
    );

    await waitFor(() => {
      expect(screen.getByText('junk-to-quarantine.tmp')).toBeInTheDocument();
    });

    // Click Quarantine Selected (1)
    const quarantineBtn = screen.getByRole('button', { name: /quarantine selected \(1\)/i });
    fireEvent.click(quarantineBtn);

    // Confirmation dialog
    await waitFor(() => {
      expect(screen.getByText('Quarantine 1 Selected Files?')).toBeInTheDocument();
    });

    // Confirm
    fireEvent.click(screen.getByRole('button', { name: 'Quarantine 1 Files' }));

    // Operation Result Modal opens
    await waitFor(() => {
      expect(screen.getByText('Quarantine Operation Result')).toBeInTheDocument();
      expect(screen.getByText('Successfully Vaulted')).toBeInTheDocument();
      expect(screen.getByText('Safety Blocked')).toBeInTheDocument();
      expect(screen.getByText('Reason: Safety preflight: File is protected system driver')).toBeInTheDocument();
    });

    // Quarantined item removed from candidates
    expect(screen.queryByText('junk-to-quarantine.tmp')).not.toBeInTheDocument();
  });
});
