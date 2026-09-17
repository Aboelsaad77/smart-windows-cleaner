import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { App } from '../App';
import { IpcClient } from '../ipc/client';
import { MockTransport } from '../ipc/transport';
import {
  IpcRequest,
  IpcResponse,
  SystemStatusDto,
  ScanSummaryDto,
  CandidateExplainabilityDto,
  QuarantineItemDto,
  AuditEntryDto,
  StorageSummaryDto,
  IpcErrorCodes,
} from '../types/ipc';

describe('M3.10 — Full Desktop End-to-End Workflow & 10 Failure Scenarios', () => {
  let transport: MockTransport;
  let client: IpcClient;

  const mockSystemStatus: SystemStatusDto = {
    os_version: 'Windows 11 Pro 64-bit (Build 22631)',
    is_elevated: false,
    uac_level: 'prompt',
    quarantine_vault_path: 'C:\\ProgramData\\SmartCleaner\\Quarantine',
    quarantine_item_count: 1,
    quarantine_total_bytes: 524288,
  };

  const mockStorageSummary: StorageSummaryDto = {
    drives: [
      {
        mount_point: 'C:\\',
        total_bytes: 512000000000,
        free_bytes: 128000000000,
        available_bytes: 128000000000,
      },
    ],
    winsxs_protection: {
      path: 'C:\\Windows\\WinSxS',
      is_protected: true,
      reason: 'Windows Component Store protected by hard safety rule',
    },
  };

  const candidateA: CandidateExplainabilityDto = {
    id: 'cand-chrome-1',
    path: 'C:\\Users\\User\\AppData\\Local\\Temp\\stale_cache.tmp',
    size_bytes: 1048576,
    category: 'Browser Cache',
    app_owner: 'Google Chrome',
    app_confidence: 'publisher_directory',
    risk_score: 15,
    risk_band: 'Safe',
    safety_verdict: 'auto_quarantine',
    can_quarantine: true,
    allowed_reasons: ['Safe temporary file recreatable by application'],
    blocked_reasons: [],
    is_pe: false,
    is_signed: false,
    is_in_use: false,
    is_hidden_or_system: false,
    selected: true,
    risk_factors: [
      { name: 'TEMP_PATH', weight: 15, reason: 'Located in standard user temporary folder' },
    ],
    local_rules: [
      {
        rule_id: 'USER_TEMP',
        category: 'User Temp',
        confidence: 'high',
        reclaim_estimate_bytes: 1048576,
      },
    ],
  };

  const candidateProtected: CandidateExplainabilityDto = {
    id: 'cand-kernel-sys',
    path: 'C:\\Windows\\System32\\drivers\\kernel_driver.sys',
    size_bytes: 2097152,
    category: 'System Driver',
    app_owner: 'Microsoft Windows',
    app_confidence: 'direct_key',
    risk_score: 100,
    risk_band: 'Protected',
    safety_verdict: 'never_delete',
    can_quarantine: false,
    allowed_reasons: [],
    blocked_reasons: ['CRITICAL_OS_DRIVER: Kernel drivers are permanently protected by Safety Engine.'],
    is_pe: true,
    is_signed: true,
    is_in_use: true,
    is_hidden_or_system: true,
    selected: false,
    risk_factors: [
      { name: 'DRIVER', weight: 50, reason: 'Kernel driver file' },
      { name: 'SYSTEM_FILE', weight: 50, reason: 'Protected operating system component' },
    ],
    local_rules: [],
  };

  const mockScanSummary: ScanSummaryDto = {
    session_id: 'sess-e2e-101',
    total_files_scanned: 1100,
    total_candidates_found: 2,
    total_reclaimable_bytes: 1048576,
    auto_eligible_bytes: 1048576,
    user_confirm_bytes: 0,
    blocked_bytes: 2097152,
    categories: [
      { category: 'Temporary Files', count: 1, total_bytes: 1048576, eligible_quarantine_bytes: 1048576 },
      { category: 'Protected System Files', count: 1, total_bytes: 2097152, eligible_quarantine_bytes: 0 },
    ],
    elapsed_ms: 5000,
  };

  const mockVaultItems: QuarantineItemDto[] = [
    {
      item_id: 'vault-uuid-001',
      original_path: 'C:\\Users\\User\\Downloads\\old_installer.exe',
      category: 'Userland Installer',
      quarantined_size_bytes: 524288,
      sha256_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      quarantined_at: '2026-09-15T12:00:00Z',
      retention_days: 7,
      days_remaining: 5,
      is_expired: false,
    },
  ];

  const mockAuditLogs: AuditEntryDto[] = [
    {
      id: 1,
      timestamp: '2026-09-15T12:00:00Z',
      operation: 'quarantine',
      target_path: 'C:\\Users\\User\\Downloads\\old_installer.exe',
      success: true,
      details: 'Quarantined to vault-uuid-001 with pre-move SHA-256 receipt',
    },
  ];

  beforeEach(() => {
    transport = new MockTransport();
    client = new IpcClient({ transport });

    // Standard query handlers
    transport.registerHandler('get_system_status', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: mockSystemStatus,
    }));

    transport.registerHandler('get_storage_summary', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: mockStorageSummary,
    }));

    transport.registerHandler('get_cleanup_candidates', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: [candidateA, candidateProtected],
    }));

    transport.registerHandler('get_quarantine_contents', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: mockVaultItems,
    }));

    transport.registerHandler('get_audit_history', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: mockAuditLogs,
    }));

    transport.registerHandler('get_scan_summary', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: mockScanSummary,
    }));
  });

  describe('Part 1: Complete Golden-Path Lifecycle End-to-End', () => {
    it('executes full lifecycle: launch -> connect -> dashboard -> configure scan -> run scan -> inspect results -> explainability -> quarantine -> vault restore -> audit log -> dashboard refresh', async () => {
      // 1. Launch & Connection
      render(<App client={client} initialRoute="dashboard" />);

      await waitFor(() => {
        expect(screen.getByText('Core Connected')).toBeInTheDocument();
        expect(screen.getByText('System Intelligence Dashboard')).toBeInTheDocument();
      });

      // 2. Dashboard KPIs
      expect(screen.getByText('Windows 11 Pro 64-bit (Build 22631)')).toBeInTheDocument();
      expect(screen.getByText('Potential Reclaimable Space')).toBeInTheDocument();

      // 3. Navigate to Scan View
      fireEvent.click(screen.getByRole('button', { name: /^scan$/i }));

      await waitFor(() => {
        expect(screen.getByText('Configure Filesystem Scan')).toBeInTheDocument();
      });

      // 4. Configure & Start Scan
      let scanStarted = false;
      transport.registerHandler('start_scan', (req: IpcRequest): IpcResponse => {
        scanStarted = true;
        return {
          id: req.id,
          status: 'ok',
          data: { session_id: 'sess-e2e-101' },
        };
      });

      fireEvent.click(screen.getByRole('button', { name: /^start scan$/i }));
      expect(scanStarted).toBe(true);

      // 5. Scan Progress
      act(() => {
        transport.emit({
          type: 'scan_progress',
          session_id: 'sess-e2e-101',
          elapsed_ms: 800,
          files_scanned: 400,
          current_path: 'C:\\Users\\User\\AppData\\Local\\Temp\\stale_cache.tmp',
          current_category: 'Temporary Files',
          candidates_found: 1,
          estimated_reclaimable_bytes: 1048576,
        });
      });

      await waitFor(() => {
        expect(screen.getByText(/Scan In Progress/i)).toBeInTheDocument();
      });

      // 6. Scan Completion
      act(() => {
        transport.emit({
          type: 'scan_completed',
          summary: mockScanSummary,
        });
      });

      await waitFor(() => {
        expect(screen.getByText(/Scan Completed Successfully/i)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /view cleanup candidates/i })).toBeInTheDocument();
      });

      // Navigate to Results
      fireEvent.click(screen.getByRole('button', { name: /view cleanup candidates/i }));

      // 7. Results View: Candidates listed
      await waitFor(() => {
        expect(screen.getByText('Cleanup Candidates & Explainability')).toBeInTheDocument();
        expect(screen.getByText('stale_cache.tmp')).toBeInTheDocument();
        expect(screen.getByText('kernel_driver.sys')).toBeInTheDocument();
      });

      // 8. Explainability Drawer
      fireEvent.click(screen.getByText('stale_cache.tmp'));

      await waitFor(() => {
        expect(screen.getByRole('dialog', { name: /candidate explainability details/i })).toBeInTheDocument();
        expect(screen.getByText('Identity & Provenance')).toBeInTheDocument();
        expect(screen.getAllByText('Google Chrome').length).toBeGreaterThanOrEqual(1);
        expect(screen.getByText('USER_TEMP')).toBeInTheDocument();
      });

      // Close drawer
      fireEvent.click(screen.getByLabelText(/close explainability panel/i));

      await waitFor(() => {
        expect(screen.queryByRole('dialog', { name: /candidate explainability details/i })).not.toBeInTheDocument();
      });

      // 9. Select & Quarantine
      const quarantineBtn = screen.getByRole('button', { name: /quarantine selected/i });
      expect(quarantineBtn).toBeEnabled();
      fireEvent.click(quarantineBtn);

      // Modal open
      await waitFor(() => {
        expect(screen.getByText(/Quarantine 1 Selected Files\?/i)).toBeInTheDocument();
      });

      let quarantineExecuted = false;
      transport.registerHandler('quarantine_selected', (req: IpcRequest): IpcResponse => {
        quarantineExecuted = true;
        return {
          id: req.id,
          status: 'ok',
          data: {
            quarantined: [
              {
                item_id: 'vault-uuid-002',
                original_path: candidateA.path,
                category: candidateA.category,
                quarantined_size_bytes: candidateA.size_bytes,
                sha256_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
                quarantined_at: '2026-09-17T12:00:00Z',
                retention_days: 7,
                days_remaining: 7,
                is_expired: false,
              },
            ],
            blocked: [],
            failed: [],
          },
        };
      });

      fireEvent.click(screen.getByRole('button', { name: /quarantine 1 files/i }));

      await waitFor(() => {
        expect(quarantineExecuted).toBe(true);
        expect(screen.getByText('Quarantine Operation Result')).toBeInTheDocument();
      });

      // 10. Open Quarantine Vault
      fireEvent.click(screen.getByRole('button', { name: /open quarantine vault/i }));

      await waitFor(() => {
        expect(screen.getByText(/Quarantine Vault & Restoration/i)).toBeInTheDocument();
        expect(screen.getByText('old_installer.exe')).toBeInTheDocument();
      });

      // 11. Restore an Item
      let restoreExecuted = false;
      transport.registerHandler('restore_quarantine_item', (req: IpcRequest): IpcResponse => {
        restoreExecuted = true;
        return {
          id: req.id,
          status: 'ok',
          data: {
            item_id: 'vault-uuid-001',
            restored_to: 'C:\\Users\\User\\Downloads\\old_installer.exe',
            file_name: 'old_installer.exe',
            sha256: mockVaultItems[0].sha256_hash,
            bytes_restored: mockVaultItems[0].quarantined_size_bytes,
          },
        };
      });

      const restoreButtons = screen.getAllByTitle(/restore this file to its original/i);
      fireEvent.click(restoreButtons[0]);

      await waitFor(() => {
        expect(screen.getByText('Restore Quarantined File')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByRole('button', { name: /confirm restore/i }));

      await waitFor(() => {
        expect(restoreExecuted).toBe(true);
      });

      // 12. Audit Logs View
      fireEvent.click(screen.getByRole('button', { name: /logs & audit/i }));

      await waitFor(() => {
        expect(screen.getByText('Audit & Security Logs')).toBeInTheDocument();
        expect(screen.getByText('SHA-256 Verified Audit Journal')).toBeInTheDocument();
        expect(screen.getByText(/old_installer\.exe/)).toBeInTheDocument();
      });

      // 13. Return to Dashboard
      fireEvent.click(screen.getByRole('button', { name: /dashboard/i }));

      await waitFor(() => {
        expect(screen.getByText('System Intelligence Dashboard')).toBeInTheDocument();
        expect(screen.getByText('Core Connected')).toBeInTheDocument();
      });
    });
  });

  describe('Part 2: 10 Explicit Failure Scenarios Validation', () => {
    // 1. Core Unavailable
    it('Scenario 1: Core Unavailable — shows initialization error and reconnect trigger', async () => {
      const failingTransport = new MockTransport();
      failingTransport.setConnected(false);
      const failingClient = new IpcClient({ transport: failingTransport });

      render(<App client={failingClient} initialRoute="dashboard" />);

      await waitFor(() => {
        expect(screen.getByText('Core Initialization Error')).toBeInTheDocument();
        expect(screen.getByText(/Native core process is not running/)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /reconnect native core/i })).toBeInTheDocument();
      });
    });

    // 2. Elevation Required
    it('Scenario 2: Elevation Required — triggers UAC Elevation Modal on permission denial', async () => {
      transport.registerHandler('start_scan', (req: IpcRequest): IpcResponse => ({
        id: req.id,
        status: 'error',
        error: {
          code: IpcErrorCodes.ELEVATION_REQUIRED,
          message: 'Operation requires elevated administrator privileges',
          details: { required_for: 'C:\\Windows\\Temp' },
        },
      }));

      render(<App client={client} initialRoute="scan" />);

      await waitFor(() => {
        expect(screen.getByText('Core Connected')).toBeInTheDocument();
        expect(screen.getByText('Configure Filesystem Scan')).toBeInTheDocument();
      });

      const startBtn = screen.getByRole('button', { name: /^start scan$/i });
      expect(startBtn).not.toBeDisabled();
      fireEvent.click(startBtn);

      await waitFor(() => {
        expect(screen.getByText('Administrator Elevation Required')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /request administrator access/i })).toBeInTheDocument();
      });
    });

    // 3. Protected File (Safety Engine Authority)
    it('Scenario 3: Protected File — Safety Engine disables selection with lock icon and NeverDelete rules', async () => {
      render(<App client={client} initialRoute="results" />);

      await waitFor(() => {
        expect(screen.getByText('kernel_driver.sys')).toBeInTheDocument();
      });

      expect(screen.getByTitle('Protected by Safety Engine: Cannot be selected for removal')).toBeInTheDocument();

      fireEvent.click(screen.getByText('kernel_driver.sys'));

      await waitFor(() => {
        expect(screen.getByText(/Why Quarantine Is Prohibited:/i)).toBeInTheDocument();
        expect(screen.getByText(/Kernel drivers are permanently protected by Safety Engine/i)).toBeInTheDocument();
      });
    });

    // 4. File in Use
    it('Scenario 4: File in Use — pre-flight gate reports process lock and keeps source untouched', async () => {
      transport.registerHandler('quarantine_selected', (req: IpcRequest): IpcResponse => ({
        id: req.id,
        status: 'ok',
        data: {
          quarantined: [],
          blocked: [
            {
              path: candidateA.path,
              reason: 'FILE_IN_USE: Target is currently locked by a running process (Google Chrome).',
            },
          ],
          failed: [],
        },
      }));

      render(<App client={client} initialRoute="results" />);

      await waitFor(() => {
        expect(screen.getByText('stale_cache.tmp')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByRole('button', { name: /quarantine selected/i }));

      await waitFor(() => {
        expect(screen.getByText(/Quarantine 1 Selected Files\?/i)).toBeInTheDocument();
      });

      fireEvent.click(screen.getByRole('button', { name: /quarantine 1 files/i }));

      await waitFor(() => {
        expect(screen.getByText('Quarantine Operation Result')).toBeInTheDocument();
        expect(screen.getByText(/Target is currently locked by a running process/i)).toBeInTheDocument();
      });
    });

    // 5. State Drift
    it('Scenario 5: State Drift — aborts when file changes size/mtime between scan and quarantine', async () => {
      transport.registerHandler('quarantine_selected', (req: IpcRequest): IpcResponse => ({
        id: req.id,
        status: 'ok',
        data: {
          quarantined: [],
          blocked: [
            {
              path: candidateA.path,
              reason: 'STATE_DRIFT: File content or size modified since initial discovery scan.',
            },
          ],
          failed: [],
        },
      }));

      render(<App client={client} initialRoute="results" />);

      await waitFor(() => {
        expect(screen.getByText('stale_cache.tmp')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByRole('button', { name: /quarantine selected/i }));

      await waitFor(() => {
        expect(screen.getByText(/Quarantine 1 Selected Files\?/i)).toBeInTheDocument();
      });

      fireEvent.click(screen.getByRole('button', { name: /quarantine 1 files/i }));

      await waitFor(() => {
        expect(screen.getByText('Quarantine Operation Result')).toBeInTheDocument();
        expect(screen.getByText(/File content or size modified/i)).toBeInTheDocument();
      });
    });

    // 6. Source Disappears
    it('Scenario 6: Source Disappears — reports source missing without corrupting vault', async () => {
      transport.registerHandler('quarantine_selected', (req: IpcRequest): IpcResponse => ({
        id: req.id,
        status: 'ok',
        data: {
          quarantined: [],
          blocked: [],
          failed: [
            {
              path: candidateA.path,
              error: 'FILE_NOT_FOUND: Source file no longer exists at original path.',
            },
          ],
        },
      }));

      render(<App client={client} initialRoute="results" />);

      await waitFor(() => {
        expect(screen.getByText('stale_cache.tmp')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByRole('button', { name: /quarantine selected/i }));

      await waitFor(() => {
        expect(screen.getByText(/Quarantine 1 Selected Files\?/i)).toBeInTheDocument();
      });

      fireEvent.click(screen.getByRole('button', { name: /quarantine 1 files/i }));

      await waitFor(() => {
        expect(screen.getByText('Quarantine Operation Result')).toBeInTheDocument();
        expect(screen.getByText(/Source file no longer exists at original path/i)).toBeInTheDocument();
      });
    });

    // 7. Quarantine Failure (I/O Error)
    it('Scenario 7: Quarantine Failure — shows structured error with source left untouched', async () => {
      transport.registerHandler('quarantine_selected', (req: IpcRequest): IpcResponse => ({
        id: req.id,
        status: 'ok',
        data: {
          quarantined: [],
          blocked: [],
          failed: [
            {
              path: candidateA.path,
              error: 'IO_ERROR: Access is denied (OS Error 5). Source left intact.',
            },
          ],
        },
      }));

      render(<App client={client} initialRoute="results" />);

      await waitFor(() => {
        expect(screen.getByText('stale_cache.tmp')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByRole('button', { name: /quarantine selected/i }));

      await waitFor(() => {
        expect(screen.getByText(/Quarantine 1 Selected Files\?/i)).toBeInTheDocument();
      });

      fireEvent.click(screen.getByRole('button', { name: /quarantine 1 files/i }));

      await waitFor(() => {
        expect(screen.getByText('Quarantine Operation Result')).toBeInTheDocument();
        expect(screen.getByText(/Access is denied \(OS Error 5\)\. Source left intact\./i)).toBeInTheDocument();
      });
    });

    // 8. Restore Conflict (Destination Exists)
    it('Scenario 8: Restore Conflict — destination already exists triggers collision error banner', async () => {
      transport.registerHandler('restore_quarantine_item', (req: IpcRequest): IpcResponse => ({
        id: req.id,
        status: 'error',
        error: {
          code: IpcErrorCodes.RESTORE_CONFLICT,
          message: 'Original destination already has a file with this name',
          details: { destination: mockVaultItems[0].original_path },
        },
      }));

      render(<App client={client} initialRoute="quarantine" />);

      await waitFor(() => {
        expect(screen.getByText('old_installer.exe')).toBeInTheDocument();
      });

      const restoreButtons = screen.getAllByTitle(/restore this file to its original/i);
      fireEvent.click(restoreButtons[0]);

      await waitFor(() => {
        expect(screen.getByText('Restore Quarantined File')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByRole('button', { name: /confirm restore/i }));

      await waitFor(() => {
        expect(screen.getByRole('status')).toBeInTheDocument();
        expect(screen.getByText(/Original destination already has a file with this name/i)).toBeInTheDocument();
      });
    });

    // 9. Integrity Failure (Hash Mismatch)
    it('Scenario 9: Integrity Failure — corrupted vault file aborts restore on SHA-256 mismatch', async () => {
      transport.registerHandler('restore_quarantine_item', (req: IpcRequest): IpcResponse => ({
        id: req.id,
        status: 'error',
        error: {
          code: 'HASH_MISMATCH',
          message: 'Cryptographic hash mismatch: Vault contents modified or corrupted',
          details: { expected: mockVaultItems[0].sha256_hash, actual: 'deadbeef' },
        },
      }));

      render(<App client={client} initialRoute="quarantine" />);

      await waitFor(() => {
        expect(screen.getByText('old_installer.exe')).toBeInTheDocument();
      });

      const restoreButtons = screen.getAllByTitle(/restore this file to its original/i);
      fireEvent.click(restoreButtons[0]);

      await waitFor(() => {
        expect(screen.getByText('Restore Quarantined File')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByRole('button', { name: /confirm restore/i }));

      await waitFor(() => {
        expect(screen.getByRole('status')).toBeInTheDocument();
        expect(screen.getByText(/Cryptographic hash mismatch: Vault contents modified or corrupted/i)).toBeInTheDocument();
      });
    });

    // 10. Insufficient Disk Space
    it('Scenario 10: Insufficient Disk Space — rejects operation before moving any bytes', async () => {
      transport.registerHandler('quarantine_selected', (req: IpcRequest): IpcResponse => ({
        id: req.id,
        status: 'error',
        error: {
          code: IpcErrorCodes.INSUFFICIENT_SPACE,
          message: 'Insufficient storage on vault partition to accept items',
          details: { needed_bytes: 52428800, available_bytes: 1048576 },
        },
      }));

      render(<App client={client} initialRoute="results" />);

      await waitFor(() => {
        expect(screen.getByText('stale_cache.tmp')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByRole('button', { name: /quarantine selected/i }));

      await waitFor(() => {
        expect(screen.getByText(/Quarantine 1 Selected Files\?/i)).toBeInTheDocument();
      });

      fireEvent.click(screen.getByRole('button', { name: /quarantine 1 files/i }));

      await waitFor(() => {
        expect(screen.getByText('Results Retrieval Failed')).toBeInTheDocument();
        expect(screen.getByText(/Insufficient storage on vault partition/i)).toBeInTheDocument();
      });
    });
  });
});
