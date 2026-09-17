import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Shell } from '../components/Shell';
import { AppProvider } from '../state/AppContext';
import { MockTransport } from '../ipc/transport';
import { IpcClient } from '../ipc/client';
import { ErrorState } from '../design-system/ErrorState';
import { ElevationModal } from '../components/ElevationModal';
import { formatIpcError } from '../ipc/errors';
import {
  IpcRequest,
  IpcResponse,
  IpcErrorCodes,
  IpcError,
  SystemStatusDto,
} from '../types/ipc';

describe('M3.9: Error / Permission UX (Explicit Error States & Elevation Triggers)', () => {
  let transport: MockTransport;
  let client: IpcClient;

  const standardSystemStatus: SystemStatusDto = {
    os_version: 'Windows 11 Pro 64-bit (Build 22631)',
    is_elevated: false,
    uac_level: 'prompt',
    quarantine_vault_path: 'C:\\ProgramData\\SmartCleaner\\Quarantine',
    quarantine_item_count: 3,
    quarantine_total_bytes: 1048576,
  };

  beforeEach(() => {
    transport = new MockTransport();
    client = new IpcClient({ transport });

    transport.registerHandler('get_system_status', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'ok',
      data: standardSystemStatus,
    }));
  });

  describe('Structured Error Mapping (formatIpcError)', () => {
    it('maps all strongly-typed IPC error codes to explicit, actionable representations', () => {
      // 1. ACCESS_DENIED
      const accessDenied = formatIpcError({
        code: IpcErrorCodes.ACCESS_DENIED,
        message: 'Denied on C:\\Windows\\System32',
      });
      expect(accessDenied.title).toBe('Access Denied');
      expect(accessDenied.requiresElevation).toBe(true);
      expect(accessDenied.suggestedAction).toMatch(/read\/write permissions.*administrator elevation/i);

      // 2. ELEVATION_REQUIRED
      const elevationReq = formatIpcError({
        code: IpcErrorCodes.ELEVATION_REQUIRED,
        message: 'UAC token required',
      });
      expect(elevationReq.title).toBe('Administrator Elevation Required');
      expect(elevationReq.requiresElevation).toBe(true);
      expect(elevationReq.suggestedAction).toMatch(/administrator privileges/i);

      // 3. FILE_IN_USE
      const fileInUse = formatIpcError({
        code: IpcErrorCodes.FILE_IN_USE,
        message: 'Handle locked by Chrome',
      });
      expect(fileInUse.title).toBe('File Is In Use By Another Process');
      expect(fileInUse.requiresElevation).toBe(false);
      expect(fileInUse.suggestedAction).toMatch(/Close the corresponding application/i);

      // 4. SOURCE_MISSING
      const sourceMissing = formatIpcError({
        code: IpcErrorCodes.SOURCE_MISSING,
        message: 'File vanished',
      });
      expect(sourceMissing.title).toBe('Source Item Not Found');
      expect(sourceMissing.suggestedAction).toMatch(/rescan/i);

      // 5. STATE_DRIFT
      const stateDrift = formatIpcError({
        code: IpcErrorCodes.STATE_DRIFT,
        message: 'Hash modified',
      });
      expect(stateDrift.title).toBe('File State Drift Detected');
      expect(stateDrift.suggestedAction).toMatch(/fresh scan/i);

      // 6. PROTECTED_ITEM
      const protectedItem = formatIpcError({
        code: IpcErrorCodes.PROTECTED_ITEM,
        message: 'Component store item',
      });
      expect(protectedItem.title).toBe('Protected System Resource');
      expect(protectedItem.suggestedAction).toMatch(/vital to Windows/i);

      // 7. QUARANTINE_FAILED
      const qFailed = formatIpcError({
        code: IpcErrorCodes.QUARANTINE_FAILED,
        message: 'Vault write error',
      });
      expect(qFailed.title).toBe('Quarantine Vault Ingestion Failed');

      // 8. RESTORE_CONFLICT
      const restoreConflict = formatIpcError({
        code: IpcErrorCodes.RESTORE_CONFLICT,
        message: 'Collision at restore path',
      });
      expect(restoreConflict.title).toBe('Restore Target Conflict');

      // 9. INSUFFICIENT_SPACE
      const spaceError = formatIpcError({
        code: IpcErrorCodes.INSUFFICIENT_SPACE,
        message: 'Only 50MB remaining',
      });
      expect(spaceError.title).toBe('Insufficient Free Disk Space');

      // 10. UNSUPPORTED_CAPABILITY
      const unsupp = formatIpcError({
        code: IpcErrorCodes.UNSUPPORTED_CAPABILITY,
        message: 'ReFS feature missing',
      });
      expect(unsupp.title).toBe('Capability Not Supported');

      // 11. INTERNAL_CORE_ERROR
      const internalErr = formatIpcError({
        code: IpcErrorCodes.INTERNAL_CORE_ERROR,
        message: 'Panic in rule engine',
      });
      expect(internalErr.title).toMatch(/Core Operation Error/);
    });
  });

  describe('ErrorState Component', () => {
    it('renders explicit error presentation with remedy and elevation button when required', () => {
      const onRetry = vi.fn();
      const onRequestElevation = vi.fn();

      const error: IpcError = {
        code: IpcErrorCodes.ACCESS_DENIED,
        message: 'Access is denied to C:\\Windows\\Temp\\system_trace.etl',
      };

      render(
        <ErrorState
          error={error}
          onRetry={onRetry}
          onRequestElevation={onRequestElevation}
        />
      );

      // Verifies title and code pill
      expect(screen.getByText('Access Denied')).toBeInTheDocument();
      expect(screen.getByText(IpcErrorCodes.ACCESS_DENIED)).toBeInTheDocument();

      // Verifies description and remedy
      expect(screen.getByText(/Access is denied to C:\\Windows\\Temp/i)).toBeInTheDocument();
      expect(screen.getByText(/Remedy:/i)).toBeInTheDocument();

      // Elevation button rendered
      const elevateBtn = screen.getByRole('button', { name: /Request Administrator Access/i });
      expect(elevateBtn).toBeInTheDocument();
      fireEvent.click(elevateBtn);
      expect(onRequestElevation).toHaveBeenCalledTimes(1);

      // Retry button rendered
      const retryBtn = screen.getByRole('button', { name: /Retry Action/i });
      expect(retryBtn).toBeInTheDocument();
      fireEvent.click(retryBtn);
      expect(onRetry).toHaveBeenCalledTimes(1);
    });

    it('renders standard non-elevation error state without elevation button', () => {
      const error: IpcError = {
        code: IpcErrorCodes.FILE_IN_USE,
        message: 'Target file is locked by process svchost.exe (PID 1044)',
      };

      render(<ErrorState error={error} onRetry={vi.fn()} />);

      expect(screen.getByText('File Is In Use By Another Process')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /Request Administrator Access/i })).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Retry Action/i })).toBeInTheDocument();
    });
  });

  describe('Elevation Modal & UAC Workflow', () => {
    it('opens elevation modal from header button and handles UAC elevation successfully', async () => {
      render(
        <AppProvider client={client} initialRoute="dashboard">
          <Shell />
        </AppProvider>
      );

      // Initially standard user
      await waitFor(() => {
        expect(screen.getByText('Standard User')).toBeInTheDocument();
      });

      // Click "Elevate" in header
      const elevateHeaderBtn = screen.getByRole('button', { name: /^Elevate$/i });
      fireEvent.click(elevateHeaderBtn);

      // Modal appears
      await waitFor(() => {
        expect(screen.getByText(/Administrator Elevation Request \(Windows UAC\)/i)).toBeInTheDocument();
        expect(screen.getByText('Locations Unlocked by UAC')).toBeInTheDocument();
        expect(screen.getByText('Safety Boundaries (Permanent)')).toBeInTheDocument();
        expect(screen.getByText(/Safety Architecture Guarantee:/i)).toBeInTheDocument();
      });

      // Confirm elevation
      const confirmElevateBtn = screen.getByRole('button', { name: /Elevate via UAC Prompt/i });
      fireEvent.click(confirmElevateBtn);

      // Modal closes and status changes to Administrator
      await waitFor(() => {
        expect(screen.queryByText(/Administrator Elevation Request/i)).not.toBeInTheDocument();
        expect(screen.getByText(/Administrator \(UAC Active\)/i)).toBeInTheDocument();
      });
    });

    it('handles UAC cancellation / failure with clear notification banner', async () => {
      // Mock failure for request_elevation
      transport.registerHandler('request_elevation', (req: IpcRequest): IpcResponse => ({
        id: req.id,
        status: 'error',
        error: {
          code: 'ACCESS_DENIED',
          message: 'The user canceled the Windows UAC elevation consent prompt (ERROR_CANCELLED).',
        },
      }));

      render(
        <AppProvider client={client} initialRoute="dashboard">
          <Shell />
        </AppProvider>
      );

      await waitFor(() => {
        expect(screen.getByText('Standard User')).toBeInTheDocument();
      });

      // Click "Elevate"
      fireEvent.click(screen.getByRole('button', { name: /^Elevate$/i }));

      // Confirm elevate
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /Elevate via UAC Prompt/i })).toBeInTheDocument();
      });
      fireEvent.click(screen.getByRole('button', { name: /Elevate via UAC Prompt/i }));

      // Error message shown inside modal and notification
      await waitFor(() => {
        expect(screen.getByText(/Elevation Failed or Dismissed:/i)).toBeInTheDocument();
        expect(
          screen.getAllByText(/The user canceled the Windows UAC elevation consent prompt/i).length
        ).toBe(2);
      });

      // Close modal
      fireEvent.click(screen.getByRole('button', { name: /Remain in Standard User Mode/i }));

      await waitFor(() => {
        expect(screen.queryByText(/Locations Unlocked by UAC/i)).not.toBeInTheDocument();
      });

      // Still in safe standard user mode
      expect(screen.getByText('Standard User')).toBeInTheDocument();
    });
  });

  describe('ElevationModal Component Unit', () => {
    it('renders with custom reason and handles dismissal', async () => {
      const onClose = vi.fn();
      const onConfirm = vi.fn().mockResolvedValue(undefined);

      render(
        <ElevationModal
          isOpen={true}
          onClose={onClose}
          onConfirm={onConfirm}
          reason="Access Denied on C:\Windows\Temp during active scan"
        />
      );

      expect(screen.getByText(/Access Denied on C:\\Windows\\Temp during active scan/i)).toBeInTheDocument();

      const cancelBtn = screen.getByRole('button', { name: /Remain in Standard User Mode/i });
      fireEvent.click(cancelBtn);
      expect(onClose).toHaveBeenCalledTimes(1);
    });
  });
});
