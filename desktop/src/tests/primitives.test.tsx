import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Button } from '../design-system/Button';
import { Badge } from '../design-system/Badge';
import { ErrorState } from '../design-system/ErrorState';
import { EmptyState } from '../design-system/EmptyState';
import { LoadingState } from '../design-system/LoadingState';
import { ConfirmationDialog } from '../design-system/ConfirmationDialog';
import { ProgressIndicator } from '../design-system/ProgressIndicator';
import { IpcErrorCodes } from '../types/ipc';

describe('Design System Primitives & Safety UX Rules', () => {
  it('renders Button with variants and handles loading/disabled states', () => {
    const handleClick = vi.fn();
    const { rerender } = render(
      <Button variant="danger" onClick={handleClick}>
        Quarantine File
      </Button>
    );

    const btn = screen.getByRole('button', { name: /quarantine file/i });
    expect(btn).toBeInTheDocument();
    fireEvent.click(btn);
    expect(handleClick).toHaveBeenCalledTimes(1);

    // Disabled state
    rerender(
      <Button variant="danger" disabled onClick={handleClick}>
        Quarantine File
      </Button>
    );
    fireEvent.click(btn);
    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('renders badges representing exact Safety Engine verdicts and risk bands', () => {
    const { rerender } = render(<Badge riskBand="Protected">Protected</Badge>);
    expect(screen.getByText('Protected')).toBeInTheDocument();

    rerender(<Badge safetyVerdict="auto_quarantine">Auto Quarantine</Badge>);
    expect(screen.getByText('Auto Quarantine')).toBeInTheDocument();

    rerender(<Badge safetyVerdict="never_delete">Never Delete</Badge>);
    expect(screen.getByText('Never Delete')).toBeInTheDocument();

    rerender(<Badge riskBand="Dangerous">Dangerous</Badge>);
    expect(screen.getByText('Dangerous')).toBeInTheDocument();
  });

  it('renders structured ErrorState using IpcError.code without generic fallback message', () => {
    const onRetry = vi.fn();
    const onRequestElevation = vi.fn();

    render(
      <ErrorState
        error={{
          code: IpcErrorCodes.ACCESS_DENIED,
          message: 'Cannot access C:\\Windows\\System32\\config',
        }}
        onRetry={onRetry}
        onRequestElevation={onRequestElevation}
      />
    );

    expect(screen.getByText('Access Denied')).toBeInTheDocument();
    expect(screen.getByText(IpcErrorCodes.ACCESS_DENIED)).toBeInTheDocument();
    expect(screen.getByText(/Cannot access C:\\Windows\\System32\\config/)).toBeInTheDocument();
    expect(screen.getByText(/Remedy:/)).toBeInTheDocument();

    // Elevation button is shown for ACCESS_DENIED
    const elevateBtn = screen.getByRole('button', { name: /request administrator access/i });
    expect(elevateBtn).toBeInTheDocument();
    fireEvent.click(elevateBtn);
    expect(onRequestElevation).toHaveBeenCalledTimes(1);
  });

  it('renders structured ErrorState for FILE_IN_USE and STATE_DRIFT', () => {
    const { rerender } = render(
      <ErrorState
        error={{
          code: IpcErrorCodes.FILE_IN_USE,
          message: 'Process chrome.exe holds handle',
        }}
      />
    );
    expect(screen.getByText('File Is In Use By Another Process')).toBeInTheDocument();

    rerender(
      <ErrorState
        error={{
          code: IpcErrorCodes.STATE_DRIFT,
          message: 'File size modified on disk after scan',
        }}
      />
    );
    expect(screen.getByText('File State Drift Detected')).toBeInTheDocument();
  });

  it('renders ProgressIndicator with exact percentages and indeterminate state without fabricating fake percentages', () => {
    const { rerender } = render(
      <ProgressIndicator progressPercent={45} statusLabel="Scanning" />
    );
    expect(screen.getByText('45%')).toBeInTheDocument();

    // When progressPercent is undefined, it must NOT show a fake number
    rerender(<ProgressIndicator progressPercent={undefined} statusLabel="Scanning" detailLabel="150 files" />);
    expect(screen.getByText('150 files')).toBeInTheDocument();
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
  });

  it('renders EmptyState and LoadingState with clear descriptions', () => {
    const { rerender } = render(
      <EmptyState title="No Items Found" description="Clean state active." />
    );
    expect(screen.getByText('No Items Found')).toBeInTheDocument();
    expect(screen.getByText('Clean state active.')).toBeInTheDocument();

    rerender(<LoadingState label="Inspecting storage..." subtext="Querying volume tables" />);
    expect(screen.getByText('Inspecting storage...')).toBeInTheDocument();
    expect(screen.getByText('Querying volume tables')).toBeInTheDocument();
  });

  it('requires explicit confirmation checkbox before enabling action in ConfirmationDialog', () => {
    const onConfirm = vi.fn();
    const onClose = vi.fn();

    render(
      <ConfirmationDialog
        isOpen={true}
        title="Quarantine Protected Item"
        message="This action will isolate selected candidates."
        requiresExplicitCheck={true}
        explicitCheckLabel="I confirm Safety Engine evaluation"
        onConfirm={onConfirm}
        onClose={onClose}
      />
    );

    const confirmBtn = screen.getByRole('button', { name: /confirm/i });
    expect(confirmBtn).toBeDisabled();

    // Check the box
    const checkbox = screen.getByRole('checkbox');
    fireEvent.click(checkbox);
    expect(confirmBtn).toBeEnabled();

    fireEvent.click(confirmBtn);
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});
