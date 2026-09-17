import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { App } from '../App';
import { IpcClient } from '../ipc/client';
import { MockTransport } from '../ipc/transport';

describe('Desktop Application Shell', () => {
  it('renders application shell with branding and navigation sidebar', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    render(<App client={client} />);

    await waitFor(() => {
      expect(screen.getByText('Core Connected')).toBeInTheDocument();
    });

    // Brand identity
    expect(screen.getByText('Smart Cleaner')).toBeInTheDocument();

    // Nav items
    expect(screen.getByRole('button', { name: /^dashboard$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^scan$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^results$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^quarantine$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^storage$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^logs & audit$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^settings$/i })).toBeInTheDocument();

    // Initial view: Dashboard
    expect(screen.getByText('System Intelligence Dashboard')).toBeInTheDocument();
  });

  it('navigates cleanly across all shell views', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    render(<App client={client} />);

    await waitFor(() => {
      expect(screen.getByText('Core Connected')).toBeInTheDocument();
    });

    // Navigate to Scan
    fireEvent.click(screen.getByRole('button', { name: /^scan$/i }));
    expect(screen.getByText(/Filesystem Scan/i)).toBeInTheDocument();

    // Navigate to Results
    fireEvent.click(screen.getByRole('button', { name: /^results$/i }));
    expect(screen.getByText('Cleanup Candidates & Explainability')).toBeInTheDocument();

    // Navigate to Quarantine
    fireEvent.click(screen.getByRole('button', { name: /^quarantine$/i }));
    expect(screen.getByText('Quarantine Vault & Restoration')).toBeInTheDocument();

    // Navigate to Storage
    fireEvent.click(screen.getByRole('button', { name: /^storage$/i }));
    expect(screen.getByText('Physical Storage View')).toBeInTheDocument();

    // Navigate to Logs
    fireEvent.click(screen.getByRole('button', { name: /^logs & audit$/i }));
    expect(screen.getByText('Audit & Security Logs')).toBeInTheDocument();

    // Navigate to Settings
    fireEvent.click(screen.getByRole('button', { name: /^settings$/i }));
    expect(screen.getByText('Settings & Policies')).toBeInTheDocument();
  });

  it('reflects core availability and system status in header and status bar', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    render(<App client={client} />);

    await waitFor(() => {
      expect(screen.getByText('Core Connected')).toBeInTheDocument();
      expect(screen.getAllByText(/Standard User/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText(/Windows 11/i).length).toBeGreaterThanOrEqual(1);
    });
  });

  it('handles core unavailable state and surfaces structured error state', async () => {
    const transport = new MockTransport();
    transport.setConnected(false); // Disconnected transport
    const client = new IpcClient({ transport });

    render(<App client={client} />);

    await waitFor(() => {
      expect(screen.getByText('Core Initialization Error')).toBeInTheDocument();
      expect(screen.getByText(/Native core process is not running/)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /reconnect native core/i })).toBeInTheDocument();
    });
  });
});
