import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect } from 'vitest';
import { AppProvider } from '../state/AppContext';
import { UpdateBanner } from '../components/UpdateBanner';
import { SettingsView } from '../views/SettingsView';
import { IpcClient } from '../ipc/client';
import { MockTransport } from '../ipc/transport';
import { UpdateStatusDto } from '../types/ipc';

describe('Stage 2 — Secure Auto-Updater UI & User Confirmation Integration', () => {
  it('renders available update banner and triggers download', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    const availableStatus: UpdateStatusDto = {
      state: 'available',
      current_version: '1.0.0',
      channel: 'stable',
      is_portable: false,
      available_update: {
        version: '1.1.0',
        channel: 'stable',
        release_date: '2026-09-18T12:00:00Z',
        architecture: 'x64',
        artifact_filename: 'SmartCleaner-Setup-1.1.0.exe',
        artifact_size: 10485760,
        sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        sha512: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        download_url: 'https://updates.local/SmartCleaner-Setup-1.1.0.exe',
        release_notes: 'Performance improvements',
        kid: 'test-key',
      },
    };

    render(
      <AppProvider client={client}>
        <UpdateBanner />
      </AppProvider>
    );

    // Simulate updater event emitted
    act(() => {
      transport.emit({ type: 'updater_status_changed', status: availableStatus });
    });

    await waitFor(() => {
      expect(screen.getByTestId('updater-available-banner')).toBeInTheDocument();
      expect(screen.getByText(/Smart Windows Cleaner v1.1.0 Available/i)).toBeInTheDocument();
    });

    const downloadBtn = screen.getByRole('button', { name: /download update/i });
    expect(downloadBtn).toBeInTheDocument();
    await userEvent.click(downloadBtn);
  });

  it('renders portable mode banner without in-place install button', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    const portableStatus: UpdateStatusDto = {
      state: 'available',
      current_version: '1.0.0',
      channel: 'stable',
      is_portable: true,
      available_update: {
        version: '1.2.0',
        channel: 'stable',
        release_date: '2026-09-18T12:00:00Z',
        architecture: 'x64',
        artifact_filename: 'SmartCleaner-Portable-1.2.0.zip',
        artifact_size: 10485760,
        sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        sha512: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        download_url: 'https://updates.local/SmartCleaner-Portable-1.2.0.zip',
        kid: 'test-key',
      },
    };

    render(
      <AppProvider client={client}>
        <UpdateBanner />
      </AppProvider>
    );

    act(() => {
      transport.emit({ type: 'updater_status_changed', status: portableStatus });
    });

    await waitFor(() => {
      expect(screen.getByTestId('updater-portable-banner')).toBeInTheDocument();
      expect(screen.getByText(/Portable Mode Active/i)).toBeInTheDocument();
      expect(screen.getByRole('link', { name: /view release/i })).toHaveAttribute(
        'href',
        'https://updates.local/SmartCleaner-Portable-1.2.0.zip'
      );
      // In-place download/install button must NOT be present
      expect(screen.queryByRole('button', { name: /download update/i })).not.toBeInTheDocument();
    });
  });

  it('renders deferred busy banner when scan or quarantine is active', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    const deferredStatus: UpdateStatusDto = {
      state: 'deferred_busy',
      current_version: '1.0.0',
      channel: 'stable',
      is_portable: false,
      deferred_reason: 'Update Ready — Restart when current operation finishes.',
    };

    render(
      <AppProvider client={client}>
        <UpdateBanner />
      </AppProvider>
    );

    act(() => {
      transport.emit({ type: 'updater_status_changed', status: deferredStatus });
    });

    await waitFor(() => {
      expect(screen.getByTestId('updater-deferred-banner')).toBeInTheDocument();
      expect(
        screen.getByText('Update Ready — Restart when current operation finishes.')
      ).toBeInTheDocument();
    });
  });

  it('renders downloaded state and allows user to trigger Restart & Apply Update', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    const downloadedStatus: UpdateStatusDto = {
      state: 'downloaded',
      current_version: '1.0.0',
      channel: 'stable',
      is_portable: false,
      available_update: {
        version: '1.1.0',
        channel: 'stable',
        release_date: '2026-09-18T12:00:00Z',
        architecture: 'x64',
        artifact_filename: 'SmartCleaner-Setup-1.1.0.exe',
        artifact_size: 10485760,
        sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        sha512: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        download_url: 'https://updates.local/SmartCleaner-Setup-1.1.0.exe',
        kid: 'test-key',
      },
    };

    render(
      <AppProvider client={client}>
        <UpdateBanner />
      </AppProvider>
    );

    act(() => {
      transport.emit({ type: 'updater_status_changed', status: downloadedStatus });
    });

    await waitFor(() => {
      expect(screen.getByTestId('updater-downloaded-banner')).toBeInTheDocument();
    });

    const restartBtn = screen.getByRole('button', { name: /restart & apply update/i });
    expect(restartBtn).toBeInTheDocument();
    await userEvent.click(restartBtn);
  });

  it('SettingsView: renders updates card and supports channel selection', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    render(
      <AppProvider client={client}>
        <SettingsView />
      </AppProvider>
    );

    await waitFor(() => {
      expect(screen.getByText(/Updates & Releases \(Ed25519 Authenticity\)/i)).toBeInTheDocument();
      expect(screen.getByText(/v1\.0\.\d+ \(Core Native Release\)/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /check for updates/i })).toBeInTheDocument();
    });

    const betaBtn = screen.getByRole('button', { name: /^beta$/i });
    expect(betaBtn).toBeInTheDocument();
    await userEvent.click(betaBtn);
  });
});
