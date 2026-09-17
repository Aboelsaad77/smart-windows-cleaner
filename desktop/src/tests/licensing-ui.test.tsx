import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { AppProvider } from '../state/AppContext';
import { SettingsView } from '../views/SettingsView';
import { IpcClient } from '../ipc/client';
import { MockTransport } from '../ipc/transport';

describe('SettingsView — Licensing & Entitlements UI Integration', () => {
  let transport: MockTransport;
  let client: IpcClient;

  beforeEach(() => {
    transport = new MockTransport();
    client = new IpcClient({ transport });
  });

  function renderSettings() {
    return render(
      <AppProvider client={client}>
        <SettingsView />
      </AppProvider>
    );
  }

  it('renders Community Edition by default with uncompromised safety guarantee', async () => {
    renderSettings();

    await waitFor(() => {
      expect(screen.getByText(/Current Edition: Community Edition/i)).toBeInTheDocument();
      expect(screen.getByText('FREE COMMUNITY')).toBeInTheDocument();
    });

    // Reassurance banner must be explicitly visible
    expect(
      screen.getByText(/Unconditional Safety Invariant/i)
    ).toBeInTheDocument();
  });

  it('toggles the activation form when Activate Pro is clicked', async () => {
    renderSettings();

    const activateBtn = await screen.findByRole('button', { name: /activate pro/i });
    fireEvent.click(activateBtn);

    expect(screen.getByText(/Activate Pro License/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /web device flow/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /manual token \/ air-gap/i })).toBeInTheDocument();
  });

  it('activates Pro via manual token entry and displays Pro status', async () => {
    renderSettings();

    const activateBtn = await screen.findByRole('button', { name: /activate pro/i });
    fireEvent.click(activateBtn);

    // Switch to manual token tab
    const manualTab = screen.getByRole('button', { name: /manual token \/ air-gap/i });
    fireEvent.click(manualTab);

    const textarea = screen.getByPlaceholderText(/eyJzY2hlbWFfdmVyc2lvbi/i);
    fireEvent.change(textarea, { target: { value: '{"plan": "pro"}' } });

    const submitBtn = screen.getByRole('button', { name: /verify & activate/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText(/Current Edition: Pro Edition/i)).toBeInTheDocument();
      expect(screen.getByText(/PRO ACTIVE/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /deactivate license/i })).toBeInTheDocument();
    });
  });

  it('supports license deactivation returning to Community Edition', async () => {
    renderSettings();

    // First activate
    const activateBtn = await screen.findByRole('button', { name: /activate pro/i });
    fireEvent.click(activateBtn);
    fireEvent.click(screen.getByRole('button', { name: /manual token \/ air-gap/i }));
    fireEvent.change(screen.getByPlaceholderText(/eyJzY2hlbWFfdmVyc2lvbi/i), { target: { value: '{"plan": "pro"}' } });
    fireEvent.click(screen.getByRole('button', { name: /verify & activate/i }));

    const deactivateBtn = await screen.findByRole('button', { name: /deactivate license/i });
    fireEvent.click(deactivateBtn);

    await waitFor(() => {
      expect(screen.getByText(/Current Edition: Community Edition/i)).toBeInTheDocument();
      expect(screen.getByText('FREE COMMUNITY')).toBeInTheDocument();
    });
  });
});
