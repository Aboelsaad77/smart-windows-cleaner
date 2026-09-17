import { describe, it, expect, vi } from 'vitest';
import { IpcClient, IpcClientError } from '../ipc/client';
import { MockTransport } from '../ipc/transport';
import { IpcRequest, IpcResponse } from '../types/ipc';

describe('IPC Client Layer', () => {
  it('correlates requests with matching response IDs', async () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    const status = await client.getSystemStatus();
    expect(status).toBeDefined();
    expect(status.os_version).toContain('Windows 11');
  });

  it('rejects when response ID does not match request ID', async () => {
    const transport = new MockTransport();
    // Intentionally corrupt ID in handler
    transport.registerHandler('get_system_status', (_req: IpcRequest): IpcResponse => ({
      id: 'mismatched-id-999',
      status: 'ok',
      data: { os_version: 'bad' },
    }));

    const client = new IpcClient({ transport });
    await expect(client.getSystemStatus()).rejects.toThrow(IpcClientError);
    await expect(client.getSystemStatus()).rejects.toMatchObject({
      code: 'CORRELATION_ERROR',
    });
  });

  it('handles structured IPC errors without losing error code or details', async () => {
    const transport = new MockTransport();
    transport.registerHandler('quarantine_selected', (req: IpcRequest): IpcResponse => ({
      id: req.id,
      status: 'error',
      error: {
        code: 'PROTECTED_ITEM',
        message: 'Cannot quarantine protected Windows directory: C:\\Windows\\System32',
        details: { path: 'C:\\Windows\\System32', rule: 'SYSTEM_FILE' },
      },
    }));

    const client = new IpcClient({ transport });
    try {
      await client.quarantineSelected(['C:\\Windows\\System32']);
      expect.unreachable('Should have thrown IpcClientError');
    } catch (err) {
      expect(err).toBeInstanceOf(IpcClientError);
      const clientErr = err as IpcClientError;
      expect(clientErr.code).toBe('PROTECTED_ITEM');
      expect(clientErr.message).toContain('Cannot quarantine protected Windows directory');
      expect(clientErr.details).toEqual({ path: 'C:\\Windows\\System32', rule: 'SYSTEM_FILE' });
    }
  });

  it('enforces request timeout when core is unresponsive', async () => {
    const slowTransport = {
      send: () => new Promise<IpcResponse>(() => {}), // never resolves
      subscribe: () => () => {},
      isConnected: () => true,
    };

    const client = new IpcClient({ transport: slowTransport, timeoutMs: 50 });
    await expect(client.getSystemStatus()).rejects.toMatchObject({
      code: 'REQUEST_TIMEOUT',
    });
  });

  it('manages event subscription and unsubscription lifecycle cleanly', () => {
    const transport = new MockTransport();
    const client = new IpcClient({ transport });

    const listener = vi.fn();
    const unsubscribe = client.on('scan_progress', listener);

    // Emit event
    transport.emit({
      type: 'scan_progress',
      session_id: 'sess-1',
      elapsed_ms: 120,
      files_scanned: 42,
      current_path: 'C:\\test',
      current_category: 'caches',
      candidates_found: 3,
      estimated_reclaimable_bytes: 4096,
    });

    expect(listener).toHaveBeenCalledTimes(1);
    expect(listener).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'scan_progress',
        files_scanned: 42,
      })
    );

    // Unsubscribe and emit again
    unsubscribe();
    transport.emit({
      type: 'scan_progress',
      session_id: 'sess-1',
      elapsed_ms: 240,
      files_scanned: 84,
      current_path: 'C:\\test2',
      current_category: 'caches',
      candidates_found: 6,
      estimated_reclaimable_bytes: 8192,
    });

    // Should not receive second event
    expect(listener).toHaveBeenCalledTimes(1);
  });
});
