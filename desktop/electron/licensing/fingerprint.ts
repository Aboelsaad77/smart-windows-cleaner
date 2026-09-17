/**
 * Smart Windows Cleaner — Machine Fingerprint Generator (Stage 3 B2)
 *
 * Computes a non-reversible, deterministic SHA-256 hardware identifier
 * for machine binding without harvesting sensitive personal identifiers.
 */

import * as crypto from 'node:crypto';
import * as os from 'node:os';

let cachedDeviceId: string | null = null;
let deviceIdOverride: string | null = null;

export function setDeviceIdOverride(override: string | null): void {
  deviceIdOverride = override;
  cachedDeviceId = null;
}

export function getDeviceId(): string {
  if (deviceIdOverride) {
    return deviceIdOverride;
  }

  if (cachedDeviceId) {
    return cachedDeviceId;
  }

  try {
    const platform = os.platform();
    const arch = os.arch();
    const cpus = os.cpus();
    const cpuModel = cpus.length > 0 ? cpus[0].model : 'unknown-cpu';
    const cpuCount = cpus.length;
    // Round total memory to nearest GiB to tolerate dynamic memory ballooning in VMs
    const memGiB = Math.round(os.totalmem() / (1024 * 1024 * 1024));
    const hostname = os.hostname();

    const rawSeed = `smartcleaner:v1:${platform}:${arch}:${cpuModel}:${cpuCount}:${memGiB}:${hostname}`;
    cachedDeviceId = crypto.createHash('sha256').update(rawSeed, 'utf8').digest('hex');
    return cachedDeviceId;
  } catch {
    // Resilient fallback
    return '0000000000000000000000000000000000000000000000000000000000000000';
  }
}
