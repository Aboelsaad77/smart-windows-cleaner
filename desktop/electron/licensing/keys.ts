/**
 * Smart Windows Cleaner — Pinned Licensing Public Keys (Stage 3 B3)
 *
 * Contains ONLY public verification keys.
 * NEVER ship private signing keys in client binaries.
 */

import { PinnedLicenseKey } from '../../src/types/licensing';

export const PINNED_LICENSE_KEYS: Record<string, PinnedLicenseKey> = {
  'smartcleaner-license-2026-1': {
    kid: 'smartcleaner-license-2026-1',
    algorithm: 'ed25519',
    publicKeyPem: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA4P2+Q3tD1/rS7KxN9Vz8Pz8F3XkL5dZ9+8L8m7m5Z3U=
-----END PUBLIC KEY-----`,
    validFrom: '2026-09-01T00:00:00Z',
    status: 'active',
    description: 'Production Smart Cleaner Licensing Authority Key 2026-1',
  },
  'smartcleaner-license-2026-2': {
    kid: 'smartcleaner-license-2026-2',
    algorithm: 'ed25519',
    publicKeyPem: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA2/tB3rL5D3m5F8pQ2xZ7V9W4kL1nP6sM8vX3T2Y9z8I=
-----END PUBLIC KEY-----`,
    validFrom: '2026-12-01T00:00:00Z',
    status: 'transition',
    description: 'Next Rotation Smart Cleaner Licensing Authority Key 2026-2',
  },
};

export function lookupPinnedLicenseKey(
  kid: string,
  keyStore: Record<string, PinnedLicenseKey> = PINNED_LICENSE_KEYS
): PinnedLicenseKey | null {
  const key = keyStore[kid];
  if (!key) return null;
  if (key.status === 'retired') return null;
  return key;
}
