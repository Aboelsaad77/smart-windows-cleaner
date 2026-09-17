/**
 * Smart Windows Cleaner — Pinned Cryptographic Public Keys for Release Authenticity
 *
 * Security Model:
 * - Update manifests MUST be signed with an Ed25519 private key corresponding to a pinned key below.
 * - Key ID ('kid') in the manifest directs lookup in this pinned table.
 * - Unknown key IDs fail closed (UNKNOWN_SIGNING_KEY).
 * - Key rotation is supported by maintaining 'active', 'transition', and 'retired' keys.
 * - PRIVATE KEYS ARE STRICTLY EXCLUDED FROM THE APPLICATION CODEBASE.
 */

import { PinnedSigningKey } from '../../src/types/updater';

export const PINNED_SIGNING_KEYS: Record<string, PinnedSigningKey> = {
  // Primary 2026 Release Signing Key
  'smartcleaner-release-2026-1': {
    kid: 'smartcleaner-release-2026-1',
    algorithm: 'ed25519',
    publicKeyPem: [
      '-----BEGIN PUBLIC KEY-----',
      'MCowBQYDK2VwAyEA+57X/ekyAT46Gf8ncu/LHnqiL3Q5iAs+rQ5TCffk1f8=',
      '-----END PUBLIC KEY-----',
    ].join('\n'),
    validFrom: '2026-09-01T00:00:00Z',
    description: 'Smart Windows Cleaner Primary 2026 Ed25519 Release Key',
    status: 'active',
  },

  // Planned Rotation Key (Demonstrates seamless key rotation allowlist)
  'smartcleaner-release-2026-rotation': {
    kid: 'smartcleaner-release-2026-rotation',
    algorithm: 'ed25519',
    publicKeyPem: [
      '-----BEGIN PUBLIC KEY-----',
      'MCowBQYDK2VwAyEAhnAAPygdJKgSMQO94LnwqRx7PhZfbRyEiEZEDFMFBrw=',
      '-----END PUBLIC KEY-----',
    ].join('\n'),
    validFrom: '2026-09-15T00:00:00Z',
    description: 'Smart Windows Cleaner 2026 Transition Key for Rotation',
    status: 'transition',
  },
};

/**
 * Lookup a trusted public key by key ID.
 * Returns null if the key is unknown or explicitly retired.
 */
export function lookupPinnedKey(kid: string, keyStore: Record<string, PinnedSigningKey> = PINNED_SIGNING_KEYS): PinnedSigningKey | null {
  const key = keyStore[kid];
  if (!key) {
    return null;
  }
  if (key.status === 'retired') {
    return null;
  }
  return key;
}
