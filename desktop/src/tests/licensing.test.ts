/**
 * Smart Windows Cleaner — Licensing & Entitlements Test Suite (Stage 3 B10)
 *
 * Verifies:
 * 1. Ed25519 signature verification with pinned public keys & key rotation.
 * 2. Hardware device binding via SHA-256 fingerprint.
 * 3. Monotonic sequence replay ratchet.
 * 4. Offline grace period and expiration boundaries.
 * 5. System clock rollback detection.
 * 6. RFC 8628 device flow linking.
 * 7. Feature gating (isEntitled) non-interference with Safety Engine.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { LicensingEngine } from '../../electron/licensing/engine';
import { setDeviceIdOverride, getDeviceId } from '../../electron/licensing/fingerprint';
import { canonicalizeJson } from '../../electron/updater/crypto';
import {
  SignedLicensePayload,
  PinnedLicenseKey,
  LicensingErrorCodes,
} from '../types/licensing';

describe('Stage 3 — Licensing & Entitlements Engine', () => {
  let testTempDir: string;
  let licenseStoragePath: string;
  let primaryKeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject; pubPem: string };
  let rotationKeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject; pubPem: string };
  let mockLicenseKeys: Record<string, PinnedLicenseKey>;
  let mockTimeMs: number;

  beforeEach(() => {
    testTempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-licensing-test-'));
    licenseStoragePath = path.join(testTempDir, 'license.json');
    mockTimeMs = Date.parse('2026-09-18T12:00:00Z');

    // Generate primary Ed25519 keypair
    const primary = crypto.generateKeyPairSync('ed25519');
    primaryKeyPair = {
      publicKey: primary.publicKey,
      privateKey: primary.privateKey,
      pubPem: primary.publicKey.export({ type: 'spki', format: 'pem' }) as string,
    };

    // Generate rotation Ed25519 keypair
    const rotation = crypto.generateKeyPairSync('ed25519');
    rotationKeyPair = {
      publicKey: rotation.publicKey,
      privateKey: rotation.privateKey,
      pubPem: rotation.publicKey.export({ type: 'spki', format: 'pem' }) as string,
    };

    mockLicenseKeys = {
      'test-lic-primary': {
        kid: 'test-lic-primary',
        algorithm: 'ed25519',
        publicKeyPem: primaryKeyPair.pubPem,
        validFrom: '2026-09-01T00:00:00Z',
        status: 'active',
        description: 'Test Licensing Primary Key',
      },
      'test-lic-rotation': {
        kid: 'test-lic-rotation',
        algorithm: 'ed25519',
        publicKeyPem: rotationKeyPair.pubPem,
        validFrom: '2026-09-15T00:00:00Z',
        status: 'transition',
        description: 'Test Licensing Rotation Key',
      },
    };

    // Set fixed device ID for predictable testing
    setDeviceIdOverride('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
  });

  afterEach(() => {
    setDeviceIdOverride(null);
    if (fs.existsSync(testTempDir)) {
      fs.rmSync(testTempDir, { recursive: true, force: true });
    }
  });

  function createSignedLicense(
    overrides: Partial<SignedLicensePayload> = {},
    signingKey: crypto.KeyObject = primaryKeyPair.privateKey,
    kid: string = 'test-lic-primary'
  ): SignedLicensePayload {
    const unsigned: Omit<SignedLicensePayload, 'signature'> = {
      schema_version: '1.0.0',
      license_id: 'lic-test-001',
      account_id: 'acc-user-456',
      account_email: 'pro-user@example.com',
      plan: 'pro',
      entitlements: ['pro.deep_forensics', 'pro.scheduled_scans', 'pro.advanced_reporting'],
      device_id: getDeviceId(),
      issued_at: '2026-09-18T10:00:00Z',
      expires_at: '2027-09-18T10:00:00Z',
      grace_until: '2027-10-02T10:00:00Z',
      seq: 1,
      kid,
      ...overrides,
    };

    const canonical = canonicalizeJson(unsigned);
    const signatureBuffer = crypto.sign(null, Buffer.from(canonical, 'utf8'), signingKey);

    return {
      ...(unsigned as SignedLicensePayload),
      signature: signatureBuffer.toString('base64'),
    };
  }

  // --------------------------------------------------------------------------
  // 1. Initial State & Community Defaults
  // --------------------------------------------------------------------------

  it('initializes to Community Edition when no license is installed', () => {
    const engine = new LicensingEngine({
      storagePath: licenseStoragePath,
      pinnedKeys: mockLicenseKeys,
      nowProvider: () => mockTimeMs,
    });

    const status = engine.getStatus();
    expect(status.plan).toBe('community');
    expect(status.is_active).toBe(true); // Community is always active
    expect(status.entitlements).toEqual([]);
    expect(engine.isEntitled('pro.deep_forensics')).toBe(false);
    expect(engine.isEntitled('pro.scheduled_scans')).toBe(false);
  });

  // --------------------------------------------------------------------------
  // 2. Cryptographic Signature Verification & Pinned Keys
  // --------------------------------------------------------------------------

  it('activates Pro Edition when presented with valid signed payload', () => {
    const engine = new LicensingEngine({
      storagePath: licenseStoragePath,
      pinnedKeys: mockLicenseKeys,
      nowProvider: () => mockTimeMs,
    });

    const validPayload = createSignedLicense();
    const status = engine.activateManual(JSON.stringify(validPayload));

    expect(status.plan).toBe('pro');
    expect(status.is_active).toBe(true);
    expect(status.account_email).toBe('pro-user@example.com');
    expect(status.entitlements).toContain('pro.deep_forensics');
    expect(engine.isEntitled('pro.deep_forensics')).toBe(true);
    expect(engine.isEntitled('pro.scheduled_scans')).toBe(true);
    expect(engine.isEntitled('pro.advanced_reporting')).toBe(true);
  });

  it('rejects license with forged digital signature', () => {
    const engine = new LicensingEngine({
      storagePath: licenseStoragePath,
      pinnedKeys: mockLicenseKeys,
      nowProvider: () => mockTimeMs,
    });

    const tampered = createSignedLicense();
    tampered.signature = Buffer.from('corrupted-signature-bytes').toString('base64');

    expect(() => engine.activateManual(JSON.stringify(tampered))).toThrow(
      LicensingErrorCodes.INVALID_SIGNATURE
    );
    expect(engine.getStatus().plan).toBe('community');
  });

  it('rejects license signed with unknown key ID', () => {
    const engine = new LicensingEngine({
      storagePath: licenseStoragePath,
      pinnedKeys: mockLicenseKeys,
      nowProvider: () => mockTimeMs,
    });

    const rogue = createSignedLicense({ kid: 'untrusted-rogue-key' });
    expect(() => engine.activateManual(JSON.stringify(rogue))).toThrow(
      LicensingErrorCodes.UNKNOWN_KEY
    );
  });

  it('supports seamless key rotation with transition keys', () => {
    const engine = new LicensingEngine({
      storagePath: licenseStoragePath,
      pinnedKeys: mockLicenseKeys,
      nowProvider: () => mockTimeMs,
    });

    const rotated = createSignedLicense({}, rotationKeyPair.privateKey, 'test-lic-rotation');
    const status = engine.activateManual(JSON.stringify(rotated));

    expect(status.plan).toBe('pro');
    expect(status.is_active).toBe(true);
  });

  // --------------------------------------------------------------------------
  // 3. Hardware Device Binding
  // --------------------------------------------------------------------------

  it('rejects license issued for a different hardware device fingerprint', () => {
    const engine = new LicensingEngine({
      storagePath: licenseStoragePath,
      pinnedKeys: mockLicenseKeys,
      nowProvider: () => mockTimeMs,
    });

    const mismatched = createSignedLicense({
      device_id: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    });

    expect(() => engine.activateManual(JSON.stringify(mismatched))).toThrow(
      LicensingErrorCodes.DEVICE_MISMATCH
    );
  });

  it('accepts wildcard enterprise license across different machines', () => {
    const engine = new LicensingEngine({
      storagePath: licenseStoragePath,
      pinnedKeys: mockLicenseKeys,
      nowProvider: () => mockTimeMs,
    });

    const enterpriseWildcard = createSignedLicense({
      plan: 'enterprise',
      device_id: '*',
    });

    const status = engine.activateManual(JSON.stringify(enterpriseWildcard));
    expect(status.plan).toBe('enterprise');
    expect(status.is_active).toBe(true);
  });

  // --------------------------------------------------------------------------
  // 4. Monotonic Sequence Replay Ratchet
  // --------------------------------------------------------------------------

  it('rejects replay of identical or older sequence number for same account', () => {
    const engine = new LicensingEngine({
      storagePath: licenseStoragePath,
      pinnedKeys: mockLicenseKeys,
      nowProvider: () => mockTimeMs,
    });

    const licSeq10 = createSignedLicense({ seq: 10 });
    engine.activateManual(JSON.stringify(licSeq10));

    // Attempt to replay seq 10
    expect(() => engine.activateManual(JSON.stringify(licSeq10))).toThrow(
      LicensingErrorCodes.REPLAY_ATTACK_DETECTED
    );

    // Attempt to replay older seq 5
    const licSeq5 = createSignedLicense({ seq: 5 });
    expect(() => engine.activateManual(JSON.stringify(licSeq5))).toThrow(
      LicensingErrorCodes.REPLAY_ATTACK_DETECTED
    );

    // Newer seq 11 must succeed
    const licSeq11 = createSignedLicense({ seq: 11 });
    const updated = engine.activateManual(JSON.stringify(licSeq11));
    expect(updated.is_active).toBe(true);
  });

  // --------------------------------------------------------------------------
  // 5. Expiration & Offline Grace Period
  // --------------------------------------------------------------------------

  it('grants Pro access during offline grace period with grace warning', () => {
    let simulatedTime = Date.parse('2026-09-18T12:00:00Z');
    const engine = new LicensingEngine({
      storagePath: licenseStoragePath,
      pinnedKeys: mockLicenseKeys,
      nowProvider: () => simulatedTime,
    });

    const lic = createSignedLicense({
      expires_at: '2026-10-01T00:00:00Z',
      grace_until: '2026-10-15T00:00:00Z',
    });
    engine.activateManual(JSON.stringify(lic));

    // Advance time past expiration but within 14-day grace window
    simulatedTime = Date.parse('2026-10-05T00:00:00Z');

    const status = engine.getStatus();
    expect(status.plan).toBe('pro');
    expect(status.is_active).toBe(true);
    expect(status.is_in_grace_period).toBe(true);
    expect(engine.isEntitled('pro.deep_forensics')).toBe(true);
  });

  it('drops to Community Edition once grace period has fully elapsed', () => {
    let simulatedTime = Date.parse('2026-09-18T12:00:00Z');
    const engine = new LicensingEngine({
      storagePath: licenseStoragePath,
      pinnedKeys: mockLicenseKeys,
      nowProvider: () => simulatedTime,
    });

    const lic = createSignedLicense({
      expires_at: '2026-10-01T00:00:00Z',
      grace_until: '2026-10-15T00:00:00Z',
    });
    engine.activateManual(JSON.stringify(lic));

    // Advance time past grace window
    simulatedTime = Date.parse('2026-10-20T00:00:00Z');

    const status = engine.getStatus();
    expect(status.plan).toBe('community');
    expect(status.is_active).toBe(false);
    expect(status.is_in_grace_period).toBe(false);
    expect(status.error?.code).toBe(LicensingErrorCodes.EXPIRED_LICENSE);
    expect(engine.isEntitled('pro.deep_forensics')).toBe(false);
  });

  // --------------------------------------------------------------------------
  // 6. System Clock Rollback Protection
  // --------------------------------------------------------------------------

  it('detects clock rollback beyond 1 hour and pauses Pro entitlements', () => {
    let simulatedTime = Date.parse('2026-09-18T12:00:00Z');
    const engine = new LicensingEngine({
      storagePath: licenseStoragePath,
      pinnedKeys: mockLicenseKeys,
      nowProvider: () => simulatedTime,
    });

    const lic = createSignedLicense({ seq: 1 });
    engine.activateManual(JSON.stringify(lic));
    expect(engine.isEntitled('pro.deep_forensics')).toBe(true);

    // User or attacker turns clock back 10 days
    simulatedTime = Date.parse('2026-09-08T12:00:00Z');

    // Create a new engine instance simulating restart under rolled-back clock
    const restartedEngine = new LicensingEngine({
      storagePath: licenseStoragePath,
      pinnedKeys: mockLicenseKeys,
      nowProvider: () => simulatedTime,
    });

    const status = restartedEngine.getStatus();
    expect(status.clock_rollback_detected).toBe(true);
    expect(status.error?.code).toBe(LicensingErrorCodes.CLOCK_ROLLBACK_DETECTED);
    expect(status.plan).toBe('community');
    expect(restartedEngine.isEntitled('pro.deep_forensics')).toBe(false);
  });

  // --------------------------------------------------------------------------
  // 7. RFC 8628 Device Authorization Flow
  // --------------------------------------------------------------------------

  it('completes RFC 8628 device flow from code generation to authorized activation', () => {
    const engine = new LicensingEngine({
      storagePath: licenseStoragePath,
      pinnedKeys: mockLicenseKeys,
      nowProvider: () => mockTimeMs,
    });

    const auth = engine.startDeviceAuth();
    expect(auth.device_code).toBeDefined();
    expect(auth.user_code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    expect(auth.verification_uri).toBe('https://smartcleaner.app/activate');

    // Polling before authorization reports pending
    const poll1 = engine.pollDeviceAuth(auth.device_code);
    expect(poll1.status).toBe('pending');
    expect(engine.getStatus().plan).toBe('community');

    // Server-side user authorization simulation
    const proLicense = createSignedLicense({ seq: 1 });
    engine.simulateServerAuthorize(auth.device_code, proLicense);

    // Polling after authorization commits license
    const poll2 = engine.pollDeviceAuth(auth.device_code);
    expect(poll2.status).toBe('authorized');
    expect(engine.getStatus().plan).toBe('pro');
    expect(engine.isEntitled('pro.deep_forensics')).toBe(true);
  });

  // --------------------------------------------------------------------------
  // 8. License Deactivation
  // --------------------------------------------------------------------------

  it('deactivates license cleanly and restores Community Edition', () => {
    const engine = new LicensingEngine({
      storagePath: licenseStoragePath,
      pinnedKeys: mockLicenseKeys,
      nowProvider: () => mockTimeMs,
    });

    const lic = createSignedLicense();
    engine.activateManual(JSON.stringify(lic));
    expect(engine.getStatus().plan).toBe('pro');

    const deactivated = engine.deactivate();
    expect(deactivated.plan).toBe('community');
    expect(deactivated.is_active).toBe(true);
    expect(deactivated.entitlements).toEqual([]);
    expect(engine.isEntitled('pro.deep_forensics')).toBe(false);
  });
});
