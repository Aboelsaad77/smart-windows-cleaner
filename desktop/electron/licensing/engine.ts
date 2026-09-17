/**
 * Smart Windows Cleaner — Licensing & Entitlements Engine (Stage 3 B2-B7)
 *
 * Implements:
 * - Ed25519 digital signature verification over RFC 8785 canonical payloads.
 * - Monotonic sequence replay ratchet.
 * - Hardware device binding via SHA-256 fingerprint.
 * - Offline grace period and system clock rollback detection.
 * - RFC 8628 device authorization linking flow.
 * - Feature gating abstraction (isEntitled).
 *
 * ABSOLUTE SAFETY INVARIANT:
 * This engine NEVER controls or influences the Rust Core Safety Engine,
 * NeverDelete rules, Preflight checks, or quarantine safety.
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  EntitlementFeature,
  SignedLicensePayload,
  LicenseStatusDto,
  DeviceAuthResponseDto,
  DeviceAuthPollResultDto,
  PinnedLicenseKey,
  LicensingErrorCodes,
} from '../../src/types/licensing';
import { canonicalizeJson } from '../updater/crypto';
import { lookupPinnedLicenseKey, PINNED_LICENSE_KEYS } from './keys';
import { getDeviceId } from './fingerprint';

interface PersistedLicenseStore {
  version: 1;
  activeLicense: SignedLicensePayload | null;
  lastSeenSeq: number;
  lastVerifiedTimestamp: number;
  clockRollbackDetected: boolean;
}

export interface LicensingEngineOptions {
  storagePath?: string;
  pinnedKeys?: Record<string, PinnedLicenseKey>;
  nowProvider?: () => number; // Optional mock time provider (epoch ms)
}

export class LicensingEngine {
  private storagePath: string;
  private pinnedKeys: Record<string, PinnedLicenseKey>;
  private nowProvider: () => number;
  private store: PersistedLicenseStore;

  // In-memory active device auth sessions (deviceCode -> session)
  private activeDeviceAuthSessions = new Map<
    string,
    {
      userCode: string;
      expiresAt: number;
      authorizedPayload: SignedLicensePayload | null;
    }
  >();

  constructor(options: LicensingEngineOptions = {}) {
    this.storagePath =
      options.storagePath ??
      path.join(
        process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'),
        'SmartCleaner',
        'license.json'
      );
    this.pinnedKeys = options.pinnedKeys ?? PINNED_LICENSE_KEYS;
    this.nowProvider = options.nowProvider ?? (() => Date.now());

    this.store = this.loadStore();
    this.evaluateStatus();
  }

  /**
   * Primary feature entitlement query.
   * ABSOLUTE SAFETY INVARIANT: Only non-safety product features can be gated.
   */
  public isEntitled(feature: EntitlementFeature | string): boolean {
    const status = this.getStatus();
    if (!status.is_active) {
      return false;
    }
    if (status.clock_rollback_detected) {
      return false;
    }
    return status.entitlements.includes(feature as EntitlementFeature);
  }

  /**
   * Returns current license and entitlement status DTO for presentation.
   */
  public getStatus(): LicenseStatusDto {
    const deviceId = getDeviceId();
    const now = this.nowProvider();

    if (!this.store.activeLicense) {
      return {
        plan: 'community',
        is_active: true, // Community edition is always active
        is_in_grace_period: false,
        account_email: null,
        license_id: null,
        expires_at: null,
        grace_until: null,
        entitlements: [],
        device_id: deviceId,
        clock_rollback_detected: this.store.clockRollbackDetected,
        last_verified_at: this.store.lastVerifiedTimestamp > 0 ? new Date(this.store.lastVerifiedTimestamp).toISOString() : null,
        error: this.store.clockRollbackDetected
          ? {
              code: LicensingErrorCodes.CLOCK_ROLLBACK_DETECTED,
              message: 'System clock rollback detected. Pro entitlements temporarily paused until time resynchronization.',
            }
          : null,
      };
    }

    const lic = this.store.activeLicense;
    const expiresMs = Date.parse(lic.expires_at);
    const graceMs = Date.parse(lic.grace_until);

    const isInGrace = now > expiresMs && now <= graceMs;
    const isExpired = now > graceMs;
    const isActive = !isExpired && !this.store.clockRollbackDetected;

    return {
      plan: isActive ? lic.plan : 'community',
      is_active: isActive,
      is_in_grace_period: isInGrace,
      account_email: lic.account_email,
      license_id: lic.license_id,
      expires_at: lic.expires_at,
      grace_until: lic.grace_until,
      entitlements: isActive ? lic.entitlements : [],
      device_id: deviceId,
      clock_rollback_detected: this.store.clockRollbackDetected,
      last_verified_at: new Date(this.store.lastVerifiedTimestamp).toISOString(),
      error: isExpired
        ? {
            code: LicensingErrorCodes.EXPIRED_LICENSE,
            message: 'Your Pro license has expired and grace period ended. Operating in Community Edition.',
          }
        : this.store.clockRollbackDetected
        ? {
            code: LicensingErrorCodes.CLOCK_ROLLBACK_DETECTED,
            message: 'System clock moved backwards beyond tolerance. Operating in Community Edition.',
          }
        : null,
    };
  }

  /**
   * Activates a license from raw input (JSON string or base64 encoded JSON).
   */
  public activateManual(rawInput: string): LicenseStatusDto {
    let payload: SignedLicensePayload;

    try {
      let jsonStr = rawInput.trim();
      // Attempt base64 decode if not plain JSON
      if (!jsonStr.startsWith('{')) {
        jsonStr = Buffer.from(jsonStr, 'base64').toString('utf8');
      }
      payload = JSON.parse(jsonStr) as SignedLicensePayload;
    } catch {
      throw new Error(`[${LicensingErrorCodes.MALFORMED_LICENSE}] License token is malformed or invalid format`);
    }

    this.verifyAndInstallLicense(payload);
    return this.getStatus();
  }

  /**
   * Deactivates current license, resetting local install to Community Edition.
   */
  public deactivate(): LicenseStatusDto {
    this.store.activeLicense = null;
    this.saveStore();
    return this.getStatus();
  }

  /**
   * Initiates RFC 8628 Device Authorization Flow.
   */
  public startDeviceAuth(): DeviceAuthResponseDto {
    const deviceCode = crypto.randomBytes(16).toString('hex');
    // Generate clean 8-char user code (e.g. ABCD-EFGH)
    const rawChars = crypto.randomBytes(4).toString('hex').toUpperCase();
    const userCode = `${rawChars.slice(0, 4)}-${rawChars.slice(4, 8)}`;
    const expiresIn = 900; // 15 minutes
    const interval = 5;

    this.activeDeviceAuthSessions.set(deviceCode, {
      userCode,
      expiresAt: this.nowProvider() + expiresIn * 1000,
      authorizedPayload: null,
    });

    return {
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: 'https://smartcleaner.app/activate',
      expires_in: expiresIn,
      interval,
    };
  }

  /**
   * Polls RFC 8628 device authorization status.
   */
  public pollDeviceAuth(deviceCode: string): DeviceAuthPollResultDto {
    const session = this.activeDeviceAuthSessions.get(deviceCode);
    if (!session) {
      return { status: 'denied', error: 'Invalid or unknown device authorization code' };
    }

    if (this.nowProvider() > session.expiresAt) {
      this.activeDeviceAuthSessions.delete(deviceCode);
      return { status: 'expired', error: 'Device authorization code expired' };
    }

    if (session.authorizedPayload) {
      this.verifyAndInstallLicense(session.authorizedPayload);
      this.activeDeviceAuthSessions.delete(deviceCode);
      return { status: 'authorized' };
    }

    return { status: 'pending' };
  }

  /**
   * Simulator helper for RFC 8628 server-side authorization in test environments.
   */
  public simulateServerAuthorize(deviceCode: string, payload: SignedLicensePayload): void {
    const session = this.activeDeviceAuthSessions.get(deviceCode);
    if (session) {
      session.authorizedPayload = payload;
    }
  }

  // --- Cryptographic & Policy Enforcement Core ---

  public verifyAndInstallLicense(payload: SignedLicensePayload): void {
    // 1. Structure check
    if (
      !payload ||
      !payload.license_id ||
      !payload.account_id ||
      !payload.device_id ||
      !payload.signature ||
      !payload.kid ||
      !payload.expires_at ||
      typeof payload.seq !== 'number'
    ) {
      throw new Error(`[${LicensingErrorCodes.MALFORMED_LICENSE}] License payload is missing required schema fields`);
    }

    // 2. Public Key check
    const pinnedKey = lookupPinnedLicenseKey(payload.kid, this.pinnedKeys);
    if (!pinnedKey) {
      throw new Error(
        `[${LicensingErrorCodes.UNKNOWN_KEY}] License signing key '${payload.kid}' is unrecognized or retired`
      );
    }

    // 3. Ed25519 Cryptographic Signature Verification over RFC 8785 Canonical Payload
    const { signature, ...signableFields } = payload;
    const canonicalPayload = canonicalizeJson(signableFields);
    const dataBuffer = Buffer.from(canonicalPayload, 'utf8');
    const signatureBuffer = Buffer.from(signature, 'base64');

    try {
      const pubKeyObj = crypto.createPublicKey(pinnedKey.publicKeyPem);
      const isSignatureValid = crypto.verify(null, dataBuffer, pubKeyObj, signatureBuffer);
      if (!isSignatureValid) {
        throw new Error(
          `[${LicensingErrorCodes.INVALID_SIGNATURE}] Digital signature is invalid or license has been tampered with`
        );
      }
    } catch (err) {
      if (err instanceof Error && err.message.includes(LicensingErrorCodes.INVALID_SIGNATURE)) {
        throw err;
      }
      throw new Error(
        `[${LicensingErrorCodes.INVALID_SIGNATURE}] Cryptographic error: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // 4. Device Binding Verification
    const currentDeviceId = getDeviceId();
    if (payload.device_id !== '*' && payload.device_id !== currentDeviceId) {
      throw new Error(
        `[${LicensingErrorCodes.DEVICE_MISMATCH}] License is registered to a different device (${payload.device_id.slice(0, 8)}... vs current ${currentDeviceId.slice(0, 8)}...)`
      );
    }

    // 5. Monotonic Sequence Replay Ratchet
    if (payload.seq <= this.store.lastSeenSeq && this.store.activeLicense?.account_id === payload.account_id) {
      throw new Error(
        `[${LicensingErrorCodes.REPLAY_ATTACK_DETECTED}] License sequence (${payload.seq}) is not strictly newer than last observed sequence (${this.store.lastSeenSeq})`
      );
    }

    // 6. Clock Rollback Check
    const now = this.nowProvider();
    if (this.store.lastVerifiedTimestamp > 0 && now < this.store.lastVerifiedTimestamp - 3600_000) {
      this.store.clockRollbackDetected = true;
      this.saveStore();
      throw new Error(
        `[${LicensingErrorCodes.CLOCK_ROLLBACK_DETECTED}] System clock rollback detected. Current system time is in the past relative to previous verification.`
      );
    }

    // 7. Expiration Check
    const graceMs = Date.parse(payload.grace_until);
    if (now > graceMs) {
      throw new Error(
        `[${LicensingErrorCodes.EXPIRED_LICENSE}] License expired on ${payload.expires_at} (grace ended ${payload.grace_until})`
      );
    }

    // Success — commit license
    this.store.activeLicense = payload;
    this.store.lastSeenSeq = Math.max(this.store.lastSeenSeq, payload.seq);
    this.store.lastVerifiedTimestamp = now;
    this.store.clockRollbackDetected = false;
    this.saveStore();
  }

  private evaluateStatus(): void {
    const now = this.nowProvider();
    // Clock rollback detection on initialization
    if (this.store.lastVerifiedTimestamp > 0 && now < this.store.lastVerifiedTimestamp - 3600_000) {
      this.store.clockRollbackDetected = true;
      this.saveStore();
    } else if (this.store.activeLicense) {
      // Update last verified timestamp if time advances naturally
      if (now > this.store.lastVerifiedTimestamp) {
        this.store.lastVerifiedTimestamp = now;
        this.saveStore();
      }
    }
  }

  private loadStore(): PersistedLicenseStore {
    try {
      if (fs.existsSync(this.storagePath)) {
        const raw = fs.readFileSync(this.storagePath, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && parsed.version === 1) {
          return parsed as PersistedLicenseStore;
        }
      }
    } catch {
      // Fall through to initial store
    }

    return {
      version: 1,
      activeLicense: null,
      lastSeenSeq: 0,
      lastVerifiedTimestamp: 0,
      clockRollbackDetected: false,
    };
  }

  private saveStore(): void {
    try {
      const parentDir = path.dirname(this.storagePath);
      if (!fs.existsSync(parentDir)) {
        fs.mkdirSync(parentDir, { recursive: true, mode: 0o700 });
      }
      fs.writeFileSync(this.storagePath, JSON.stringify(this.store, null, 2), { mode: 0o600 });
    } catch {
      // Non-fatal if storage temporarily fails (e.g. read-only media)
    }
  }
}
