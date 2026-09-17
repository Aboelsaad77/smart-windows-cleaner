/**
 * Smart Windows Cleaner — Licensing & Entitlements Type Definitions (Stage 3)
 *
 * Safety Invariant:
 * The licensing engine NEVER gates or affects SafetyEngine, NeverDelete,
 * Preflight checks, or quarantine safety. All plans receive 100% protection.
 */

export type LicensePlan = 'community' | 'pro' | 'enterprise';

export type EntitlementFeature =
  | 'pro.deep_forensics'
  | 'pro.scheduled_scans'
  | 'pro.advanced_reporting';

export const KNOWN_ENTITLEMENTS: readonly EntitlementFeature[] = [
  'pro.deep_forensics',
  'pro.scheduled_scans',
  'pro.advanced_reporting',
] as const;

export interface SignedLicensePayload {
  schema_version: string;
  license_id: string;
  account_id: string;
  account_email: string;
  plan: LicensePlan;
  entitlements: EntitlementFeature[];
  device_id: string;
  issued_at: string;
  expires_at: string;
  grace_until: string;
  seq: number;
  kid: string;
  signature: string;
}

export interface LicenseStatusDto {
  plan: LicensePlan;
  is_active: boolean;
  is_in_grace_period: boolean;
  account_email: string | null;
  license_id: string | null;
  expires_at: string | null;
  grace_until: string | null;
  entitlements: string[];
  device_id: string;
  clock_rollback_detected: boolean;
  last_verified_at: string | null;
  error: {
    code: string;
    message: string;
  } | null;
}

export interface DeviceAuthResponseDto {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}

export interface DeviceAuthPollResultDto {
  status: 'pending' | 'authorized' | 'expired' | 'denied';
  license_token?: string;
  error?: string;
}

export interface PinnedLicenseKey {
  kid: string;
  algorithm: 'ed25519';
  publicKeyPem: string;
  validFrom: string;
  status: 'active' | 'transition' | 'retired';
  description: string;
}

export const LicensingErrorCodes = {
  INVALID_SIGNATURE: 'LIC_INVALID_SIGNATURE',
  EXPIRED_LICENSE: 'LIC_EXPIRED_LICENSE',
  DEVICE_MISMATCH: 'LIC_DEVICE_MISMATCH',
  REPLAY_ATTACK_DETECTED: 'LIC_REPLAY_ATTACK_DETECTED',
  CLOCK_ROLLBACK_DETECTED: 'LIC_CLOCK_ROLLBACK_DETECTED',
  UNKNOWN_KEY: 'LIC_UNKNOWN_KEY',
  MALFORMED_LICENSE: 'LIC_MALFORMED_LICENSE',
  STORAGE_ERROR: 'LIC_STORAGE_ERROR',
  DEVICE_AUTH_TIMEOUT: 'LIC_DEVICE_AUTH_TIMEOUT',
  NETWORK_ERROR: 'LIC_NETWORK_ERROR',
} as const;
