/**
 * Smart Windows Cleaner — Secure Auto-Updater Type Definitions (Stage 2)
 */

export type UpdateChannel = 'stable' | 'beta' | 'rc';

export type UpdateState =
  | 'idle'
  | 'checking'
  | 'available'
  | 'not_available'
  | 'downloading'
  | 'downloaded'
  | 'deferred_busy'
  | 'applying'
  | 'error';

export interface SignedUpdateManifest {
  schema_version: string;
  version: string;
  channel: UpdateChannel;
  release_date: string;
  architecture: string;
  artifact_filename: string;
  artifact_size: number;
  sha256: string;
  sha512: string;
  download_url: string;
  min_supported_version?: string;
  release_notes?: string;
  kid: string;
  signature: string;
}

export interface AvailableUpdateInfo {
  version: string;
  channel: UpdateChannel;
  release_date: string;
  architecture: string;
  artifact_filename: string;
  artifact_size: number;
  sha256: string;
  sha512: string;
  download_url: string;
  min_supported_version?: string;
  release_notes?: string;
  kid: string;
}

export interface DownloadProgress {
  percent: number;
  bytes_transferred: number;
  total_bytes: number;
}

export interface UpdateStatusDto {
  state: UpdateState;
  current_version: string;
  channel: UpdateChannel;
  is_portable: boolean;
  available_update?: AvailableUpdateInfo | null;
  download_progress?: DownloadProgress | null;
  downloaded_file_path?: string | null;
  deferred_reason?: string | null;
  error?: {
    code: string;
    message: string;
  } | null;
  last_checked_at?: string | null;
}

export interface PinnedSigningKey {
  kid: string;
  algorithm: 'ed25519';
  publicKeyPem: string;
  validFrom: string;
  validUntil?: string;
  description: string;
  status: 'active' | 'transition' | 'retired';
}

export const UpdaterErrorCodes = {
  NETWORK_UNAVAILABLE: 'NETWORK_UNAVAILABLE',
  METADATA_UNAVAILABLE: 'METADATA_UNAVAILABLE',
  METADATA_SIGNATURE_INVALID: 'METADATA_SIGNATURE_INVALID',
  UNKNOWN_SIGNING_KEY: 'UNKNOWN_SIGNING_KEY',
  ARTIFACT_HASH_MISMATCH: 'ARTIFACT_HASH_MISMATCH',
  UNSUPPORTED_VERSION: 'UNSUPPORTED_VERSION',
  DOWNGRADE_ATTEMPT: 'DOWNGRADE_ATTEMPT',
  ALREADY_UP_TO_DATE: 'ALREADY_UP_TO_DATE',
  CHANNEL_MISMATCH: 'CHANNEL_MISMATCH',
  INTERRUPTED_DOWNLOAD: 'INTERRUPTED_DOWNLOAD',
  INSUFFICIENT_SPACE: 'INSUFFICIENT_SPACE',
  INSTALLER_LAUNCH_FAILURE: 'INSTALLER_LAUNCH_FAILURE',
  UPDATE_CANCELLED: 'UPDATE_CANCELLED',
  PORTABLE_MODE_BLOCKED: 'PORTABLE_MODE_BLOCKED',
  ENGINE_BUSY: 'ENGINE_BUSY',
  CONFIRMATION_REQUIRED: 'CONFIRMATION_REQUIRED',
  MALICIOUS_PATH_REJECTED: 'MALICIOUS_PATH_REJECTED',
  INTERNAL_UPDATER_ERROR: 'INTERNAL_UPDATER_ERROR',
} as const;

export type UpdaterErrorCode = (typeof UpdaterErrorCodes)[keyof typeof UpdaterErrorCodes] | string;
