/**
 * Smart Windows Cleaner — Secure Auto-Updater Orchestrator (Stage 2)
 *
 * Implements the full secure update flow:
 * App -> Check release metadata -> Verify signature (pinned key) ->
 * Validate version/channel -> Verify artifact hash -> Download to secure temp ->
 * Verify downloaded hashes -> User confirmation -> Install/apply update.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as http from 'node:http';
import * as https from 'node:https';
import * as child_process from 'node:child_process';
import {
  UpdateChannel,
  UpdateState,
  UpdateStatusDto,
  SignedUpdateManifest,
  UpdaterErrorCodes,
  PinnedSigningKey,
  AvailableUpdateInfo,
} from '../../src/types/updater';
import {
  verifyManifestAuthenticity,
  verifyArtifactIntegrity,
  sanitizeArtifactFilename,
} from './crypto';
import { compareSemver, parseSemver, isChannelCompatible } from './semver';
import { detectPortableMode } from './portable';
import { PINNED_SIGNING_KEYS } from './keys';

export type EventBroadcaster = (event: {
  type: 'updater_status_changed' | 'updater_progress' | 'updater_error';
  status?: UpdateStatusDto;
  percent?: number;
  bytes_transferred?: number;
  total_bytes?: number;
  code?: string;
  message?: string;
}) => void;

export interface UpdaterOptions {
  currentVersion: string;
  defaultChannel?: UpdateChannel;
  pinnedKeys?: Record<string, PinnedSigningKey>;
  manifestUrl?: string;
  isPortable?: boolean;
  eventBroadcaster?: EventBroadcaster;
  tempDirectory?: string;
}

export class SecureAutoUpdater {
  private currentVersion: string;
  private channel: UpdateChannel;
  private isPortable: boolean;
  private pinnedKeys: Record<string, PinnedSigningKey>;
  private manifestUrl: string;
  private tempDirectory: string;
  private broadcaster?: EventBroadcaster;

  // Runtime Safety Coordinator: Engine busy check
  private isEngineBusyFn: () => boolean = () => false;

  // Active state
  private status: UpdateStatusDto;
  private activeManifest: SignedUpdateManifest | null = null;
  private activeDownloadRequest: http.ClientRequest | null = null;
  private isCancelled: boolean = false;

  constructor(options: UpdaterOptions) {
    this.currentVersion = options.currentVersion;
    this.channel = options.defaultChannel ?? 'stable';
    this.pinnedKeys = options.pinnedKeys ?? PINNED_SIGNING_KEYS;
    this.manifestUrl =
      options.manifestUrl ??
      'https://raw.githubusercontent.com/Aboelsaad77/smart-windows-cleaner/main/releases/latest.json';
    this.tempDirectory = options.tempDirectory ?? path.join(os.tmpdir(), 'smart-cleaner-updater');
    this.broadcaster = options.eventBroadcaster;

    const portableDetection = detectPortableMode();
    this.isPortable = options.isPortable !== undefined ? options.isPortable : portableDetection.isPortable;

    this.status = {
      state: 'idle',
      current_version: this.currentVersion,
      channel: this.channel,
      is_portable: this.isPortable,
      available_update: null,
      download_progress: null,
      downloaded_file_path: null,
      deferred_reason: null,
      error: null,
      last_checked_at: null,
    };
  }

  /**
   * Registers a provider function that checks if scan, quarantine, restore, or purge is running.
   */
  public setEngineBusyProvider(fn: () => boolean): void {
    this.isEngineBusyFn = fn;
  }

  public getStatus(): UpdateStatusDto {
    return { ...this.status };
  }

  public setChannel(newChannel: UpdateChannel): UpdateStatusDto {
    if (newChannel !== 'stable' && newChannel !== 'beta' && newChannel !== 'rc') {
      throw new Error(`Invalid channel '${newChannel}'. Must be 'stable', 'beta', or 'rc'.`);
    }
    this.channel = newChannel;
    this.status.channel = newChannel;
    this.emitStatus();
    return this.getStatus();
  }

  /**
   * Checks for updates by fetching and cryptographically verifying the signed manifest.
   */
  public async checkForUpdates(
    options: {
      manifestUrlOverride?: string;
      manifestPayloadOverride?: SignedUpdateManifest;
    } = {}
  ): Promise<UpdateStatusDto> {
    this.status.state = 'checking';
    this.status.error = null;
    this.status.deferred_reason = null;
    this.emitStatus();

    try {
      let manifest: SignedUpdateManifest;

      if (options.manifestPayloadOverride) {
        manifest = options.manifestPayloadOverride;
      } else {
        const url = options.manifestUrlOverride || this.manifestUrl;
        manifest = await this.fetchManifestHttp(url);
      }

      this.status.last_checked_at = new Date().toISOString();

      // STEP 1: Verify Metadata Signature against Pinned Public Key (Authenticity)
      const sigResult = verifyManifestAuthenticity(manifest, this.pinnedKeys);
      if (!sigResult.valid) {
        const errCode = sigResult.errorCode || UpdaterErrorCodes.METADATA_SIGNATURE_INVALID;
        const errMsg = sigResult.errorMessage || 'Release metadata signature verification failed';
        this.transitionToError(errCode, errMsg);
        throw new Error(`[${errCode}] ${errMsg}`);
      }

      // STEP 2: Validate Semantic Versioning & Downgrade Prevention
      const candidateSemver = parseSemver(manifest.version);
      if (!candidateSemver) {
        this.transitionToError(
          UpdaterErrorCodes.UNSUPPORTED_VERSION,
          `Release manifest contains malformed semver string: '${manifest.version}'`
        );
        throw new Error(`[${UpdaterErrorCodes.UNSUPPORTED_VERSION}] Invalid semver in manifest`);
      }

      let comparison: number;
      try {
        comparison = compareSemver(manifest.version, this.currentVersion);
      } catch (err) {
        this.transitionToError(
          UpdaterErrorCodes.UNSUPPORTED_VERSION,
          `Failed to compare versions: ${err instanceof Error ? err.message : String(err)}`
        );
        throw err;
      }

      if (comparison < 0) {
        // Candidate version is older than current version: DOWNGRADE REJECTED
        this.status.state = 'not_available';
        this.status.error = {
          code: UpdaterErrorCodes.DOWNGRADE_ATTEMPT,
          message: `Update rejected: manifest version (${manifest.version}) is older than installed version (${this.currentVersion}). Downgrades are blocked for security.`,
        };
        this.emitStatus();
        return this.getStatus();
      }

      if (comparison === 0) {
        // Exactly current version
        this.status.state = 'not_available';
        this.status.available_update = null;
        this.emitStatus();
        return this.getStatus();
      }

      // STEP 3: Validate Channel Compatibility
      if (!isChannelCompatible(manifest.channel, this.channel)) {
        this.status.state = 'not_available';
        this.status.error = {
          code: UpdaterErrorCodes.CHANNEL_MISMATCH,
          message: `Update channel mismatch: manifest channel is '${manifest.channel}' but configured channel is '${this.channel}'`,
        };
        this.emitStatus();
        return this.getStatus();
      }

      // STEP 4: Validate Artifact Hash Specifications in Manifest
      if (!manifest.sha256 || manifest.sha256.length !== 64 || !manifest.sha512 || manifest.sha512.length !== 128) {
        this.transitionToError(
          UpdaterErrorCodes.ARTIFACT_HASH_MISMATCH,
          'Manifest artifact hashes (SHA-256 / SHA-512) are missing or invalid length'
        );
        throw new Error('Invalid manifest hash lengths');
      }

      // STEP 5: Success — Update is available
      this.activeManifest = manifest;
      const updateInfo: AvailableUpdateInfo = {
        version: manifest.version,
        channel: manifest.channel,
        release_date: manifest.release_date,
        architecture: manifest.architecture,
        artifact_filename: manifest.artifact_filename,
        artifact_size: manifest.artifact_size,
        sha256: manifest.sha256,
        sha512: manifest.sha512,
        download_url: manifest.download_url,
        min_supported_version: manifest.min_supported_version,
        release_notes: manifest.release_notes,
        kid: manifest.kid,
      };

      this.status.state = 'available';
      this.status.available_update = updateInfo;
      this.emitStatus();
      return this.getStatus();
    } catch (err) {
      const currentState = this.status.state as UpdateState;
      if (currentState !== 'error' && currentState !== 'not_available') {
        const msg = err instanceof Error ? err.message : String(err);
        this.transitionToError(UpdaterErrorCodes.METADATA_UNAVAILABLE, msg);
      }
      throw err;
    }
  }

  /**
   * Downloads the update artifact to secure staging directory and verifies SHA-256 and SHA-512 hashes.
   */
  public async downloadUpdate(options: { localArtifactSourcePath?: string } = {}): Promise<UpdateStatusDto> {
    if (!this.activeManifest || !this.status.available_update) {
      throw new Error('No verified update is currently available to download. Call checkForUpdates first.');
    }

    const manifest = this.activeManifest;
    this.status.state = 'downloading';
    this.status.download_progress = { percent: 0, bytes_transferred: 0, total_bytes: manifest.artifact_size };
    this.status.error = null;
    this.isCancelled = false;
    this.emitStatus();

    if (!fs.existsSync(this.tempDirectory)) {
      fs.mkdirSync(this.tempDirectory, { recursive: true, mode: 0o700 });
    }

    // A4: Validate artifact filename against path traversal attacks (.., /, \, :)
    let safeFilename: string;
    try {
      safeFilename = sanitizeArtifactFilename(manifest.artifact_filename);
    } catch (sanitizeErr) {
      this.transitionToError(
        UpdaterErrorCodes.MALICIOUS_PATH_REJECTED,
        `Path traversal or illegal filename rejected: ${sanitizeErr instanceof Error ? sanitizeErr.message : String(sanitizeErr)}`
      );
      throw sanitizeErr;
    }

    const targetFilePath = path.join(this.tempDirectory, safeFilename);

    // Symlink / Reparse Point Staging Protection:
    if (fs.existsSync(targetFilePath) && fs.lstatSync(targetFilePath).isSymbolicLink()) {
      fs.unlinkSync(targetFilePath);
    }

    try {
      if (options.localArtifactSourcePath) {
        // Fast-path for testing or local simulation
        fs.copyFileSync(options.localArtifactSourcePath, targetFilePath);
      } else {
        await this.downloadFileHttp(manifest.download_url, targetFilePath, manifest.artifact_size);
      }

      if (this.isCancelled) {
        if (fs.existsSync(targetFilePath)) fs.unlinkSync(targetFilePath);
        this.status.state = 'available';
        this.status.download_progress = null;
        this.emitStatus();
        throw new Error(`[${UpdaterErrorCodes.UPDATE_CANCELLED}] Download was cancelled by user`);
      }

      // STEP 6: Cryptographic Artifact Verification (Dual SHA-256 and SHA-512)
      const integrity = await verifyArtifactIntegrity(
        targetFilePath,
        manifest.sha256,
        manifest.sha512,
        manifest.artifact_size
      );

      if (!integrity.valid) {
        if (fs.existsSync(targetFilePath)) fs.unlinkSync(targetFilePath);
        this.transitionToError(
          UpdaterErrorCodes.ARTIFACT_HASH_MISMATCH,
          `Integrity verification failed on downloaded package: ${integrity.reason}`
        );
        throw new Error(`[${UpdaterErrorCodes.ARTIFACT_HASH_MISMATCH}] ${integrity.reason}`);
      }

      this.status.state = 'downloaded';
      this.status.downloaded_file_path = targetFilePath;
      this.status.download_progress = {
        percent: 100,
        bytes_transferred: manifest.artifact_size,
        total_bytes: manifest.artifact_size,
      };
      this.emitStatus();
      return this.getStatus();
    } catch (err) {
      const currentState = this.status.state as UpdateState;
      if (currentState !== 'available' && currentState !== 'error') {
        const msg = err instanceof Error ? err.message : String(err);
        this.transitionToError(UpdaterErrorCodes.INTERRUPTED_DOWNLOAD, msg);
      }
      throw err;
    }
  }

  /**
   * Applies the downloaded update with strict runtime safety and portable mode protection.
   *
   * Safety Constraints:
   * 1. Requires explicit user confirmation (options.confirm === true).
   * 2. Blocks execution in Portable Mode.
   * 3. Blocks execution and defers if Scan, Quarantine, Restore, or Purge is running.
   */
  public async applyUpdate(options: {
    confirm: boolean;
    onApplySpawn?: (filePath: string) => void;
  }): Promise<{ applied: boolean; deferred: boolean; reason?: string }> {
    if (!options.confirm) {
      throw new Error(`[${UpdaterErrorCodes.CONFIRMATION_REQUIRED}] User confirmation is strictly required to apply an update`);
    }

    if (this.isPortable) {
      const msg =
        'Smart Cleaner is running in Portable Mode. In-place installer execution is prohibited to preserve host system cleanliness. Please extract the new portable archive manually.';
      this.status.state = 'error';
      this.status.error = { code: UpdaterErrorCodes.PORTABLE_MODE_BLOCKED, message: msg };
      this.emitStatus();
      throw new Error(`[${UpdaterErrorCodes.PORTABLE_MODE_BLOCKED}] ${msg}`);
    }

    if (!this.status.downloaded_file_path || !fs.existsSync(this.status.downloaded_file_path)) {
      throw new Error('No verified update installer is staged on disk. Please download the update first.');
    }

    // RUNTIME SAFETY GATE: Check if Scan / Quarantine / Restore / Purge is active
    if (this.isEngineBusyFn()) {
      const deferredMsg = 'Update Ready — Restart when current operation finishes.';
      this.status.state = 'deferred_busy';
      this.status.deferred_reason = deferredMsg;
      this.emitStatus();
      return {
        applied: false,
        deferred: true,
        reason: deferredMsg,
      };
    }

    // Clear deferred reason if previously set
    this.status.deferred_reason = null;
    this.status.state = 'applying';
    this.emitStatus();

    const filePath = this.status.downloaded_file_path;

    // A4: Execution boundary checks (no symlinks, must be inside temp directory)
    const resolvedPath = path.resolve(filePath);
    const resolvedTemp = path.resolve(this.tempDirectory);
    if (!resolvedPath.startsWith(resolvedTemp)) {
      const msg = `Staged artifact path '${filePath}' escapes updater temporary directory`;
      this.transitionToError(UpdaterErrorCodes.MALICIOUS_PATH_REJECTED, msg);
      throw new Error(`[${UpdaterErrorCodes.MALICIOUS_PATH_REJECTED}] ${msg}`);
    }

    if (fs.lstatSync(resolvedPath).isSymbolicLink()) {
      fs.unlinkSync(resolvedPath);
      const msg = `Staged artifact is a symbolic link, which is rejected for safety`;
      this.transitionToError(UpdaterErrorCodes.MALICIOUS_PATH_REJECTED, msg);
      throw new Error(`[${UpdaterErrorCodes.MALICIOUS_PATH_REJECTED}] ${msg}`);
    }

    if (options.onApplySpawn) {
      options.onApplySpawn(filePath);
      return { applied: true, deferred: false };
    }

    // Production Windows Installer Launch:
    try {
      if (process.platform === 'win32') {
        const child = child_process.spawn(filePath, ['/S'], {
          detached: true,
          stdio: 'ignore',
        });
        child.unref();
      }
      return { applied: true, deferred: false };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.transitionToError(UpdaterErrorCodes.INSTALLER_LAUNCH_FAILURE, `Failed to launch installer: ${msg}`);
      throw new Error(`[${UpdaterErrorCodes.INSTALLER_LAUNCH_FAILURE}] ${msg}`);
    }
  }

  /**
   * Cancels any active download operation.
   */
  public cancel(): UpdateStatusDto {
    this.isCancelled = true;
    if (this.activeDownloadRequest) {
      this.activeDownloadRequest.destroy();
      this.activeDownloadRequest = null;
    }
    if (this.status.state === 'downloading') {
      this.status.state = 'available';
      this.status.download_progress = null;
      this.emitStatus();
    }
    return this.getStatus();
  }

  // --- Internal Helpers ---

  private transitionToError(code: string, message: string): void {
    this.status.state = 'error';
    this.status.error = { code, message };
    this.emitStatus();
    if (this.broadcaster) {
      this.broadcaster({ type: 'updater_error', code, message });
    }
  }

  private emitStatus(): void {
    if (this.broadcaster) {
      this.broadcaster({
        type: 'updater_status_changed',
        status: this.getStatus(),
      });
    }
  }

  private async fetchManifestHttp(urlStr: string): Promise<SignedUpdateManifest> {
    return new Promise((resolve, reject) => {
      let client: typeof http | typeof https = http;
      if (urlStr.startsWith('https:')) client = https;

      const req = client.get(urlStr, { timeout: 10000 }, (res) => {
        if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
          return reject(new Error(`HTTP ${res.statusCode}: Failed to fetch update manifest from ${urlStr}`));
        }

        let rawData = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          rawData += chunk;
        });

        res.on('end', () => {
          try {
            const parsed = JSON.parse(rawData);
            resolve(parsed as SignedUpdateManifest);
          } catch (e) {
            reject(new Error(`Invalid JSON received from update manifest endpoint: ${String(e)}`));
          }
        });
      });

      req.on('error', (err) => {
        reject(new Error(`Network error while fetching update manifest: ${err.message}`));
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Update check request timed out after 10000ms'));
      });
    });
  }

  private async downloadFileHttp(urlStr: string, destPath: string, expectedSize: number): Promise<void> {
    return new Promise((resolve, reject) => {
      let client: typeof http | typeof https = http;
      if (urlStr.startsWith('https:')) client = https;

      const fileStream = fs.createWriteStream(destPath);
      let downloadedBytes = 0;

      const req = client.get(urlStr, { timeout: 30000 }, (res) => {
        if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
          fileStream.close();
          return reject(new Error(`HTTP ${res.statusCode} while downloading update package`));
        }

        res.on('data', (chunk: Buffer) => {
          if (this.isCancelled) {
            res.destroy();
            fileStream.close();
            return;
          }
          downloadedBytes += chunk.length;
          fileStream.write(chunk);

          const percent = expectedSize > 0 ? Math.min(100, Math.round((downloadedBytes / expectedSize) * 100)) : 0;
          this.status.download_progress = {
            percent,
            bytes_transferred: downloadedBytes,
            total_bytes: expectedSize,
          };

          if (this.broadcaster) {
            this.broadcaster({
              type: 'updater_progress',
              percent,
              bytes_transferred: downloadedBytes,
              total_bytes: expectedSize,
            });
          }
        });

        res.on('end', () => {
          fileStream.end(() => {
            resolve();
          });
        });

        res.on('error', (err) => {
          fileStream.close();
          reject(err);
        });
      });

      this.activeDownloadRequest = req;

      req.on('error', (err) => {
        fileStream.close();
        reject(new Error(`Network error during artifact download: ${err.message}`));
      });

      req.on('timeout', () => {
        req.destroy();
        fileStream.close();
        reject(new Error('Artifact download timed out after 30000ms'));
      });
    });
  }
}
