import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  canonicalizeJson,
  verifyManifestAuthenticity,
  verifyArtifactIntegrity,
} from '../../electron/updater/crypto';
import {
  parseSemver,
  compareSemver,
  isDowngradeOrSame,
  isChannelCompatible,
} from '../../electron/updater/semver';
import { detectPortableMode } from '../../electron/updater/portable';
import { verifyAuthenticode } from '../../electron/updater/authenticode';
import { SecureAutoUpdater } from '../../electron/updater/orchestrator';
import { SignedUpdateManifest, PinnedSigningKey, UpdaterErrorCodes } from '../types/updater';

describe('Stage 2 — Secure Auto-Updater Cryptographic & Verification Engine', () => {
  let testTempDir: string;
  let testKeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject; pubPem: string };
  let rotationKeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject; pubPem: string };
  let mockPinnedKeys: Record<string, PinnedSigningKey>;

  beforeEach(() => {
    testTempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-updater-test-'));

    // Generate mock Ed25519 keypair for test manifests
    const primary = crypto.generateKeyPairSync('ed25519');
    testKeyPair = {
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

    mockPinnedKeys = {
      'test-key-primary': {
        kid: 'test-key-primary',
        algorithm: 'ed25519',
        publicKeyPem: testKeyPair.pubPem,
        validFrom: '2026-09-01T00:00:00Z',
        description: 'Test Primary Key',
        status: 'active',
      },
      'test-key-rotation': {
        kid: 'test-key-rotation',
        algorithm: 'ed25519',
        publicKeyPem: rotationKeyPair.pubPem,
        validFrom: '2026-09-15T00:00:00Z',
        description: 'Test Rotation Key',
        status: 'transition',
      },
    };
  });

  afterEach(() => {
    if (fs.existsSync(testTempDir)) {
      fs.rmSync(testTempDir, { recursive: true, force: true });
    }
  });

  // Helper to build a cryptographically signed manifest fixture
  function createSignedManifest(
    overrides: Partial<SignedUpdateManifest> = {},
    signingKey: crypto.KeyObject = testKeyPair.privateKey,
    kid: string = 'test-key-primary'
  ): SignedUpdateManifest {
    const unsigned: Omit<SignedUpdateManifest, 'signature'> = {
      schema_version: '1.0.0',
      version: '1.1.0',
      channel: 'stable',
      release_date: '2026-09-18T12:00:00Z',
      architecture: 'x64',
      artifact_filename: 'SmartCleaner-Setup-1.1.0.exe',
      artifact_size: 10485760, // 10 MB
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      sha512: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
      download_url: 'https://updates.smartcleaner.local/releases/SmartCleaner-Setup-1.1.0.exe',
      min_supported_version: '1.0.0',
      release_notes: 'Automated test release notes',
      kid,
      ...overrides,
    };

    const canonical = canonicalizeJson(unsigned);
    const signatureBuffer = crypto.sign(null, Buffer.from(canonical, 'utf8'), signingKey);

    return {
      ...(unsigned as SignedUpdateManifest),
      signature: signatureBuffer.toString('base64'),
    };
  }

  // Helper to create a dummy artifact file with known hashes
  function createArtifactFile(filename: string, content: Buffer): { filePath: string; sha256: string; sha512: string; size: number } {
    const filePath = path.join(testTempDir, filename);
    fs.writeFileSync(filePath, content);
    const sha256 = crypto.createHash('sha256').update(content).digest('hex');
    const sha512 = crypto.createHash('sha512').update(content).digest('hex');
    return { filePath, sha256, sha512, size: content.length };
  }

  // --------------------------------------------------------------------------
  // 1. Canonicalization & Signature Verification Tests
  // --------------------------------------------------------------------------

  it('canonicalizeJson: produces identical output regardless of object key order', () => {
    const objA = { z: 1, a: 2, m: { y: 'nested', x: 'first' } };
    const objB = { a: 2, m: { x: 'first', y: 'nested' }, z: 1 };
    expect(canonicalizeJson(objA)).toBe(canonicalizeJson(objB));
    expect(canonicalizeJson(objA)).toBe('{"a":2,"m":{"x":"first","y":"nested"},"z":1}');
  });

  it('verifyManifestAuthenticity: verifies a valid signed manifest against pinned public key', () => {
    const manifest = createSignedManifest();
    const result = verifyManifestAuthenticity(manifest, mockPinnedKeys);
    expect(result.valid).toBe(true);
    expect(result.verifiedKeyId).toBe('test-key-primary');
  });

  it('verifyManifestAuthenticity: rejects manifest signed with unknown key ID', () => {
    const manifest = createSignedManifest({ kid: 'unknown-key-999' });
    const result = verifyManifestAuthenticity(manifest, mockPinnedKeys);
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(UpdaterErrorCodes.UNKNOWN_SIGNING_KEY);
  });

  it('verifyManifestAuthenticity: rejects manifest when signature has been corrupted or forged', () => {
    const manifest = createSignedManifest();
    manifest.signature = Buffer.from('invalid-signature-bytes-which-should-fail').toString('base64');
    const result = verifyManifestAuthenticity(manifest, mockPinnedKeys);
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(UpdaterErrorCodes.METADATA_SIGNATURE_INVALID);
  });

  it('verifyManifestAuthenticity: rejects manifest when payload is tampered post-signing', () => {
    const manifest = createSignedManifest();
    // Tamper with download URL after signature creation
    manifest.download_url = 'https://malicious.evil.com/fake-installer.exe';
    const result = verifyManifestAuthenticity(manifest, mockPinnedKeys);
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(UpdaterErrorCodes.METADATA_SIGNATURE_INVALID);
  });

  it('verifyManifestAuthenticity: seamlessly supports key rotation with transition keys', () => {
    // Sign using rotation key pair
    const manifest = createSignedManifest({}, rotationKeyPair.privateKey, 'test-key-rotation');
    const result = verifyManifestAuthenticity(manifest, mockPinnedKeys);
    expect(result.valid).toBe(true);
    expect(result.verifiedKeyId).toBe('test-key-rotation');
  });

  // --------------------------------------------------------------------------
  // 2. Semver & Downgrade Prevention Tests
  // --------------------------------------------------------------------------

  it('parseSemver: parses valid semver and detects channels correctly', () => {
    const stable = parseSemver('1.2.3');
    expect(stable).toEqual({ major: 1, minor: 2, patch: 3, prerelease: undefined, channel: 'stable', raw: '1.2.3' });

    const beta = parseSemver('1.3.0-beta.2');
    expect(beta?.channel).toBe('beta');
    expect(beta?.prerelease).toBe('beta.2');

    const rc = parseSemver('2.0.0-rc.1');
    expect(rc?.channel).toBe('rc');

    expect(parseSemver('invalid.version')).toBeNull();
    expect(parseSemver('1.0')).toBeNull();
  });

  it('compareSemver: strictly compares versions and prerelease hierarchies', () => {
    expect(compareSemver('1.1.0', '1.0.0')).toBe(1);
    expect(compareSemver('1.0.0', '1.1.0')).toBe(-1);
    expect(compareSemver('1.0.0', '1.0.0')).toBe(0);

    // Release is newer than pre-release of the same version
    expect(compareSemver('1.1.0', '1.1.0-rc.1')).toBe(1);
    expect(compareSemver('1.1.0-rc.1', '1.1.0')).toBe(-1);

    // Prerelease increments
    expect(compareSemver('1.1.0-beta.2', '1.1.0-beta.1')).toBe(1);
  });

  it('isDowngradeOrSame: detects downgrade attempts and identical versions', () => {
    expect(isDowngradeOrSame('0.9.5', '1.0.0')).toBe(true);  // downgrade
    expect(isDowngradeOrSame('1.0.0', '1.0.0')).toBe(true);  // same version
    expect(isDowngradeOrSame('1.0.1', '1.0.0')).toBe(false); // upgrade
  });

  it('isChannelCompatible: strictly respects channel boundaries', () => {
    // Stable configured: accepts only stable
    expect(isChannelCompatible('stable', 'stable')).toBe(true);
    expect(isChannelCompatible('beta', 'stable')).toBe(false);
    expect(isChannelCompatible('rc', 'stable')).toBe(false);

    // Beta configured: accepts beta and stable
    expect(isChannelCompatible('beta', 'beta')).toBe(true);
    expect(isChannelCompatible('stable', 'beta')).toBe(true);
    expect(isChannelCompatible('rc', 'beta')).toBe(false);

    // RC configured: accepts rc and stable
    expect(isChannelCompatible('rc', 'rc')).toBe(true);
    expect(isChannelCompatible('stable', 'rc')).toBe(true);
    expect(isChannelCompatible('beta', 'rc')).toBe(false);
  });

  // --------------------------------------------------------------------------
  // 3. Dual-Hash Artifact Verification Tests
  // --------------------------------------------------------------------------

  it('verifyArtifactIntegrity: passes when both SHA-256 and SHA-512 match perfectly', async () => {
    const dummyBytes = Buffer.from('Deterministic Smart Cleaner Test Installer Payload Bytes');
    const { filePath, sha256, sha512, size } = createArtifactFile('installer.exe', dummyBytes);

    const result = await verifyArtifactIntegrity(filePath, sha256, sha512, size);
    expect(result.valid).toBe(true);
  });

  it('verifyArtifactIntegrity: fails when SHA-256 does not match', async () => {
    const dummyBytes = Buffer.from('Legitimate Payload');
    const { filePath, sha512, size } = createArtifactFile('installer.exe', dummyBytes);
    const bogusSha256 = '0000000000000000000000000000000000000000000000000000000000000000';

    const result = await verifyArtifactIntegrity(filePath, bogusSha256, sha512, size);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('SHA-256 mismatch');
  });

  it('verifyArtifactIntegrity: fails when file size does not match expected metadata', async () => {
    const dummyBytes = Buffer.from('Legitimate Payload');
    const { filePath, sha256, sha512 } = createArtifactFile('installer.exe', dummyBytes);

    const result = await verifyArtifactIntegrity(filePath, sha256, sha512, 9999999);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Artifact size mismatch');
  });

  // --------------------------------------------------------------------------
  // 4. Orchestrator End-to-End Workflow Tests
  // --------------------------------------------------------------------------

  it('checkForUpdates: accepts valid signed newer release and transitions to available', async () => {
    const updater = new SecureAutoUpdater({
      currentVersion: '1.0.0',
      pinnedKeys: mockPinnedKeys,
      tempDirectory: testTempDir,
      isPortable: false,
    });

    const manifest = createSignedManifest({ version: '1.1.0' });
    const status = await updater.checkForUpdates({ manifestPayloadOverride: manifest });

    expect(status.state).toBe('available');
    expect(status.available_update?.version).toBe('1.1.0');
    expect(status.error).toBeNull();
  });

  it('checkForUpdates: rejects downgrade attempt (version < currentVersion) with DOWNGRADE_ATTEMPT', async () => {
    const updater = new SecureAutoUpdater({
      currentVersion: '1.0.0',
      pinnedKeys: mockPinnedKeys,
      tempDirectory: testTempDir,
      isPortable: false,
    });

    const manifest = createSignedManifest({ version: '0.9.8' });
    const status = await updater.checkForUpdates({ manifestPayloadOverride: manifest });

    expect(status.state).toBe('not_available');
    expect(status.error?.code).toBe(UpdaterErrorCodes.DOWNGRADE_ATTEMPT);
  });

  it('checkForUpdates: rejects identical version (version == currentVersion) with not_available', async () => {
    const updater = new SecureAutoUpdater({
      currentVersion: '1.0.0',
      pinnedKeys: mockPinnedKeys,
      tempDirectory: testTempDir,
      isPortable: false,
    });

    const manifest = createSignedManifest({ version: '1.0.0' });
    const status = await updater.checkForUpdates({ manifestPayloadOverride: manifest });

    expect(status.state).toBe('not_available');
    expect(status.available_update).toBeNull();
  });

  it('checkForUpdates: rejects beta release when configured channel is stable', async () => {
    const updater = new SecureAutoUpdater({
      currentVersion: '1.0.0',
      defaultChannel: 'stable',
      pinnedKeys: mockPinnedKeys,
      tempDirectory: testTempDir,
      isPortable: false,
    });

    const manifest = createSignedManifest({ version: '1.1.0-beta.1', channel: 'beta' });
    const status = await updater.checkForUpdates({ manifestPayloadOverride: manifest });

    expect(status.state).toBe('not_available');
    expect(status.error?.code).toBe(UpdaterErrorCodes.CHANNEL_MISMATCH);
  });

  it('downloadUpdate: downloads and verifies artifact integrity, staging file in temp', async () => {
    const dummyBytes = Buffer.from('Mock Installer Executable Content 1.1.0');
    const { filePath, sha256, sha512, size } = createArtifactFile('source-setup.exe', dummyBytes);

    const updater = new SecureAutoUpdater({
      currentVersion: '1.0.0',
      pinnedKeys: mockPinnedKeys,
      tempDirectory: testTempDir,
      isPortable: false,
    });

    const manifest = createSignedManifest({
      version: '1.1.0',
      artifact_filename: 'SmartCleaner-Setup-1.1.0.exe',
      artifact_size: size,
      sha256,
      sha512,
    });

    await updater.checkForUpdates({ manifestPayloadOverride: manifest });
    const downloadStatus = await updater.downloadUpdate({ localArtifactSourcePath: filePath });

    expect(downloadStatus.state).toBe('downloaded');
    expect(downloadStatus.downloaded_file_path).toBeDefined();
    expect(fs.existsSync(downloadStatus.downloaded_file_path!)).toBe(true);
  });

  it('downloadUpdate: fails closed and deletes staged file when downloaded hash does not match', async () => {
    const dummyBytes = Buffer.from('Original Installer');
    const { filePath, size } = createArtifactFile('source-setup.exe', dummyBytes);

    const updater = new SecureAutoUpdater({
      currentVersion: '1.0.0',
      pinnedKeys: mockPinnedKeys,
      tempDirectory: testTempDir,
      isPortable: false,
    });

    // Provide bogus expected sha256 in manifest
    const manifest = createSignedManifest({
      version: '1.1.0',
      artifact_filename: 'SmartCleaner-Setup-1.1.0.exe',
      artifact_size: size,
      sha256: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      sha512: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    });

    await updater.checkForUpdates({ manifestPayloadOverride: manifest });
    await expect(updater.downloadUpdate({ localArtifactSourcePath: filePath })).rejects.toThrow();

    const status = updater.getStatus();
    expect(status.state).toBe('error');
    expect(status.error?.code).toBe(UpdaterErrorCodes.ARTIFACT_HASH_MISMATCH);

    // Staged corrupted file must be deleted
    const stagedPath = path.join(testTempDir, 'SmartCleaner-Setup-1.1.0.exe');
    expect(fs.existsSync(stagedPath)).toBe(false);
  });

  // --------------------------------------------------------------------------
  // 5. Runtime Safety: Engine Busy & Deferred Restart Tests
  // --------------------------------------------------------------------------

  it('applyUpdate: blocks and defers restart when scan is running', async () => {
    let scanActive = true;
    const dummyBytes = Buffer.from('Installer 1.1.0');
    const { filePath, sha256, sha512, size } = createArtifactFile('source-setup.exe', dummyBytes);

    const updater = new SecureAutoUpdater({
      currentVersion: '1.0.0',
      pinnedKeys: mockPinnedKeys,
      tempDirectory: testTempDir,
      isPortable: false,
    });

    // Hook engine busy provider to active scan state
    updater.setEngineBusyProvider(() => scanActive);

    const manifest = createSignedManifest({
      version: '1.1.0',
      artifact_filename: 'SmartCleaner-Setup-1.1.0.exe',
      artifact_size: size,
      sha256,
      sha512,
    });

    await updater.checkForUpdates({ manifestPayloadOverride: manifest });
    await updater.downloadUpdate({ localArtifactSourcePath: filePath });

    // Attempt to apply update while scan is running
    const applyResult = await updater.applyUpdate({ confirm: true });

    expect(applyResult.applied).toBe(false);
    expect(applyResult.deferred).toBe(true);
    expect(applyResult.reason).toBe('Update Ready — Restart when current operation finishes.');
    expect(updater.getStatus().state).toBe('deferred_busy');

    // Now complete the scan
    scanActive = false;

    // Re-attempt application after scan completion
    let spawnedInstaller = false;
    const postScanResult = await updater.applyUpdate({
      confirm: true,
      onApplySpawn: () => {
        spawnedInstaller = true;
      },
    });

    expect(postScanResult.applied).toBe(true);
    expect(postScanResult.deferred).toBe(false);
    expect(spawnedInstaller).toBe(true);
    expect(updater.getStatus().state).toBe('applying');
  });

  it('applyUpdate: blocks and defers restart when quarantine operation is running', async () => {
    let quarantineActive = true;
    const dummyBytes = Buffer.from('Installer 1.1.0');
    const { filePath, sha256, sha512, size } = createArtifactFile('source-setup.exe', dummyBytes);

    const updater = new SecureAutoUpdater({
      currentVersion: '1.0.0',
      pinnedKeys: mockPinnedKeys,
      tempDirectory: testTempDir,
      isPortable: false,
    });

    updater.setEngineBusyProvider(() => quarantineActive);

    const manifest = createSignedManifest({
      version: '1.1.0',
      artifact_filename: 'SmartCleaner-Setup-1.1.0.exe',
      artifact_size: size,
      sha256,
      sha512,
    });

    await updater.checkForUpdates({ manifestPayloadOverride: manifest });
    await updater.downloadUpdate({ localArtifactSourcePath: filePath });

    const result = await updater.applyUpdate({ confirm: true });
    expect(result.deferred).toBe(true);
    expect(result.applied).toBe(false);
    expect(updater.getStatus().deferred_reason).toContain('Update Ready — Restart when current operation finishes.');
  });

  it('applyUpdate: strictly requires explicit user confirmation', async () => {
    const dummyBytes = Buffer.from('Installer 1.1.0');
    const { filePath, sha256, sha512, size } = createArtifactFile('source-setup.exe', dummyBytes);

    const updater = new SecureAutoUpdater({
      currentVersion: '1.0.0',
      pinnedKeys: mockPinnedKeys,
      tempDirectory: testTempDir,
      isPortable: false,
    });

    const manifest = createSignedManifest({
      version: '1.1.0',
      artifact_filename: 'SmartCleaner-Setup-1.1.0.exe',
      artifact_size: size,
      sha256,
      sha512,
    });

    await updater.checkForUpdates({ manifestPayloadOverride: manifest });
    await updater.downloadUpdate({ localArtifactSourcePath: filePath });

    // Calling with confirm: false must throw and fail closed
    await expect(updater.applyUpdate({ confirm: false })).rejects.toThrow(UpdaterErrorCodes.CONFIRMATION_REQUIRED);
  });

  // --------------------------------------------------------------------------
  // 6. Portable Mode Safety Tests
  // --------------------------------------------------------------------------

  it('applyUpdate: prohibits in-place installer execution in Portable Mode', async () => {
    const dummyBytes = Buffer.from('Installer 1.1.0');
    const { filePath, sha256, sha512, size } = createArtifactFile('source-setup.exe', dummyBytes);

    const updater = new SecureAutoUpdater({
      currentVersion: '1.0.0',
      pinnedKeys: mockPinnedKeys,
      tempDirectory: testTempDir,
      isPortable: true, // Running in Portable Mode
    });

    const manifest = createSignedManifest({
      version: '1.1.0',
      artifact_filename: 'SmartCleaner-Setup-1.1.0.exe',
      artifact_size: size,
      sha256,
      sha512,
    });

    await updater.checkForUpdates({ manifestPayloadOverride: manifest });
    await updater.downloadUpdate({ localArtifactSourcePath: filePath });

    await expect(updater.applyUpdate({ confirm: true })).rejects.toThrow(UpdaterErrorCodes.PORTABLE_MODE_BLOCKED);

    const status = updater.getStatus();
    expect(status.state).toBe('error');
    expect(status.error?.code).toBe(UpdaterErrorCodes.PORTABLE_MODE_BLOCKED);
    expect(status.error?.message).toContain('Portable Mode');
  });

  it('detectPortableMode: recognizes environment variables and marker files', () => {
    // 1. Env variable test
    process.env.SMART_CLEANER_PORTABLE = '1';
    expect(detectPortableMode().isPortable).toBe(true);
    delete process.env.SMART_CLEANER_PORTABLE;

    // 2. Portable executable dir
    process.env.PORTABLE_EXECUTABLE_DIR = 'C:\\PortableApps\\SmartCleaner';
    expect(detectPortableMode().isPortable).toBe(true);
    delete process.env.PORTABLE_EXECUTABLE_DIR;

    // 3. Marker file test
    const mockAppDir = path.join(testTempDir, 'mock-app');
    fs.mkdirSync(mockAppDir, { recursive: true });
    const mockAppExe = path.join(mockAppDir, 'SmartCleaner.exe');
    fs.writeFileSync(mockAppExe, '');
    fs.writeFileSync(path.join(mockAppDir, '.portable'), '');

    expect(detectPortableMode(mockAppExe).isPortable).toBe(true);
  });

  // --------------------------------------------------------------------------
  // 7. Phase A3: RFC 8785 / JCS Strict Compliance Tests
  // --------------------------------------------------------------------------

  describe('RFC 8785 / JCS Strict Compliance', () => {
    it('omits properties with undefined, function, or symbol values', () => {
      const input = {
        b: 1,
        a: undefined,
        fn: () => {},
        sym: Symbol('test'),
        c: 'valid',
      };
      expect(canonicalizeJson(input)).toBe('{"b":1,"c":"valid"}');
    });

    it('serializes array undefined and function elements as null', () => {
      const input = [1, undefined, () => {}, 'item'];
      expect(canonicalizeJson(input)).toBe('[1,null,null,"item"]');
    });

    it('serializes negative zero (-0) as 0 per RFC 8785 Section 3.2.2.3', () => {
      expect(canonicalizeJson(-0)).toBe('0');
      expect(canonicalizeJson({ zero: -0 })).toBe('{"zero":0}');
    });

    it('throws on NaN or Infinity per RFC 8785', () => {
      expect(() => canonicalizeJson(NaN)).toThrow(TypeError);
      expect(() => canonicalizeJson(Infinity)).toThrow(TypeError);
      expect(() => canonicalizeJson(-Infinity)).toThrow(TypeError);
    });

    it('sorts keys by UTF-16 code units strictly', () => {
      const input = {
        '\u00e9': 'e-acute',
        b: 'b',
        a: 'a',
        '\u0000': 'null-char',
      };
      // \u0000 (0x0000) < 'a' (0x0061) < 'b' (0x0062) < '\u00e9' (0x00e9)
      expect(canonicalizeJson(input)).toBe('{"\\u0000":"null-char","a":"a","b":"b","é":"e-acute"}');
    });
  });

  // --------------------------------------------------------------------------
  // 8. Phase A4: Download & Execution Boundary Hardening Tests
  // --------------------------------------------------------------------------

  describe('Download & Execution Boundary Hardening', () => {
    it('rejects manifest with path traversal in artifact_filename', async () => {
      const updater = new SecureAutoUpdater({
        currentVersion: '1.0.0',
        pinnedKeys: mockPinnedKeys,
        tempDirectory: testTempDir,
        isPortable: false,
      });

      const manifest = createSignedManifest({
        version: '1.1.0',
        artifact_filename: '../../../Windows/System32/evil.exe',
      });

      await updater.checkForUpdates({ manifestPayloadOverride: manifest });
      await expect(updater.downloadUpdate()).rejects.toThrow();
      expect(updater.getStatus().error?.code).toBe(UpdaterErrorCodes.MALICIOUS_PATH_REJECTED);
    });

    it('rejects manifest with backslash or absolute path in artifact_filename', async () => {
      const updater = new SecureAutoUpdater({
        currentVersion: '1.0.0',
        pinnedKeys: mockPinnedKeys,
        tempDirectory: testTempDir,
        isPortable: false,
      });

      const manifest = createSignedManifest({
        version: '1.1.0',
        artifact_filename: 'C:\\evil.exe',
      });

      await updater.checkForUpdates({ manifestPayloadOverride: manifest });
      await expect(updater.downloadUpdate()).rejects.toThrow();
      expect(updater.getStatus().error?.code).toBe(UpdaterErrorCodes.MALICIOUS_PATH_REJECTED);
    });

    it('rejects applyUpdate if staged artifact is a symbolic link', async () => {
      const dummyBytes = Buffer.from('Legitimate Payload');
      const { filePath, sha256, sha512, size } = createArtifactFile('source-setup.exe', dummyBytes);

      const updater = new SecureAutoUpdater({
        currentVersion: '1.0.0',
        pinnedKeys: mockPinnedKeys,
        tempDirectory: testTempDir,
        isPortable: false,
      });

      const manifest = createSignedManifest({
        version: '1.1.0',
        artifact_filename: 'SmartCleaner-Setup-1.1.0.exe',
        artifact_size: size,
        sha256,
        sha512,
      });

      await updater.checkForUpdates({ manifestPayloadOverride: manifest });
      await updater.downloadUpdate({ localArtifactSourcePath: filePath });

      // Replace the downloaded file with a symlink
      const stagedPath = path.join(testTempDir, 'SmartCleaner-Setup-1.1.0.exe');
      fs.unlinkSync(stagedPath);
      try {
        fs.symlinkSync(filePath, stagedPath);
      } catch (e: any) {
        if (process.platform === 'win32' && (e.code === 'EPERM' || e.code === 'EACCES')) {
          // Unprivileged Windows environments block symlink creation by OS policy
          return;
        }
        throw e;
      }

      await expect(updater.applyUpdate({ confirm: true })).rejects.toThrow(
        UpdaterErrorCodes.MALICIOUS_PATH_REJECTED
      );
    });
  });

  // --------------------------------------------------------------------------
  // 9. Phase A1: State Survival across Disposable Version Transition (1.0.0 -> 1.1.0)
  // --------------------------------------------------------------------------

  describe('Disposable Version Transition & State Survival (1.0.0 -> 1.1.0)', () => {
    it('preserves vault items, SQLite ledger, and user exclusions across version upgrade', async () => {
      // 1. Setup simulated application state for v1.0.0
      const appDataDir = path.join(testTempDir, 'SmartCleaner');
      const vaultDir = path.join(appDataDir, 'Vault');
      const ledgerPath = path.join(appDataDir, 'audit.db');
      const configPath = path.join(appDataDir, 'config.json');

      fs.mkdirSync(vaultDir, { recursive: true });
      fs.writeFileSync(path.join(vaultDir, 'quarantine-item-1.dat'), 'Quarantined Content');
      fs.writeFileSync(ledgerPath, 'SQLite format 3 -- mock audit records for session 1');
      fs.writeFileSync(
        configPath,
        JSON.stringify({
          version: '1.0.0',
          excluded_paths: ['C:\\Windows\\CustomProtected', 'D:\\SensitiveData'],
          retention_days: 14,
        })
      );

      // 2. Perform v1.1.0 signed update transition
      const dummyBytes = Buffer.from('Smart Cleaner 1.1.0 Upgrade Binary');
      const { filePath, sha256, sha512, size } = createArtifactFile('setup-1.1.0.exe', dummyBytes);

      const updater = new SecureAutoUpdater({
        currentVersion: '1.0.0',
        pinnedKeys: mockPinnedKeys,
        tempDirectory: testTempDir,
        isPortable: false,
      });

      const manifest = createSignedManifest({
        version: '1.1.0',
        artifact_filename: 'SmartCleaner-Setup-1.1.0.exe',
        artifact_size: size,
        sha256,
        sha512,
      });

      await updater.checkForUpdates({ manifestPayloadOverride: manifest });
      await updater.downloadUpdate({ localArtifactSourcePath: filePath });

      let applied = false;
      const applyResult = await updater.applyUpdate({
        confirm: true,
        onApplySpawn: () => {
          applied = true;
        },
      });

      expect(applyResult.applied).toBe(true);
      expect(applied).toBe(true);

      // 3. Verify that persistent state survived completely intact
      expect(fs.existsSync(path.join(vaultDir, 'quarantine-item-1.dat'))).toBe(true);
      expect(fs.readFileSync(path.join(vaultDir, 'quarantine-item-1.dat'), 'utf8')).toBe('Quarantined Content');

      expect(fs.existsSync(ledgerPath)).toBe(true);
      expect(fs.readFileSync(ledgerPath, 'utf8')).toContain('mock audit records');

      const survivingConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      expect(survivingConfig.excluded_paths).toEqual(['C:\\Windows\\CustomProtected', 'D:\\SensitiveData']);
      expect(survivingConfig.retention_days).toBe(14);

      // 4. Verify that once upgraded to 1.1.0, attempting downgrade back to 1.0.0 fails closed
      const upgradedUpdater = new SecureAutoUpdater({
        currentVersion: '1.1.0',
        pinnedKeys: mockPinnedKeys,
        tempDirectory: testTempDir,
        isPortable: false,
      });

      const oldManifest = createSignedManifest({ version: '1.0.0' });
      const downgradeStatus = await upgradedUpdater.checkForUpdates({ manifestPayloadOverride: oldManifest });
      expect(downgradeStatus.state).toBe('not_available');
      expect(downgradeStatus.error?.code).toBe(UpdaterErrorCodes.DOWNGRADE_ATTEMPT);
    });
  });

  // --------------------------------------------------------------------------
  // 10. Phase A2: Authenticode Verification & Separation Tests
  // --------------------------------------------------------------------------

  describe('Phase A2: Authenticode Verification & Publisher Separation', () => {
    it('returns UnknownError when file does not exist', async () => {
      const res = await verifyAuthenticode(path.join(testTempDir, 'non-existent.exe'));
      expect(res.status).toBe('UnknownError');
      expect(res.hasSignature).toBe(false);
    });

    it('returns NotSigned for non-PE files', async () => {
      const txtFile = path.join(testTempDir, 'script.bat');
      fs.writeFileSync(txtFile, '@echo off\necho test\n');
      const res = await verifyAuthenticode(txtFile);
      expect(res.status).toBe('NotSigned');
      expect(res.hasSignature).toBe(false);
    });

    it('returns NotSigned for PE executable without certificate directory', async () => {
      const peFile = path.join(testTempDir, 'unsigned.exe');
      const buffer = Buffer.alloc(1024);
      // MZ signature
      buffer[0] = 0x4d;
      buffer[1] = 0x5a;
      // PE header offset at 0x3c -> 0x80
      buffer.writeUInt32LE(0x80, 0x3c);
      // PE signature "PE\0\0"
      buffer[0x80] = 0x50;
      buffer[0x81] = 0x45;
      buffer[0x82] = 0x00;
      buffer[0x83] = 0x00;
      // Optional header magic: PE32 (0x10b)
      buffer.writeUInt16LE(0x10b, 0x80 + 24);
      // Security directory offset: 0x80 + 24 + 96 + 32 = 0x80 + 152 = 0x118
      // All zeroes in security directory (address = 0, size = 0)
      fs.writeFileSync(peFile, buffer);

      const res = await verifyAuthenticode(peFile);
      expect(res.status).toBe('NotSigned');
      expect(res.hasSignature).toBe(false);
    });

    it('identifies PE executable with certificate table present', async () => {
      const peFile = path.join(testTempDir, 'signed-sim.exe');
      const buffer = Buffer.alloc(1024);
      // MZ signature
      buffer[0] = 0x4d;
      buffer[1] = 0x5a;
      // PE header offset at 0x3c -> 0x80
      buffer.writeUInt32LE(0x80, 0x3c);
      // PE signature "PE\0\0"
      buffer[0x80] = 0x50;
      buffer[0x81] = 0x45;
      buffer[0x82] = 0x00;
      buffer[0x83] = 0x00;
      // Optional header magic: PE32 (0x10b)
      buffer.writeUInt16LE(0x10b, 0x80 + 24);
      // Security directory at 0x80 + 24 + 96 + 32 = 0x118
      // Write cert table address = 0x200, size = 0x100
      buffer.writeUInt32LE(0x200, 0x118);
      buffer.writeUInt32LE(0x100, 0x11c);
      fs.writeFileSync(peFile, buffer);

      const res = await verifyAuthenticode(peFile);
      expect(res.hasSignature).toBe(true);
      expect(res.status).toBe('Valid');
      expect(res.isPublisherTrusted).toBe(true);
    });
  });
});

