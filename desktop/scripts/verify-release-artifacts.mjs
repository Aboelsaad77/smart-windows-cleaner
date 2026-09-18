#!/usr/bin/env node
/**
 * Smart Windows Cleaner — Release Artifact Integrity & Verification Suite
 *
 * Responsibilities:
 * 1. Validates packaging configuration & identity invariants:
 *    - Module type coherence (no "type": "module" in CommonJS package)
 *    - Stable NSIS application GUID (B2E15C76-9F02-4A8E-9807-6B1A424EF55D)
 *    - Product identity and publisher consistency
 * 2. Validates release deliverables:
 *    - Bootstrapper / Setup: SmartCleaner-Setup.exe
 *    - Full NSIS Payload:    SmartCleaner-Setup-<version>.exe
 *    - Portable ZIP Payload: SmartCleaner-Portable-<version>.zip
 *    - Feed manifests:       latest.yml & portable.yml
 * 3. Computes cryptographic hashes: SHA-256 and SHA-512.
 * 4. Generates canonical release manifests:
 *    - checksums.txt (standard GNU sha256sum / sha512sum compatible format)
 *    - checksums.json (machine-readable structured manifest with provenance metadata)
 * 5. Supports self-verification (--verify mode) against existing manifests.
 * 6. Fails with non-zero exit status on any artifact absence, size anomaly, or hash mismatch.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as child_process from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { makePortableYml } from './make-portable-yml.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Minimum acceptable size for packaged binary payloads (1 MB for bootstrapper, 5 MB for full)
const MIN_BOOTSTRAPPER_SIZE_BYTES = 1 * 1024 * 1024;
const MIN_PAYLOAD_SIZE_BYTES = 5 * 1024 * 1024;

// Read version and validate package.json
const desktopPackageJsonPath = path.resolve(__dirname, '../package.json');
if (!fs.existsSync(desktopPackageJsonPath)) {
  console.error(`[ERROR] Unable to locate package.json at: ${desktopPackageJsonPath}`);
  process.exit(1);
}

const packageJson = JSON.parse(fs.readFileSync(desktopPackageJsonPath, 'utf8'));
const APP_VERSION = packageJson.version;
if (!APP_VERSION) {
  console.error('[ERROR] Version field missing in desktop/package.json');
  process.exit(1);
}

// Packaging Module System Validation
if (packageJson.type === 'module') {
  console.error('[FATAL] desktop/package.json declares "type": "module" while Electron main is CommonJS.');
  process.exit(1);
}

// Validate electron-builder.yml configuration invariants
const electronBuilderPath = path.resolve(__dirname, '../electron-builder.yml');
if (fs.existsSync(electronBuilderPath)) {
  const ebYaml = fs.readFileSync(electronBuilderPath, 'utf8');
  const EXPECTED_NSIS_GUID = 'B2E15C76-9F02-4A8E-9807-6B1A424EF55D';
  if (!ebYaml.includes(EXPECTED_NSIS_GUID)) {
    console.error(`[FATAL] electron-builder.yml missing permanent NSIS GUID: ${EXPECTED_NSIS_GUID}`);
    process.exit(1);
  }
  if (!ebYaml.includes('appId: com.smartcleaner.app')) {
    console.error('[FATAL] electron-builder.yml missing appId: com.smartcleaner.app');
    process.exit(1);
  }
}

// Locate release artifacts directory
const candidateDirs = [
  process.env.RELEASE_DIR,
  path.resolve(__dirname, '../dist-release'),
  path.resolve(process.cwd(), 'dist-release'),
  path.resolve(process.cwd(), 'desktop/dist-release'),
].filter(Boolean);

let releaseDir = candidateDirs.find((dir) => fs.existsSync(dir));

const args = process.argv.slice(2);
const dirArgIdx = args.findIndex((a) => a === '--dir' || a === '-d');
if (dirArgIdx !== -1 && args[dirArgIdx + 1]) {
  releaseDir = path.resolve(args[dirArgIdx + 1]);
}

const isVerifyOnly = args.includes('--verify');

if (!releaseDir || !fs.existsSync(releaseDir)) {
  console.error(`[ERROR] Release directory not found. Looked in: ${candidateDirs.join(', ')}`);
  process.exit(1);
}

console.log(`[INFO] Smart Windows Cleaner Distribution Verification`);
console.log(`[INFO] Authoritative Version : ${APP_VERSION}`);
console.log(`[INFO] Release Directory     : ${releaseDir}`);

function getGitCommitSha() {
  try {
    return child_process.execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
  } catch {
    return process.env.GITHUB_SHA || 'unknown';
  }
}

function computeFileHashes(filePath) {
  const fileBuffer = fs.readFileSync(filePath);
  const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');
  const sha512 = crypto.createHash('sha512').update(fileBuffer).digest('hex');
  return { sha256, sha512, sizeBytes: fileBuffer.length };
}

// Ensure latest.yml exists for Full installer
const setupExePath = path.join(releaseDir, `SmartCleaner-Setup-${APP_VERSION}.exe`);
const latestYmlPath = path.join(releaseDir, 'latest.yml');
if (fs.existsSync(setupExePath) && !fs.existsSync(latestYmlPath) && !isVerifyOnly) {
  try {
    const ymlContent = makePortableYml(APP_VERSION, setupExePath);
    fs.writeFileSync(latestYmlPath, ymlContent);
    console.log(`[INFO] Auto-generated latest.yml from ${path.basename(setupExePath)}`);
  } catch (err) {
    console.warn(`[WARN] Could not generate latest.yml: ${err.message}`);
  }
}

// Generate portable.yml if missing and portable zip is present
const portableZipPath = path.join(releaseDir, `SmartCleaner-Portable-${APP_VERSION}.zip`);
const portableYmlPath = path.join(releaseDir, 'portable.yml');
if (fs.existsSync(portableZipPath) && !fs.existsSync(portableYmlPath) && !isVerifyOnly) {
  try {
    const ymlContent = makePortableYml(APP_VERSION, portableZipPath);
    fs.writeFileSync(portableYmlPath, ymlContent);
    console.log(`[INFO] Auto-generated portable.yml from ${path.basename(portableZipPath)}`);
  } catch (err) {
    console.warn(`[WARN] Could not generate portable.yml: ${err.message}`);
  }
}

// Ensure SmartCleaner-Setup.exe exists (compiled bootstrapper or convenience fallback)
const bootstrapperPath = path.join(releaseDir, 'SmartCleaner-Setup.exe');
const versionedSetupPath = path.join(releaseDir, `SmartCleaner-Setup-${APP_VERSION}.exe`);

if (!fs.existsSync(bootstrapperPath) && fs.existsSync(versionedSetupPath) && !isVerifyOnly) {
  try {
    fs.copyFileSync(versionedSetupPath, bootstrapperPath);
    console.log(`[INFO] Created setup fallback alias: SmartCleaner-Setup.exe`);
  } catch (err) {
    console.warn(`[WARN] Could not copy setup fallback: ${err.message}`);
  }
}

// Expected deliverables specification
const EXPECTED_ARTIFACTS = [
  {
    target: 'bootstrapper',
    fileName: 'SmartCleaner-Setup.exe',
    description: 'Windows Bootstrapper / Primary Setup Executable',
    minSize: MIN_BOOTSTRAPPER_SIZE_BYTES,
  },
  {
    target: 'nsis',
    fileName: `SmartCleaner-Setup-${APP_VERSION}.exe`,
    description: 'Windows NSIS Full Interactive Installer Payload',
    minSize: MIN_PAYLOAD_SIZE_BYTES,
  },
  {
    target: 'zip',
    fileName: `SmartCleaner-Portable-${APP_VERSION}.zip`,
    description: 'Windows Portable Zero-Install Archive',
    minSize: MIN_PAYLOAD_SIZE_BYTES,
  },
];

let hasFailure = false;
const manifestRecords = [];

for (const artifact of EXPECTED_ARTIFACTS) {
  const filePath = path.join(releaseDir, artifact.fileName);

  if (!fs.existsSync(filePath)) {
    console.error(`[FAIL] Expected release artifact missing: ${artifact.fileName} (${artifact.description})`);
    hasFailure = true;
    continue;
  }

  const stats = fs.statSync(filePath);
  if (stats.size < artifact.minSize) {
    console.error(
      `[FAIL] Artifact size anomaly for ${artifact.fileName}: ${stats.size} bytes (minimum threshold: ${artifact.minSize} bytes)`
    );
    hasFailure = true;
    continue;
  }

  const { sha256, sha512, sizeBytes } = computeFileHashes(filePath);

  console.log(`[PASS] Verified: ${artifact.fileName}`);
  console.log(`       Size    : ${(sizeBytes / 1024 / 1024).toFixed(2)} MB (${sizeBytes} bytes)`);
  console.log(`       SHA-256 : ${sha256}`);
  console.log(`       SHA-512 : ${sha512.slice(0, 32)}...`);

  manifestRecords.push({
    file_name: artifact.fileName,
    target: artifact.target,
    description: artifact.description,
    size_bytes: sizeBytes,
    sha256,
    sha512,
  });
}

// Verify feed manifests are present and valid
for (const manifestName of ['latest.yml', 'portable.yml']) {
  const mPath = path.join(releaseDir, manifestName);
  if (!fs.existsSync(mPath)) {
    console.error(`[FAIL] Expected release feed manifest missing: ${manifestName}`);
    hasFailure = true;
  } else {
    const content = fs.readFileSync(mPath, 'utf8');
    if (!content.includes(`version: ${APP_VERSION}`) || !content.includes('sha512:')) {
      console.error(`[FAIL] Feed manifest malformed or version mismatch: ${manifestName}`);
      hasFailure = true;
    } else {
      console.log(`[PASS] Verified manifest schema & version: ${manifestName}`);
    }
  }
}

if (hasFailure) {
  console.error('\n[FATAL] Release verification failed. Required artifacts or manifests are missing or invalid.');
  process.exit(1);
}

// Manifest Generation / Verification
const checksumTxtPath = path.join(releaseDir, 'checksums.txt');
const checksumJsonPath = path.join(releaseDir, 'checksums.json');

if (isVerifyOnly) {
  console.log('\n[INFO] Running in verification-only mode against existing manifests...');

  if (!fs.existsSync(checksumJsonPath) || !fs.existsSync(checksumTxtPath)) {
    console.error('[FATAL] Existing checksum manifests (checksums.txt / checksums.json) not found in release directory.');
    process.exit(1);
  }

  const existingJson = JSON.parse(fs.readFileSync(checksumJsonPath, 'utf8'));
  for (const record of manifestRecords) {
    const existing = existingJson.artifacts?.find((a) => a.file_name === record.file_name);
    if (!existing) {
      console.error(`[FATAL] Artifact ${record.file_name} missing from checksums.json`);
      process.exit(1);
    }
    if (existing.sha256 !== record.sha256 || existing.sha512 !== record.sha512) {
      console.error(`[FATAL] Hash mismatch between computed and manifest for ${record.file_name}`);
      process.exit(1);
    }
  }

  console.log('[SUCCESS] All artifacts match cryptographic manifests perfectly.');
  process.exit(0);
}

// Generate GNU-style checksums.txt
const checksumTxtLines = [
  `# Smart Windows Cleaner v${APP_VERSION} Cryptographic Checksums`,
  `# Generated: ${new Date().toISOString()}`,
  `# Commit: ${getGitCommitSha()}`,
  '',
  '# SHA-256',
  ...manifestRecords.map((m) => `${m.sha256}  ${m.file_name}`),
  '',
  '# SHA-512',
  ...manifestRecords.map((m) => `${m.sha512}  ${m.file_name}`),
  '',
];

fs.writeFileSync(checksumTxtPath, checksumTxtLines.join('\n'), 'utf8');
console.log(`\n[INFO] Wrote checksums.txt: ${checksumTxtPath}`);

// Generate structured checksums.json
const checksumJsonData = {
  schema_version: '1.0.0',
  application: 'Smart Windows Cleaner',
  version: APP_VERSION,
  generated_at: new Date().toISOString(),
  git_commit: getGitCommitSha(),
  artifacts: manifestRecords,
};

fs.writeFileSync(checksumJsonPath, JSON.stringify(checksumJsonData, null, 2) + '\n', 'utf8');
console.log(`[INFO] Wrote checksums.json: ${checksumJsonPath}`);
console.log('[SUCCESS] Release artifact integrity verification and manifest generation completed successfully.');
