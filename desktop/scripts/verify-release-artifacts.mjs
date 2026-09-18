#!/usr/bin/env node
/**
 * Smart Windows Cleaner — Release Artifact Integrity & Verification Suite
 *
 * Responsibilities:
 * 1. Validates presence and minimum integrity constraints of release artifacts:
 *    - NSIS Installer: SmartCleaner-Setup-<version>.exe
 *    - Portable ZIP:   SmartCleaner-Portable-<version>.zip
 * 2. Computes cryptographic hashes: SHA-256 and SHA-512.
 * 3. Generates canonical release manifests:
 *    - checksums.txt (standard GNU sha256sum / sha512sum compatible format)
 *    - checksums.json (machine-readable structured manifest with provenance metadata)
 * 4. Supports self-verification (--verify mode) against existing manifests.
 * 5. Fails with non-zero exit status on any artifact absence, size anomaly, or hash mismatch.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as child_process from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Minimum acceptable size for packaged Electron + Rust core bundle (5 MB)
const MIN_ARTIFACT_SIZE_BYTES = 5 * 1024 * 1024;

// Read version from desktop/package.json
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

// Packaging Module System Validation: Prevent "exports is not defined in ES module scope"
if (packageJson.type === 'module') {
  console.error('[FATAL] desktop/package.json declares "type": "module" while Electron main is CommonJS.');
  console.error('This causes "ReferenceError: exports is not defined in ES module scope" in packaged Electron.');
  process.exit(1);
}

// Locate release artifacts directory (default: desktop/dist-release)
const candidateDirs = [
  process.env.RELEASE_DIR,
  path.resolve(__dirname, '../dist-release'),
  path.resolve(process.cwd(), 'dist-release'),
  path.resolve(process.cwd(), 'desktop/dist-release'),
].filter(Boolean);

let releaseDir = candidateDirs.find((dir) => fs.existsSync(dir));

// If running in verification mode or testing with custom directory
const args = process.argv.slice(2);
const dirArgIdx = args.findIndex((a) => a === '--dir' || a === '-d');
if (dirArgIdx !== -1 && args[dirArgIdx + 1]) {
  releaseDir = path.resolve(args[dirArgIdx + 1]);
}

const isVerifyOnly = args.includes('--verify');

if (!releaseDir || !fs.existsSync(releaseDir)) {
  console.error(`[ERROR] Release directory not found. Looked in: ${candidateDirs.join(', ')}`);
  console.error('Run electron-builder first to generate release deliverables.');
  process.exit(1);
}

console.log(`[INFO] Smart Cleaner Release Verification`);
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

// Expected deliverables specification
const EXPECTED_ARTIFACTS = [
  {
    target: 'nsis',
    fileName: `SmartCleaner-Setup-${APP_VERSION}.exe`,
    description: 'Windows NSIS Interactive Installer (Per-User Default)',
  },
  {
    target: 'zip',
    fileName: `SmartCleaner-Portable-${APP_VERSION}.zip`,
    description: 'Windows Portable Archive (Zero-Install)',
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
  if (stats.size < MIN_ARTIFACT_SIZE_BYTES) {
    console.error(
      `[FAIL] Artifact size anomaly for ${artifact.fileName}: ${stats.size} bytes (minimum threshold: ${MIN_ARTIFACT_SIZE_BYTES} bytes)`
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

if (hasFailure) {
  console.error('\n[FATAL] Release verification failed. Required artifacts are missing or invalid.');
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
