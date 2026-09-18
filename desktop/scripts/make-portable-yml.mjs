#!/usr/bin/env node
/**
 * Smart Windows Cleaner - Generate release manifest (latest.yml / portable.yml)
 *
 * Generates release payload manifest matching the electron-builder schema:
 *   version / files[0].{url, sha512, size} / path / sha512 / releaseDate
 *
 * Supports both Portable ZIP (portable.yml) and Full Installer NSIS EXE (latest.yml).
 *
 * Dependency-free: uses Node.js built-ins only.
 * CLI: node scripts/make-portable-yml.mjs <version> <payloadPath> [outPath]
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function sha512Base64(filePath) {
  const hash = createHash('sha512');
  hash.update(readFileSync(filePath));
  return hash.digest('base64');
}

/** Deterministic render given explicit inputs (fixture-testable). */
export function buildPortableYml({ version, fileName, size, sha512, releaseDate }) {
  if (!version || !/^\d+\.\d+\.\d+$/.test(version)) {
    throw new Error(`bad version for manifest: ${version}`);
  }
  if (!fileName || fileName.includes('/') || fileName.includes('\\') || fileName.includes('..')) {
    throw new Error(`unsafe file name for manifest: ${fileName}`);
  }
  if (!Number.isInteger(size) || size < 0) {
    throw new Error(`bad size for manifest: ${size}`);
  }
  if (!sha512 || !/^[A-Za-z0-9+/]+={0,2}$/.test(sha512)) {
    throw new Error('bad sha512 for manifest');
  }
  const date = releaseDate || new Date().toISOString();
  return (
    `version: ${version}\n` +
    `files:\n` +
    `  - url: ${fileName}\n` +
    `    sha512: ${sha512}\n` +
    `    size: ${size}\n` +
    `path: ${fileName}\n` +
    `sha512: ${sha512}\n` +
    `releaseDate: '${date}'\n`
  );
}

/** Build from real ZIP or EXE on disk. */
export function makePortableYml(version, payloadPath, { releaseDate } = {}) {
  if (!existsSync(payloadPath) || !statSync(payloadPath).isFile()) {
    throw new Error(`payload file not found: ${payloadPath}`);
  }
  const fileName = path.basename(payloadPath);
  if (!fileName.endsWith('.zip') && !fileName.endsWith('.exe')) {
    throw new Error(`payload must be a .zip or .exe: ${fileName}`);
  }
  return buildPortableYml({
    version,
    fileName,
    size: statSync(payloadPath).size,
    sha512: sha512Base64(payloadPath),
    releaseDate,
  });
}

const invokedAsCli =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedAsCli) {
  const [version, payloadPath, outPath] = process.argv.slice(2);
  if (!version || !payloadPath) {
    console.error('usage: node scripts/make-portable-yml.mjs <version> <payloadPath> [outPath]');
    process.exit(1);
  }
  try {
    const yml = makePortableYml(version, path.resolve(payloadPath));
    const isExe = path.basename(payloadPath).endsWith('.exe');
    const defaultOutName = isExe ? 'latest.yml' : 'portable.yml';
    const out = outPath ? path.resolve(outPath) : path.join(path.dirname(path.resolve(payloadPath)), defaultOutName);
    writeFileSync(out, yml);
    console.log(`[INFO] manifest written: ${out}`);
  } catch (e) {
    console.error(`[FATAL] manifest generation FAILED: ${e.message}`);
    process.exit(1);
  }
}
