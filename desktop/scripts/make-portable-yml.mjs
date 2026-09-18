#!/usr/bin/env node
/**
 * Smart Windows Cleaner — Generate portable.yml manifest
 *
 * Generates portable-payload manifest matching the exact electron-builder
 * latest.yml schema:
 *   version / files[0].{url, sha512, size} / path / sha512 / releaseDate
 *
 * Dependency-free: uses Node.js built-ins only.
 * CLI: node scripts/make-portable-yml.mjs <version> <zipPath> [outPath]
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
    throw new Error(`bad version for portable.yml: ${version}`);
  }
  if (!fileName || fileName.includes('/') || fileName.includes('\\') || fileName.includes('..')) {
    throw new Error(`unsafe file name for portable.yml: ${fileName}`);
  }
  if (!Number.isInteger(size) || size < 0) {
    throw new Error(`bad size for portable.yml: ${size}`);
  }
  if (!sha512 || !/^[A-Za-z0-9+/]+={0,2}$/.test(sha512)) {
    throw new Error('bad sha512 for portable.yml');
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

/** Build from real ZIP on disk. */
export function makePortableYml(version, zipPath, { releaseDate } = {}) {
  if (!existsSync(zipPath) || !statSync(zipPath).isFile()) {
    throw new Error(`portable ZIP not found: ${zipPath}`);
  }
  const fileName = path.basename(zipPath);
  if (!fileName.endsWith('.zip')) {
    throw new Error(`portable payload must be a .zip: ${fileName}`);
  }
  return buildPortableYml({
    version,
    fileName,
    size: statSync(zipPath).size,
    sha512: sha512Base64(zipPath),
    releaseDate,
  });
}

const invokedAsCli =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedAsCli) {
  const [version, zipPath, outPath] = process.argv.slice(2);
  if (!version || !zipPath) {
    console.error('usage: node scripts/make-portable-yml.mjs <version> <zipPath> [outPath]');
    process.exit(1);
  }
  try {
    const yml = makePortableYml(version, path.resolve(zipPath));
    const out = outPath ? path.resolve(outPath) : path.join(path.dirname(path.resolve(zipPath)), 'portable.yml');
    writeFileSync(out, yml);
    console.log(`[INFO] portable.yml written: ${out}`);
  } catch (e) {
    console.error(`[FATAL] portable.yml FAILED: ${e.message}`);
    process.exit(1);
  }
}
