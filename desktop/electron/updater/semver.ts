/**
 * Smart Windows Cleaner — Semantic Versioning, Downgrade Protection & Channel Validation
 */

import { UpdateChannel } from '../../src/types/updater';

export interface ParsedSemver {
  major: number;
  minor: number;
  patch: number;
  prerelease?: string;
  channel?: UpdateChannel;
  raw: string;
}

const SEMVER_REGEX = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/;

/**
 * Parses and validates a semantic version string.
 * Returns null if the format is invalid or malformed.
 */
export function parseSemver(versionStr: string): ParsedSemver | null {
  if (typeof versionStr !== 'string') return null;
  const match = versionStr.trim().match(SEMVER_REGEX);
  if (!match) return null;

  const major = parseInt(match[1], 10);
  const minor = parseInt(match[2], 10);
  const patch = parseInt(match[3], 10);
  const prerelease = match[4];

  if (isNaN(major) || isNaN(minor) || isNaN(patch)) return null;

  let channel: UpdateChannel = 'stable';
  if (prerelease) {
    const lower = prerelease.toLowerCase();
    if (lower.startsWith('beta')) {
      channel = 'beta';
    } else if (lower.startsWith('rc')) {
      channel = 'rc';
    } else {
      channel = 'beta';
    }
  }

  return {
    major,
    minor,
    patch,
    prerelease,
    channel,
    raw: versionStr.trim().replace(/^v/, ''),
  };
}

/**
 * Compares two semantic version strings.
 * Returns:
 *   1 if v1 > v2 (v1 is newer)
 *  -1 if v1 < v2 (v1 is older)
 *   0 if v1 === v2
 * Throws an Error if either version string is malformed.
 */
export function compareSemver(v1Str: string, v2Str: string): number {
  const v1 = parseSemver(v1Str);
  const v2 = parseSemver(v2Str);

  if (!v1) throw new Error(`Invalid semantic version string: '${v1Str}'`);
  if (!v2) throw new Error(`Invalid semantic version string: '${v2Str}'`);

  if (v1.major !== v2.major) return v1.major > v2.major ? 1 : -1;
  if (v1.minor !== v2.minor) return v1.minor > v2.minor ? 1 : -1;
  if (v1.patch !== v2.patch) return v1.patch > v2.patch ? 1 : -1;

  // Both base versions are equal; handle prerelease tags
  // Standard semver rule: a version without prerelease is NEWER than a version with prerelease (e.g. 1.1.0 > 1.1.0-rc.1)
  if (!v1.prerelease && v2.prerelease) return 1;
  if (v1.prerelease && !v2.prerelease) return -1;
  if (!v1.prerelease && !v2.prerelease) return 0;

  // Both have prereleases: compare prerelease strings lexically/numerically
  const p1Parts = v1.prerelease!.split('.');
  const p2Parts = v2.prerelease!.split('.');
  const maxLen = Math.max(p1Parts.length, p2Parts.length);

  for (let i = 0; i < maxLen; i++) {
    const p1Part = p1Parts[i];
    const p2Part = p2Parts[i];

    if (p1Part === undefined) return -1;
    if (p2Part === undefined) return 1;

    const p1Num = parseInt(p1Part, 10);
    const p2Num = parseInt(p2Part, 10);

    const isP1Num = !isNaN(p1Num) && String(p1Num) === p1Part;
    const isP2Num = !isNaN(p2Num) && String(p2Num) === p2Part;

    if (isP1Num && isP2Num) {
      if (p1Num !== p2Num) return p1Num > p2Num ? 1 : -1;
    } else if (isP1Num) {
      return -1; // numeric identifiers have lower precedence than lexical
    } else if (isP2Num) {
      return 1;
    } else {
      const cmp = p1Part.localeCompare(p2Part);
      if (cmp !== 0) return cmp > 0 ? 1 : -1;
    }
  }

  return 0;
}

/**
 * Checks if candidateVersion represents a downgrade or identical version relative to currentVersion.
 */
export function isDowngradeOrSame(candidateVersion: string, currentVersion: string): boolean {
  return compareSemver(candidateVersion, currentVersion) <= 0;
}

/**
 * Validates channel compatibility based on user preference.
 * - 'stable': strictly accepts stable releases (no prerelease).
 * - 'beta': accepts 'beta' and 'stable' releases.
 * - 'rc': accepts 'rc' and 'stable' releases.
 */
export function isChannelCompatible(manifestChannel: UpdateChannel, configuredChannel: UpdateChannel): boolean {
  if (configuredChannel === 'stable') {
    return manifestChannel === 'stable';
  }
  if (configuredChannel === 'beta') {
    return manifestChannel === 'beta' || manifestChannel === 'stable';
  }
  if (configuredChannel === 'rc') {
    return manifestChannel === 'rc' || manifestChannel === 'stable';
  }
  return false;
}
