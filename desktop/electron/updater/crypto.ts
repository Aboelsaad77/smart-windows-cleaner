/**
 * Smart Windows Cleaner — Updater Cryptographic Utilities
 *
 * Implements:
 * - RFC 8785 (JSON Canonicalization Scheme - JCS) strict compliant serialization.
 * - Ed25519 digital signature verification over canonical manifest payloads.
 * - Dual-hash (SHA-256 and SHA-512) artifact verification.
 * - Strict artifact filename and path traversal sanitization.
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { SignedUpdateManifest, PinnedSigningKey } from '../../src/types/updater';
import { lookupPinnedKey } from './keys';

/**
 * Strict RFC 8785 (JSON Canonicalization Scheme - JCS) canonicalizer.
 *
 * Requirements enforced:
 * 1. Object keys sorted by UTF-16 code units (as unsigned 16-bit integers).
 * 2. Numbers serialized via ECMAScript canonical ToString; NaN and Infinity rejected; -0 serialized as 0.
 * 3. Strings serialized with standard JSON escaping; control characters U+0000..U+001F escaped.
 * 4. Object properties with undefined or function values omitted.
 * 5. Arrays serialize undefined items as null.
 * 6. Zero superfluous whitespace between tokens.
 */
export function canonicalizeJson(obj: unknown): string {
  if (obj === null || typeof obj === 'boolean' || typeof obj === 'string') {
    return JSON.stringify(obj);
  }

  if (typeof obj === 'number') {
    if (!Number.isFinite(obj)) {
      throw new TypeError('RFC 8785: NaN and Infinity numbers are not permitted in canonical JSON');
    }
    // Negative zero (-0) MUST be serialized as 0 per RFC 8785 Section 3.2.2.3
    if (Object.is(obj, -0)) {
      return '0';
    }
    return JSON.stringify(obj);
  }

  if (typeof obj === 'bigint') {
    throw new TypeError('RFC 8785: BigInt values are not supported in canonical JSON');
  }

  if (typeof obj !== 'object') {
    return ''; // Functions/symbols return empty
  }

  // Handle toJSON if object implements custom serialization
  const hasToJSON = typeof (obj as { toJSON?: unknown }).toJSON === 'function';
  if (hasToJSON) {
    return canonicalizeJson((obj as { toJSON: () => unknown }).toJSON());
  }

  if (Array.isArray(obj)) {
    const items = obj.map((item) => {
      if (item === undefined || typeof item === 'function' || typeof item === 'symbol') {
        return 'null';
      }
      return canonicalizeJson(item);
    });
    return '[' + items.join(',') + ']';
  }

  // Object property sorting: UTF-16 code units
  const record = obj as Record<string, unknown>;
  const keys = Object.keys(record).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const pairs: string[] = [];

  for (const key of keys) {
    const val = record[key];
    // RFC 8785: properties with undefined, function, or symbol values MUST be omitted
    if (val === undefined || typeof val === 'function' || typeof val === 'symbol') {
      continue;
    }
    const serializedVal = canonicalizeJson(val);
    if (serializedVal !== '') {
      pairs.push(JSON.stringify(key) + ':' + serializedVal);
    }
  }

  return '{' + pairs.join(',') + '}';
}

/**
 * Strips the signature property from the manifest to obtain the pure signable payload.
 */
export function getSignablePayload(manifest: SignedUpdateManifest): Record<string, unknown> {
  const { signature, ...signable } = manifest;
  return signable;
}

/**
 * Validates and sanitizes artifact filename to prevent path traversal and arbitrary directory writes.
 * Rejects:
 * - Empty filenames
 * - Path traversal sequences (`..`, `.`, `./`, `..\`)
 * - Slashes or backslashes (`/`, `\`)
 * - Colons (Windows drive letters / alternate streams)
 * - NUL bytes or control characters
 */
export function sanitizeArtifactFilename(filename: string): string {
  if (typeof filename !== 'string' || filename.trim() === '') {
    throw new Error('Artifact filename cannot be empty');
  }

  const clean = filename.trim();

  // Must equal path.basename (no path segments)
  if (path.basename(clean) !== clean) {
    throw new Error(`Path traversal detected: '${filename}' contains path separator segments`);
  }

  if (clean.includes('..') || clean.includes('/') || clean.includes('\\') || clean.includes(':') || clean.includes('\0')) {
    throw new Error(`Illegal characters in artifact filename: '${filename}'`);
  }

  // Must match expected safe extensions
  if (!clean.endsWith('.exe') && !clean.endsWith('.zip')) {
    throw new Error(`Untrusted artifact extension in filename: '${filename}'. Only .exe and .zip permitted`);
  }

  return clean;
}

export interface SignatureVerificationResult {
  valid: boolean;
  errorCode?: string;
  errorMessage?: string;
  verifiedKeyId?: string;
}

/**
 * Cryptographically verifies an update manifest against the pinned public key allowlist.
 */
export function verifyManifestAuthenticity(
  manifest: SignedUpdateManifest,
  pinnedKeys?: Record<string, PinnedSigningKey>
): SignatureVerificationResult {
  if (!manifest || typeof manifest !== 'object') {
    return {
      valid: false,
      errorCode: 'METADATA_UNAVAILABLE',
      errorMessage: 'Manifest payload is missing or malformed',
    };
  }

  if (!manifest.kid || typeof manifest.kid !== 'string') {
    return {
      valid: false,
      errorCode: 'UNKNOWN_SIGNING_KEY',
      errorMessage: "Manifest missing key ID ('kid') attribute",
    };
  }

  if (!manifest.signature || typeof manifest.signature !== 'string') {
    return {
      valid: false,
      errorCode: 'METADATA_SIGNATURE_INVALID',
      errorMessage: 'Manifest missing signature string',
    };
  }

  const pinnedKey = lookupPinnedKey(manifest.kid, pinnedKeys);
  if (!pinnedKey) {
    return {
      valid: false,
      errorCode: 'UNKNOWN_SIGNING_KEY',
      errorMessage: `Key ID '${manifest.kid}' is not recognized in pinned public key allowlist or has been retired`,
    };
  }

  try {
    const canonicalPayload = canonicalizeJson(getSignablePayload(manifest));
    const dataBuffer = Buffer.from(canonicalPayload, 'utf8');
    const signatureBuffer = Buffer.from(manifest.signature, 'base64');

    const publicKeyObject = crypto.createPublicKey(pinnedKey.publicKeyPem);
    const isSignatureValid = crypto.verify(null, dataBuffer, publicKeyObject, signatureBuffer);

    if (!isSignatureValid) {
      return {
        valid: false,
        errorCode: 'METADATA_SIGNATURE_INVALID',
        errorMessage: `Ed25519 signature verification failed against pinned key '${manifest.kid}'`,
      };
    }

    return {
      valid: true,
      verifiedKeyId: manifest.kid,
    };
  } catch (err) {
    return {
      valid: false,
      errorCode: 'METADATA_SIGNATURE_INVALID',
      errorMessage: `Cryptographic verification error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * Computes SHA-256 and SHA-512 dual hashes of a local file.
 */
export async function computeFileHashes(
  filePath: string
): Promise<{ sha256: string; sha512: string; sizeBytes: number }> {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(filePath)) {
      return reject(new Error(`File not found at path: ${filePath}`));
    }

    const hash256 = crypto.createHash('sha256');
    const hash512 = crypto.createHash('sha512');
    let totalBytes = 0;

    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => {
      totalBytes += chunk.length;
      hash256.update(chunk);
      hash512.update(chunk);
    });

    stream.on('end', () => {
      resolve({
        sha256: hash256.digest('hex').toLowerCase(),
        sha512: hash512.digest('hex').toLowerCase(),
        sizeBytes: totalBytes,
      });
    });

    stream.on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Validates file integrity against expected SHA-256 and SHA-512 hashes.
 */
export async function verifyArtifactIntegrity(
  filePath: string,
  expectedSha256: string,
  expectedSha512: string,
  expectedSize?: number
): Promise<{ valid: boolean; reason?: string; actualSha256?: string; actualSha512?: string; actualSize?: number }> {
  try {
    const { sha256, sha512, sizeBytes } = await computeFileHashes(filePath);

    if (expectedSize !== undefined && sizeBytes !== expectedSize) {
      return {
        valid: false,
        reason: `Artifact size mismatch: expected ${expectedSize} bytes, got ${sizeBytes} bytes`,
        actualSize: sizeBytes,
      };
    }

    const cleanExpected256 = expectedSha256.trim().toLowerCase();
    const cleanExpected512 = expectedSha512.trim().toLowerCase();

    if (sha256 !== cleanExpected256) {
      return {
        valid: false,
        reason: `SHA-256 mismatch: expected ${cleanExpected256}, got ${sha256}`,
        actualSha256: sha256,
        actualSha512: sha512,
        actualSize: sizeBytes,
      };
    }

    if (sha512 !== cleanExpected512) {
      return {
        valid: false,
        reason: `SHA-512 mismatch: expected ${cleanExpected512}, got ${sha512}`,
        actualSha256: sha256,
        actualSha512: sha512,
        actualSize: sizeBytes,
      };
    }

    return {
      valid: true,
      actualSha256: sha256,
      actualSha512: sha512,
      actualSize: sizeBytes,
    };
  } catch (err) {
    return {
      valid: false,
      reason: `Failed to compute hashes on downloaded artifact: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}
