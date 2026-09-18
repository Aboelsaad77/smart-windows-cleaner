/**
 * Smart Windows Cleaner — Bootstrapper & Distribution Architecture Tests
 *
 * Verifies:
 * 1. portable.yml generation is deterministic and schema-compatible with electron-builder latest.yml.
 * 2. Inno Setup bootstrapper.iss posture: lowest privilege, native pages only, zero external plugins.
 * 3. Strict verify-before-run invariant: payload SHA-512 must verify before execution or extraction.
 * 4. Cache integrity: cached payloads are re-verified against manifest on every run.
 * 5. CI release workflow compiles bootstrapper and publishes the complete distribution set.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';
// @ts-expect-error script module
import { buildPortableYml, makePortableYml } from '../../scripts/make-portable-yml.mjs';

const desktopRoot = path.resolve(__dirname, '../../');
const repoRoot = path.resolve(desktopRoot, '../');

function stripIssComments(src: string): string {
  return src
    .split('\n')
    .map((line) => {
      if (line.trimStart().startsWith(';')) return '';
      return line.replace(/(^|[^:])\/\/.*$/, '$1');
    })
    .join('\n');
}

describe('Bootstrapper & Distribution Architecture (PortSaid Parity)', () => {
  describe('portable.yml Schema & Generation', () => {
    it('generates deterministic portable.yml compatible with latest.yml schema', () => {
      const yml = buildPortableYml({
        version: '1.0.0',
        fileName: 'SmartCleaner-Portable-1.0.0.zip',
        size: 52428800,
        sha512: 'bW9ja1NoYTUxMg==',
        releaseDate: '2026-09-18T00:00:00.000Z',
      });

      expect(yml).toContain('version: 1.0.0');
      expect(yml).toContain('url: SmartCleaner-Portable-1.0.0.zip');
      expect(yml).toContain('sha512: bW9ja1NoYTUxMg==');
      expect(yml).toContain('size: 52428800');
      expect(yml).toContain('path: SmartCleaner-Portable-1.0.0.zip');
      expect(yml).toContain("releaseDate: '2026-09-18T00:00:00.000Z'");
    });

    it('rejects invalid or unsafe arguments for portable.yml', () => {
      const valid = {
        version: '1.0.0',
        fileName: 'SmartCleaner-Portable-1.0.0.zip',
        size: 1000,
        sha512: 'bW9ja1NoYTUxMg==',
      };

      expect(() => buildPortableYml({ ...valid, version: 'invalid-ver' })).toThrow('bad version');
      expect(() => buildPortableYml({ ...valid, fileName: '../evil.zip' })).toThrow('unsafe file name');
      expect(() => buildPortableYml({ ...valid, fileName: 'nested/evil.zip' })).toThrow('unsafe file name');
      expect(() => buildPortableYml({ ...valid, size: -1 })).toThrow('bad size');
      expect(() => buildPortableYml({ ...valid, sha512: 'invalid-not-base64!' })).toThrow('bad sha512');
    });

    it('hashes real zip file accurately on disk', () => {
      const tmpZip = path.join(desktopRoot, 'test-portable-fixture.zip');
      fs.writeFileSync(tmpZip, 'test-payload-bytes');
      try {
        const expectedSha = createHash('sha512').update('test-payload-bytes').digest('base64');
        const yml = makePortableYml('1.0.0', tmpZip);
        expect(yml).toContain(`sha512: ${expectedSha}`);
        expect(yml).toContain('size: 18');
      } finally {
        if (fs.existsSync(tmpZip)) fs.unlinkSync(tmpZip);
      }
    });
  });

  describe('Inno Setup Bootstrapper Configuration & Posture', () => {
    const issPath = path.join(repoRoot, 'installer/bootstrapper.iss');

    it('verifies bootstrapper.iss exists with required companion assets', () => {
      expect(fs.existsSync(issPath)).toBe(true);
      expect(fs.existsSync(path.join(repoRoot, 'installer/app.ico'))).toBe(true);
      expect(fs.existsSync(path.join(repoRoot, 'installer/license.txt'))).toBe(true);
      expect(fs.existsSync(path.join(repoRoot, 'installer/portable.dat'))).toBe(true);
      expect(fs.existsSync(path.join(repoRoot, 'installer/README-Portable.txt'))).toBe(true);
    });

    it('enforces least-privilege execution (PrivilegesRequired=lowest)', () => {
      const iss = fs.readFileSync(issPath, 'utf8');
      expect(iss).toContain('PrivilegesRequired=lowest');
      expect(iss).toContain('Uninstallable=no');
      expect(iss).toContain('CreateAppDir=no');
      expect(iss).toContain('ArchitecturesAllowed=x64compatible');
      expect(iss).toContain('ArchiveExtraction=full');
      expect(iss).toContain('OutputBaseFilename=SmartCleaner-Setup');
    });

    it('enforces Inno Setup 6.2+ compiler gate', () => {
      const iss = fs.readFileSync(issPath, 'utf8');
      expect(iss).toContain('#if Ver < 0x06020000');
    });

    it('maintains distinct AppId for bootstrapper to avoid collision with application GUID', () => {
      const iss = fs.readFileSync(issPath, 'utf8');
      const builderYaml = fs.readFileSync(path.join(desktopRoot, 'electron-builder.yml'), 'utf8');

      const nsisGuidMatch = builderYaml.match(/guid:\s*([A-F0-9-]+)/i);
      const bootAppIdMatch = iss.match(/AppId=\{\{([A-F0-9-]+)\}\}/i);

      expect(nsisGuidMatch).not.toBeNull();
      expect(bootAppIdMatch).not.toBeNull();
      // Bootstrapper AppId must NOT match installed application NSIS GUID
      expect(bootAppIdMatch![1].toUpperCase()).not.toBe(nsisGuidMatch![1].toUpperCase());
    });

    it('uses pure built-ins only (zero external plugins, no curl, no IDP)', () => {
      const iss = stripIssComments(fs.readFileSync(issPath, 'utf8'));

      expect(iss).toContain('CreateDownloadPage');
      expect(iss).toContain('DownloadTemporaryFile');
      expect(iss).toContain('CreateExtractionPage');
      expect(iss).toContain('Get-FileHash');
      expect(iss).toContain('CreateInputOptionPage');
      expect(iss).toContain('CreateInputDirPage');

      // Reject unmaintained third-party plugins
      expect(iss.toLowerCase()).not.toContain('idp.iss');
      expect(iss.toLowerCase()).not.toContain('dwinshs');
      expect(iss.toLowerCase()).not.toContain('external ');
      expect(iss.toLowerCase()).not.toContain('curl');
      expect(iss.toLowerCase()).not.toContain('bitstransfer');
    });

    it('enforces verify-before-run on both online and offline cached execution paths', () => {
      const iss = stripIssComments(fs.readFileSync(issPath, 'utf8'));

      // Both execution branches call VerifyPayloadHash() (excluding procedure definition)
      const verifyCalls = iss.match(/(^|\n)\s+VerifyPayloadHash\(\);/g) || [];
      expect(verifyCalls.length).toBe(2);

      // Verify occurs strictly BEFORE RunFullPayload or ExtractPortablePayload
      const verifyIdx = iss.indexOf('VerifyPayloadHash();');
      const runFullIdx = iss.indexOf('RunFullPayload()');
      const extractPortIdx = iss.indexOf('ExtractPortablePayload()');

      expect(verifyIdx).toBeGreaterThan(0);
      expect(verifyIdx).toBeLessThan(runFullIdx);
      expect(verifyIdx).toBeLessThan(extractPortIdx);

      // Fails closed by deleting corrupted payload
      expect(iss).toContain('DeleteFile(PayloadPath)');
      expect(iss).toContain('INTEGRITY FAILURE');
    });

    it('implements localized English and Arabic messages', () => {
      const iss = fs.readFileSync(issPath, 'utf8');
      expect(iss).toContain('english.ModeFull=Full Installation (recommended)');
      expect(iss).toContain('arabic.ModeFull=تثبيت كامل (مُوصى به)');
      expect(iss).toContain('arabic.ModePort=نسخة محمولة (بدون تثبيت)');
    });
  });

  describe('CI/CD Workflow Distribution Pipeline', () => {
    it('verifies GitHub Actions workflow compiles bootstrapper and publishes manifests', () => {
      const workflowPath = path.join(repoRoot, '.github/workflows/build-windows.yml');
      const workflow = fs.readFileSync(workflowPath, 'utf8');

      expect(workflow).toContain('Compile Inno Setup Bootstrapper (ISCC)');
      expect(workflow).toContain('installer\\bootstrapper.iss');
      expect(workflow).toContain('Generate portable.yml Manifest');
      expect(workflow).toContain('desktop/scripts/make-portable-yml.mjs');

      // Releases must include the full distribution set:
      expect(workflow).toContain('desktop/dist-release/SmartCleaner-Setup.exe');
      expect(workflow).toContain('desktop/dist-release/SmartCleaner-Setup-*.exe');
      expect(workflow).toContain('desktop/dist-release/SmartCleaner-Portable-*.zip');
      expect(workflow).toContain('desktop/dist-release/latest.yml');
      expect(workflow).toContain('desktop/dist-release/portable.yml');
      expect(workflow).toContain('desktop/dist-release/checksums.txt');
      expect(workflow).toContain('desktop/dist-release/checksums.json');
    });
  });
});
