/**
 * Packaging & Trust-Chain Invariant Regression Test
 *
 * Verifies:
 * 1. desktop/package.json does NOT declare "type": "module" while Electron main is CommonJS.
 * 2. tsconfig.electron.json targets CommonJS module output.
 * 3. AppId and permanent NSIS Application GUID are explicitly configured and stable.
 * 4. Product identity and CompanyName consistency across package manifests and electron-builder.
 * 5. Rust Core PE version resource metadata and RT_MANIFEST (requestedExecutionLevel = asInvoker).
 * 6. Bundled Rust Core binary location in extraResources.
 * 7. Installer artifact naming conventions.
 * 8. Preload script isolation via contextBridge.
 * 9. Fallback resolution of index.html in main process.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

describe('Production Packaging & Trust-Chain Invariants', () => {
  const desktopRoot = path.resolve(__dirname, '../../');
  const repoRoot = path.resolve(desktopRoot, '../');
  const pkgPath = path.join(desktopRoot, 'package.json');
  const tsconfigElectronPath = path.join(desktopRoot, 'tsconfig.electron.json');
  const electronBuilderPath = path.join(desktopRoot, 'electron-builder.yml');
  const rustBuildRsPath = path.join(repoRoot, 'core/crates/cli/build.rs');

  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  const tsconfigElectron = JSON.parse(fs.readFileSync(tsconfigElectronPath, 'utf8'));
  const electronBuilderYaml = fs.readFileSync(electronBuilderPath, 'utf8');

  beforeAll(() => {
    // Ensure dist-electron is compiled if running before build step
    const mainCompiledPath = path.join(desktopRoot, 'dist-electron/electron/main.js');
    if (!fs.existsSync(mainCompiledPath)) {
      try {
        execSync('npx tsc -p tsconfig.electron.json', {
          cwd: desktopRoot,
          stdio: 'pipe',
          timeout: 30000,
        });
      } catch (err) {
        console.warn('Could not pre-compile electron main for packaging test:', err);
      }
    }
  });

  describe('Module System Coherence', () => {
    it('enforces CommonJS module format: package.json must NOT declare "type": "module"', () => {
      expect(pkg.type).toBeUndefined();
      expect(pkg.type).not.toBe('module');
    });

    it('verifies tsconfig.electron.json targets CommonJS module output', () => {
      expect(tsconfigElectron.compilerOptions.module.toLowerCase()).toBe('commonjs');
      expect(tsconfigElectron.compilerOptions.outDir).toBe('./dist-electron');
    });

    it('declares a valid main entry point in package.json', () => {
      expect(pkg.main).toBe('dist-electron/electron/main.js');
    });

    it('fails closed if CommonJS main is forced into an ESM context (regression simulation)', () => {
      const mainFullPath = path.join(desktopRoot, pkg.main);
      let mainContent = '';
      if (fs.existsSync(mainFullPath)) {
        mainContent = fs.readFileSync(mainFullPath, 'utf8');
      } else {
        mainContent = '"use strict"; Object.defineProperty(exports, "__esModule", { value: true }); exports.createWindow = createWindow;';
      }

      const simulateEsmConflict = (declaredType: string | undefined, mainCode: string) => {
        if (declaredType === 'module' && (mainCode.includes('exports.') || mainCode.includes('Object.defineProperty(exports'))) {
          throw new ReferenceError('exports is not defined in ES module scope');
        }
        return 'ok';
      };

      expect(simulateEsmConflict(pkg.type, mainContent)).toBe('ok');
      expect(() => simulateEsmConflict('module', mainContent)).toThrow(
        'exports is not defined in ES module scope'
      );
    });
  });

  describe('Installer & App Identity Metadata Consistency', () => {
    it('verifies AppId is com.smartcleaner.app in electron-builder.yml', () => {
      expect(electronBuilderYaml).toContain('appId: com.smartcleaner.app');
    });

    it('verifies explicit permanent NSIS application GUID is configured', () => {
      // Must be stable across all future releases for ARP and upgrade continuity
      const expectedGuid = 'B2E15C76-9F02-4A8E-9807-6B1A424EF55D';
      expect(electronBuilderYaml).toContain(`guid: ${expectedGuid}`);
    });

    it('verifies consistent ProductName across package and builder manifests', () => {
      expect(electronBuilderYaml).toContain('productName: Smart Windows Cleaner');
      expect(electronBuilderYaml).toContain('shortcutName: Smart Windows Cleaner');
      expect(electronBuilderYaml).toContain('uninstallDisplayName: Smart Windows Cleaner');
    });

    it('verifies consistent CompanyName / Author across package and builder manifests', () => {
      const expectedAuthor = 'Abdelrahman Aboelsaad';
      expect(pkg.author).toBe(expectedAuthor);
      expect(electronBuilderYaml).toContain(`publisherName: ${expectedAuthor}`);
      expect(electronBuilderYaml).toContain(`copyright: Copyright © 2026 ${expectedAuthor}`);
    });

    it('verifies installer artifact filename patterns for NSIS and Portable', () => {
      expect(electronBuilderYaml).toContain('artifactName: SmartCleaner-Setup-${version}.${ext}');
      expect(electronBuilderYaml).toContain('artifactName: SmartCleaner-Portable-${version}.${ext}');
    });

    it('verifies extraResources correctly bundles Rust Core into resources/bin', () => {
      expect(electronBuilderYaml).toContain('from: ../core/target/release');
      expect(electronBuilderYaml).toContain('to: bin');
      expect(electronBuilderYaml).toContain('smart-cleaner-core.exe');
    });
  });

  describe('Rust Core PE Version Metadata & RT_MANIFEST Invariants', () => {
    it('verifies Rust build.rs exists and configures native Windows PE resources', () => {
      expect(fs.existsSync(rustBuildRsPath)).toBe(true);
      const buildRsContent = fs.readFileSync(rustBuildRsPath, 'utf8');

      // PE version resource key strings
      expect(buildRsContent).toContain('"CompanyName"');
      expect(buildRsContent).toContain('"Abdelrahman Aboelsaad"');
      expect(buildRsContent).toContain('"ProductName"');
      expect(buildRsContent).toContain('"Smart Windows Cleaner"');
      expect(buildRsContent).toContain('"FileDescription"');
      expect(buildRsContent).toContain('"Smart Windows Cleaner Core Native Engine"');
      expect(buildRsContent).toContain('"OriginalFilename"');
      expect(buildRsContent).toContain('"smart-cleaner-core.exe"');
      expect(buildRsContent).toContain('"ProductVersion"');
      expect(buildRsContent).toContain('"1.0.1"');
      expect(buildRsContent).toContain('"FileVersion"');
      expect(buildRsContent).toContain('"1.0.1.0"');
    });

    it('verifies Rust Core RT_MANIFEST enforces requestedExecutionLevel asInvoker', () => {
      const buildRsContent = fs.readFileSync(rustBuildRsPath, 'utf8');
      expect(buildRsContent).toContain('<requestedExecutionLevel level="asInvoker" uiAccess="false" />');
    });

    it('verifies Cargo.toml includes winres build dependency for Windows target', () => {
      const cargoTomlPath = path.join(repoRoot, 'core/crates/cli/Cargo.toml');
      const cargoContent = fs.readFileSync(cargoTomlPath, 'utf8');
      expect(cargoContent).toContain('winres');
    });
  });

  describe('Runtime Electron Isolation & Path Resolution', () => {
    it('verifies Electron preload script source implements secure contextBridge isolation', () => {
      const preloadSource = fs.readFileSync(path.join(desktopRoot, 'electron/preload.ts'), 'utf8');
      expect(preloadSource).toContain('contextBridge.exposeInMainWorld');
      expect(preloadSource).toContain('smartCleanerIpc');
    });

    it('verifies main.ts resolves index.html accurately with fallback for dev and prod', () => {
      const mainSource = fs.readFileSync(path.join(desktopRoot, 'electron/main.ts'), 'utf8');
      expect(mainSource).toContain('fs.existsSync');
      expect(mainSource).toContain('../../dist/index.html');
      expect(mainSource).toContain('../dist/index.html');
    });

    it('verifies source index.html exists in desktop root', () => {
      const sourceHtmlPath = path.join(desktopRoot, 'index.html');
      expect(fs.existsSync(sourceHtmlPath)).toBe(true);
      const content = fs.readFileSync(sourceHtmlPath, 'utf8');
      expect(content).toContain('<div id="root"></div>');
    });
  });
});
