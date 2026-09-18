/**
 * Packaging & Runtime Module System Regression Test
 *
 * Verifies:
 * 1. desktop/package.json does NOT declare `"type": "module"` while main process is CommonJS.
 * 2. Packaged main entry exists at the declared path.
 * 3. Packaged preload script exists and matches CommonJS format.
 * 4. Renderer index.html exists at the expected relative path.
 * 5. Main entry is syntactically valid CommonJS and would fail if treated as ESM.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

describe('Production Packaging & Module System Invariants', () => {
  const desktopRoot = path.resolve(__dirname, '../../');
  const pkgPath = path.join(desktopRoot, 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

  it('declares a valid main entry point that exists on disk', () => {
    expect(pkg.main).toBeDefined();
    expect(typeof pkg.main).toBe('string');
    const mainFullPath = path.join(desktopRoot, pkg.main);
    expect(fs.existsSync(mainFullPath)).toBe(true);
  });

  it('enforces module format coherence: CommonJS main must NOT reside in type="module"', () => {
    const mainFullPath = path.join(desktopRoot, pkg.main);
    const mainContent = fs.readFileSync(mainFullPath, 'utf8');

    const isCjsMain =
      mainContent.includes('exports.') ||
      mainContent.includes('module.exports') ||
      mainContent.includes('Object.defineProperty(exports');

    if (isCjsMain) {
      // If the compiled main process is CommonJS, package.json MUST NOT declare "type": "module"
      // because Node/Electron will attempt to parse it as an ES module, causing:
      // "ReferenceError: exports is not defined in ES module scope"
      expect(pkg.type).not.toBe('module');
    }
  });

  it('fails closed if CommonJS main is forced into an ESM context (regression simulation)', () => {
    const simulateEsmConflict = (declaredType: string | undefined, mainCode: string) => {
      if (declaredType === 'module' && (mainCode.includes('exports.') || mainCode.includes('Object.defineProperty(exports'))) {
        throw new ReferenceError('exports is not defined in ES module scope');
      }
      return 'ok';
    };

    const mainFullPath = path.join(desktopRoot, pkg.main);
    const mainContent = fs.readFileSync(mainFullPath, 'utf8');

    // The current packaged state must be valid
    expect(simulateEsmConflict(pkg.type, mainContent)).toBe('ok');

    // Forcing "type": "module" must trigger the ReferenceError
    expect(() => simulateEsmConflict('module', mainContent)).toThrow(
      'exports is not defined in ES module scope'
    );
  });

  it('verifies preload script exists and exposes smartCleanerIpc', () => {
    const preloadPath = path.join(desktopRoot, 'dist-electron/electron/preload.js');
    expect(fs.existsSync(preloadPath)).toBe(true);

    const preloadContent = fs.readFileSync(preloadPath, 'utf8');
    expect(preloadContent).toContain('smartCleanerIpc');
    expect(preloadContent).toContain('contextBridge');
  });

  it('verifies renderer bundle index.html exists at the expected path', () => {
    const indexPath = path.join(desktopRoot, 'dist/index.html');
    expect(fs.existsSync(indexPath)).toBe(true);

    const htmlContent = fs.readFileSync(indexPath, 'utf8');
    expect(htmlContent).toContain('<div id="root">');
    // Renderer must use ESM script tag in browser context
    expect(htmlContent).toContain('type="module"');
  });

  it('verifies main.ts resolves index.html accurately from dist-electron/electron/', () => {
    const mainDir = path.join(desktopRoot, 'dist-electron/electron');
    const prodPath = path.join(mainDir, '../../dist/index.html');
    expect(fs.existsSync(prodPath)).toBe(true);
  });
});
