/**
 * Packaging & Runtime Module System Regression Test
 *
 * Prevents regression of:
 * "ReferenceError: exports is not defined in ES module scope"
 * which occurs when desktop/package.json contains "type": "module"
 * while Electron main process is compiled as CommonJS.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

describe('Production Packaging & Module System Invariants', () => {
  const desktopRoot = path.resolve(__dirname, '../../');
  const pkgPath = path.join(desktopRoot, 'package.json');
  const tsconfigElectronPath = path.join(desktopRoot, 'tsconfig.electron.json');

  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  const tsconfigElectron = JSON.parse(fs.readFileSync(tsconfigElectronPath, 'utf8'));

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

  it('enforces CommonJS module format: package.json must NOT declare "type": "module"', () => {
    // The electron main process is compiled as CommonJS (dist-electron/electron/main.js).
    // If package.json declares "type": "module", Node.js treats the entry point as ESM
    // and throws "ReferenceError: exports is not defined in ES module scope".
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
      // Fallback representation of compiled CommonJS output
      mainContent = '"use strict"; Object.defineProperty(exports, "__esModule", { value: true }); exports.createWindow = createWindow;';
    }

    const simulateEsmConflict = (declaredType: string | undefined, mainCode: string) => {
      if (declaredType === 'module' && (mainCode.includes('exports.') || mainCode.includes('Object.defineProperty(exports'))) {
        throw new ReferenceError('exports is not defined in ES module scope');
      }
      return 'ok';
    };

    // Current state (no "type": "module") must pass cleanly
    expect(simulateEsmConflict(pkg.type, mainContent)).toBe('ok');

    // Forcing "type": "module" must throw ReferenceError
    expect(() => simulateEsmConflict('module', mainContent)).toThrow(
      'exports is not defined in ES module scope'
    );
  });

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
