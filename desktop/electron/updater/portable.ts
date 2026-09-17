/**
 * Smart Windows Cleaner — Portable Mode Detection & Protection
 *
 * In Portable Mode:
 * - Automatic in-place execution of NSIS installers is strictly blocked to avoid
 *   modifying the host machine's %LOCALAPPDATA% or system directories.
 * - The updater notifies the user of new versions and provides a verified manual
 *   download link to the portable ZIP archive along with its expected hashes.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

export interface PortableDetectionResult {
  isPortable: boolean;
  reason: string;
}

export function detectPortableMode(customAppPath?: string): PortableDetectionResult {
  // 1. Explicit environment variable set by electron-builder portable wrapper
  if (process.env.PORTABLE_EXECUTABLE_DIR) {
    return {
      isPortable: true,
      reason: `Electron Builder portable executable directory detected: ${process.env.PORTABLE_EXECUTABLE_DIR}`,
    };
  }

  // 2. Explicit environment variable set by administrator or test harness
  if (process.env.SMART_CLEANER_PORTABLE === '1' || process.env.SMART_CLEANER_PORTABLE === 'true') {
    return {
      isPortable: true,
      reason: 'SMART_CLEANER_PORTABLE environment variable explicitly set',
    };
  }

  // 3. Check for .portable marker file adjacent to binary
  const basePath = customAppPath || process.execPath;
  const execDir = path.dirname(basePath);
  const portableMarker = path.join(execDir, '.portable');

  if (fs.existsSync(portableMarker)) {
    return {
      isPortable: true,
      reason: `Portable mode marker file detected at: ${portableMarker}`,
    };
  }

  // 4. On Windows, check whether app is running outside standard Programs directory
  if (process.platform === 'win32' && !process.env.VITE_DEV_SERVER_URL) {
    const localAppData = process.env.LOCALAPPDATA || '';
    const programFiles = process.env.ProgramFiles || '';
    const programFilesX86 = process.env['ProgramFiles(x86)'] || '';

    const normalizedExec = path.resolve(basePath).toLowerCase();
    const inLocalAppData = localAppData && normalizedExec.startsWith(path.resolve(localAppData).toLowerCase());
    const inProgramFiles = programFiles && normalizedExec.startsWith(path.resolve(programFiles).toLowerCase());
    const inProgramFilesX86 = programFilesX86 && normalizedExec.startsWith(path.resolve(programFilesX86).toLowerCase());

    // If installed in standard paths, it's NSIS installed
    if (inLocalAppData || inProgramFiles || inProgramFilesX86) {
      return {
        isPortable: false,
        reason: 'Application is installed in standard Windows Programs directory',
      };
    }
  }

  return {
    isPortable: false,
    reason: 'Standard installation mode',
  };
}
