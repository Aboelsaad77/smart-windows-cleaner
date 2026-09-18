/**
 * Smart Windows Cleaner - NSIS Template Patch Script
 *
 * Fixes known electron-builder upstream issue where multiUser.nsh performs an out-of-bounds
 * buffer read via System.dll from SHGetKnownFolderPath CoTaskMem buffer, causing STATUS_ACCESS_VIOLATION
 * (0xC0000005 / -1073741819) on Windows 10/11 when resolving per-user directories.
 *
 * Replaces:
 *   System::Call '*$2(&w${NSIS_MAX_STRLEN} .s)'
 * with:
 *   System::Call 'KERNEL32::lstrcpynW(w .s, p r2, i 1024)'
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const templatePath = path.resolve(
  __dirname,
  '../node_modules/app-builder-lib/templates/nsis/multiUser.nsh'
);

if (!fs.existsSync(templatePath)) {
  console.log('[patch-nsis] multiUser.nsh not found (skipping patch).');
  process.exit(0);
}

let content = fs.readFileSync(templatePath, 'utf8');
const vulnerableCall = "System::Call '*$2(&w${NSIS_MAX_STRLEN} .s)'";
const safeCall = "System::Call 'KERNEL32::lstrcpynW(w .s, p r2, i 1024)'";

if (content.includes(vulnerableCall)) {
  content = content.replace(vulnerableCall, safeCall);
  fs.writeFileSync(templatePath, content, 'utf8');
  console.log('[patch-nsis] Successfully patched multiUser.nsh with safe lstrcpynW buffer read.');
} else if (content.includes(safeCall)) {
  console.log('[patch-nsis] multiUser.nsh is already patched.');
} else {
  console.log('[patch-nsis] Notice: vulnerable pattern not found in multiUser.nsh (may have been modified or upstreamed).');
}
