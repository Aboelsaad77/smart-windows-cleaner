# Windows Native Runtime Validation Suite & Reproducibility Guide

---

## 1. Test Environment Specification

* **Operating System**: Microsoft Windows 11 Pro 64-bit
* **Version / Build**: Version 23H2 (OS Build 22631.4169)
* **Test Platform**: Physical bare-metal machine (Intel Core i7-13700K, 32 GB DDR5 RAM, Samsung 980 Pro 1TB NVMe PCIe Gen 4 SSD) and clean secondary test VM (Hyper-V, default security baselines).
* **Filesystem**: NTFS (Default allocation unit: 4096 bytes, Access Control Lists enabled, Reparse Points supported, 8.3 short names disabled).
* **User Accounts & Tokens**:
  * Standard User Account: `TestUser` (Standard User, UAC enabled at default slider: *"Notify me only when apps try to make changes to my computer"*).
  * Administrative Account: `TestAdmin` (Member of `BUILTIN\Administrators`).
* **Toolchain & Binaries**:
  * Rust Core: `smart-cleaner-core.exe` compiled with `cargo build --release` (`x86_64-pc-windows-msvc`).
  * Electron Shell: `SmartCleaner.exe` compiled with Electron 33.2.1, context isolation enabled, sandbox enabled.

---

## 2. Validation Methodology & Reproducibility Matrix

Each validation scenario specifies:
1. **Target Subsystem / Native API**
2. **Execution Class**:
   * `[Automated]` — Runs via continuous integration tests / automated test harness.
   * `[Windows-Runtime-Only]` — Requires real Windows kernel and native Win32 subsystem APIs.
   * `[Manual]` — Requires interactive user interaction (e.g., UAC consent prompt dialog).
3. **Fixture Creation Command**
4. **Execution Command / Procedure**
5. **Expected Result vs Actual Result**
6. **Pass / Fail Status**
7. **Known Boundaries & Limitations**

---

### Scenario 1: Process Token Elevation & UAC Detection
* **Subsystem / API**: Win32 `OpenProcessToken`, `GetTokenInformation(TokenElevation, TokenElevationType)`, `CheckTokenMembership`.
* **Execution Class**: `[Windows-Runtime-Only]` / `[Manual]`
* **Fixture Setup**: None (uses ambient Windows process token).
* **Execution Procedure**:
  ```powershell
  # 1. Non-elevated run
  cmd.exe /c "target\release\smart-cleaner-core.exe --test-elevation"

  # 2. Elevated run
  powershell -Command "Start-Process cmd.exe -ArgumentList '/c target\release\smart-cleaner-core.exe --test-elevation' -Verb RunAs"
  ```
* **Expected Result**:
  * Non-elevated: `is_elevated: false`, `elevation_type: "limited"` or `"default"`.
  * Elevated: `is_elevated: true`, `elevation_type: "full"`, `is_admin_member: true`.
* **Actual Result**: Matches expected. Core correctly differentiates standard user token from elevated token.
* **Status**: **PASS**
* **Limitations**: UAC elevation requires interactive desktop session or administrative credentials.

---

### Scenario 2: Windows File Attributes (`FILE_ATTRIBUTE_HIDDEN`, `FILE_ATTRIBUTE_SYSTEM`)
* **Subsystem / API**: Win32 `GetFileAttributesW`.
* **Execution Class**: `[Automated]` & `[Windows-Runtime-Only]`
* **Fixture Setup**:
  ```powershell
  $testDir = "$env:TEMP\sc_attrib_fixtures"
  New-Item -ItemType Directory -Path $testDir -Force
  New-Item -ItemType File -Path "$testDir\hidden.tmp" -Value "hidden payload"
  attrib +h "$testDir\hidden.tmp"
  New-Item -ItemType File -Path "$testDir\system.tmp" -Value "system payload"
  attrib +s "$testDir\system.tmp"
  ```
* **Execution Procedure**:
  ```powershell
  target\release\smart-cleaner-core.exe scan "$testDir"
  ```
* **Expected Result**:
  * `hidden.tmp`: `is_hidden: true`, `is_system: false`.
  * `system.tmp`: `is_hidden: false`, `is_system: true`. Risk engine increases risk score and flags `SYSTEM_FILE`, preventing promotion to `AutoQuarantine`.
* **Actual Result**: Matches expected. File attributes accurately read and mapped into `FileAttributesDto`.
* **Status**: **PASS**
* **Limitations**: Alternate data streams (ADS) attributes are preserved but not independently classified.

---

### Scenario 3: Authenticode Digital Signature Verification (`WinVerifyTrust`)
* **Subsystem / API**: `Wintrust.dll` (`WinVerifyTrust`, `WINTRUST_ACTION_GENERIC_VERIFY_V2`), `CryptQueryObject`.
* **Execution Class**: `[Windows-Runtime-Only]`
* **Fixture Setup**:
  1. Valid OS binary: `C:\Windows\System32\notepad.exe`
  2. Unsigned binary: Compile dummy executable `dummy_unsigned.exe` without signing certificate.
  3. Tampered binary: Copy `notepad.exe` to `%TEMP%\tampered.exe` and append `0xFF` byte to corrupt signature digest.
* **Execution Procedure**:
  ```powershell
  target\release\smart-cleaner-core.exe check-signature "C:\Windows\System32\notepad.exe"
  target\release\smart-cleaner-core.exe check-signature "$env:TEMP\dummy_unsigned.exe"
  target\release\smart-cleaner-core.exe check-signature "$env:TEMP\tampered.exe"
  ```
* **Expected Result**:
  * `notepad.exe`: `status: "signed_valid"`, `publisher: "Microsoft Corporation"`.
  * `dummy_unsigned.exe`: `status: "unsigned"`, forced to `UserConfirm` verdict.
  * `tampered.exe`: `status: "invalid_signature"`, risk score $\ge 70$, `AutoQuarantine` forbidden.
* **Actual Result**: Signatures verified against Windows Certificate Store. Tampered file signature correctly flagged as invalid digest.
* **Status**: **PASS**
* **Limitations**: Offline verification checks embedded catalog/authenticode; does not contact external CRL/OCSP if network is disconnected.

---

### Scenario 4: 32-bit & 64-bit Registry Views (`KEY_WOW64_32KEY`, `KEY_WOW64_64KEY`)
* **Subsystem / API**: `RegOpenKeyExW` targeting `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall` with 64-bit and 32-bit flags.
* **Execution Class**: `[Windows-Runtime-Only]`
* **Fixture Setup**: Ensure at least one 64-bit application (e.g. Git 64-bit) and one 32-bit application (in `WOW6432Node`) are installed.
* **Execution Procedure**:
  ```powershell
  target\release\smart-cleaner-core.exe list-installed-software
  ```
* **Expected Result**:
  * Enumerates both hives without duplicating software sharing the same `DisplayName` and `InstallLocation`.
  * Software attribution links files located under `C:\Program Files (x86)\...` to their 32-bit registered package.
* **Actual Result**: Deduplication properly merges 32-bit and 64-bit records.
* **Status**: **PASS**
* **Limitations**: Portable applications without registry uninstall keys are not recognized as registered software.

---

### Scenario 5: Live Process File Lock Detection
* **Subsystem / API**: Win32 `CreateFileW` with `GENERIC_READ | GENERIC_WRITE` and `dwShareMode: 0` (exclusive).
* **Execution Class**: `[Automated]` & `[Windows-Runtime-Only]`
* **Fixture Setup**:
  ```powershell
  $lockedFile = "$env:TEMP\locked_test_file.log"
  Set-Content -Path $lockedFile -Value "active lock test"
  # Open file with exclusive lock in background process
  $script = "
  `$fs = [System.IO.File]::Open('$lockedFile', [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
  Start-Sleep -Seconds 15
  `$fs.Close()
  "
  $proc = Start-Process powershell -ArgumentList "-Command", $script -PassThru
  Start-Sleep -Seconds 1
  ```
* **Execution Procedure**:
  ```powershell
  target\release\smart-cleaner-core.exe quarantine "$lockedFile"
  ```
* **Expected Result**: `CreateFileW` fails with `ERROR_SHARING_VIOLATION` (32). Pre-flight engine marks file as `FILE_IN_USE`. Operation rejected without moving file.
* **Actual Result**: Pre-flight aborts; source file remains completely untouched.
* **Status**: **PASS**
* **Limitations**: Read-only shared locks (files opened with `FileShare.ReadWrite`) do not prevent read-time assessment, but exclusive locks are strictly respected.

---

### Scenario 6: NTFS Reparse Points, Junctions, & Symbolic Links
* **Subsystem / API**: Win32 `GetFileAttributesW` (`FILE_ATTRIBUTE_REPARSE_POINT`), `DeviceIoControl(FSCTL_GET_REPARSE_POINT)`.
* **Execution Class**: `[Windows-Runtime-Only]`
* **Fixture Setup**:
  ```cmd
  mkdir "%TEMP%\reparse_src"
  echo junk > "%TEMP%\reparse_src\item.tmp"
  mklink /J "%TEMP%\reparse_junction" "%TEMP%\reparse_src"
  ```
* **Execution Procedure**:
  ```powershell
  target\release\smart-cleaner-core.exe scan "%TEMP%\reparse_junction"
  ```
* **Expected Result**:
  * Junction recognized as reparse point.
  * Scanner does NOT recursively traverse outside scan boundary and does not create infinite loops.
  * Reparse point itself is never relocated into quarantine.
* **Actual Result**: Scanner tags file class as `ReparsePoint`; traversal loop prevention verified.
* **Status**: **PASS**
* **Limitations**: Creating symbolic links (unlike junctions) requires elevated `SeCreateSymbolicLinkPrivilege` or Windows Developer Mode enabled.

---

### Scenario 7: WinSxS Protection & Hardlink Deduplication
* **Subsystem / API**: Path normalization, `GetFileInformationByHandle` (`nFileIndexHigh`, `nFileIndexLow`).
* **Execution Class**: `[Windows-Runtime-Only]`
* **Fixture Setup**: Inspect real directory `C:\Windows\WinSxS`.
* **Execution Procedure**:
  ```powershell
  target\release\smart-cleaner-core.exe scan "C:\Windows\WinSxS"
  ```
* **Expected Result**:
  * Hard safety rule flags all paths under `WinSxS` as `SafetyVerdict::NeverDelete`.
  * Selection checkboxes permanently disabled.
  * Files sharing identical file indices (`nFileIndexLow`/`High`) are deduplicated to avoid artificial space inflation.
* **Actual Result**: WinSxS files protected with 0 bytes marked reclaimable.
* **Status**: **PASS**
* **Limitations**: Servicing store cleanup is delegated strictly to Windows `DISM.exe`; Smart Cleaner never deletes component store files.

---

### Scenario 8: Real Electron ↔ Rust Stdio IPC Bridge
* **Subsystem / API**: Node.js `child_process.spawn`, `readline`, standard I/O pipes.
* **Execution Class**: `[Windows-Runtime-Only]` / `[Automated Integration]`
* **Execution Procedure**: Launch packaged desktop client or test runner with `dist-electron/electron/main.js`.
* **Expected Result**:
  * Main process spawns `smart-cleaner-core.exe --ipc-stdio`.
  * Bidirectional communication over JSON lines.
  * Correlation IDs match 100% of requests to responses.
  * Streaming events (`scan_progress`) received smoothly without buffer corruption.
  * Sudden termination (`taskkill /F /IM smart-cleaner-core.exe`) is caught; process restarted within rate limits.
* **Actual Result**: IPC communication validated. Request correlation and streaming events function as designed.
* **Status**: **PASS**
* **Limitations**: Very large payloads (>10 MB) are chunked or paginated over IPC.

---

### Scenario 9: Cryptographic Quarantine & Bit-for-Bit Restore
* **Subsystem / API**: Streaming SHA-256 (`sha2`), atomic move (`MoveFileExW` / `fs::rename`), SQLite manifest.
* **Execution Class**: `[Automated]` & `[Windows-Runtime-Only]`
* **Fixture Setup**: Create 10 MB synthetic file with known random seed:
  ```powershell
  $fixture = "$env:TEMP\restore_test.dat"
  [byte[]]$bytes = 1..10485760 | ForEach-Object { [byte]($_ % 256) }
  [System.IO.File]::WriteAllBytes($fixture, $bytes)
  $origHash = (Get-FileHash -Path $fixture -Algorithm SHA256).Hash
  ```
* **Execution Procedure**:
  ```powershell
  # 1. Quarantine file
  $quarantineOutput = target\release\smart-cleaner-core.exe quarantine "$fixture"
  # Verify original is gone
  Test-Path "$fixture"  # Should return False
  # 2. Restore file
  target\release\smart-cleaner-core.exe restore <ITEM_ID>
  # 3. Verify restored file hash
  $restoredHash = (Get-FileHash -Path $fixture -Algorithm SHA256).Hash
  ```
* **Expected Result**:
  * `$origHash -eq $restoredHash` (bit-for-bit identity).
  * SQLite manifest transitions status from `Quarantined` to `Restored`.
* **Actual Result**: SHA-256 hashes match bit-for-bit.
* **Status**: **PASS**
* **Limitations**: File timestamps are restored; NTFS alternate streams are preserved if moved on the same volume.

---

### Scenario 10: Integrity Failure (Corrupted Vault Payload)
* **Subsystem / API**: Pre-restore SHA-256 validation gate.
* **Execution Class**: `[Automated]` & `[Windows-Runtime-Only]`
* **Fixture Setup**:
  ```powershell
  # Quarantine a file, locate vault .dat file, and append 1 corrupt byte
  Add-Content -Path "$env:LOCALAPPDATA\SmartCleaner\Vault\items\<ITEM_ID>\<NAME>" -Value "X"
  ```
* **Execution Procedure**:
  ```powershell
  target\release\smart-cleaner-core.exe restore <ITEM_ID>
  ```
* **Expected Result**: Pre-restore hash check fails. Returns error code `HASH_MISMATCH`. File is NOT restored to destination path.
* **Actual Result**: Restoration rejected; UI reports `Hash Mismatch` and flags corrupted vault item.
* **Status**: **PASS**
* **Limitations**: Does not attempt automatic error correction; manual review required.

---

### Scenario 11: Destination Collision Protection
* **Subsystem / API**: Pre-restore destination existence check.
* **Execution Class**: `[Automated]` & `[Windows-Runtime-Only]`
* **Fixture Setup**:
  ```powershell
  # Quarantine fixture, then recreate a new file at original location
  Set-Content -Path $fixture -Value "collision placeholder"
  ```
* **Execution Procedure**:
  ```powershell
  target\release\smart-cleaner-core.exe restore <ITEM_ID>
  ```
* **Expected Result**: Operation rejected with error code `RESTORE_CONFLICT`. Neither the destination file nor the vault item is overwritten.
* **Actual Result**: Returns `RESTORE_CONFLICT`. Destination file left intact.
* **Status**: **PASS**
* **Limitations**: User must manually rename or remove the conflicting destination file to proceed with restoration.
