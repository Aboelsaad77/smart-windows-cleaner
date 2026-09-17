# Windows Native Runtime Validation Suite & Checklist (M4.1 – M4.4)

This specification defines the validation criteria, disposable fixture harnesses, and execution procedures for verifying Smart Windows Cleaner against real Windows 10/11 environments.

---

## 1. M4.1 — Windows Native API Validation Checklist

### 1.1 Elevation & Token Detection
* **API / Subsystem**: `OpenProcessToken`, `GetTokenInformation(TokenElevation)`, `CheckTokenMembership`.
* **Behavior Tested**:
  * Standard User Token (`TokenElevation = 0`): App reports `uac_level: standard_user`, `is_elevated: false`.
  * Elevated Administrator Token (`TokenElevation != 0`): App reports `uac_level: elevated_admin`, `is_elevated: true`.
  * Split-token UAC (Filtered Token): Detects non-elevated administrator without crashing or asserting false privileges.
* **Disposable Fixture**:
  * Run test binary under un-elevated `cmd.exe` $\rightarrow$ assert non-elevated.
  * Run test binary under `powershell Start-Process -Verb RunAs` $\rightarrow$ assert elevated.

### 1.2 Windows File Attributes (`FILE_ATTRIBUTE_HIDDEN`, `FILE_ATTRIBUTE_SYSTEM`)
* **API / Subsystem**: `GetFileAttributesW`.
* **Behavior Tested**:
  * Attributes properly mapped into `FileAttributesDto` (`is_hidden`, `is_system`, `is_readonly`).
  * Safety Engine flags `FILE_ATTRIBUTE_SYSTEM` as elevated risk factor (`SYSTEM_FILE`).
* **Disposable Fixture**:
  ```powershell
  New-Item -ItemType File -Path "$env:TEMP\fixture_hidden.tmp"
  attrib +h "$env:TEMP\fixture_hidden.tmp"
  New-Item -ItemType File -Path "$env:TEMP\fixture_system.tmp"
  attrib +s "$env:TEMP\fixture_system.tmp"
  ```

### 1.3 Authenticode & Digital Signature Verification (`WinVerifyTrust`)
* **API / Subsystem**: `Wintrust.dll` (`WinVerifyTrust`), `CryptQueryObject`, `CertGetNameStringW`.
* **Behavior Tested**:
  * Valid Microsoft OS binary (`C:\Windows\System32\notepad.exe`): returns `SignedValid`, publisher `"Microsoft Corporation"`, thumbprint verified against root store.
  * Valid Third-Party Signed binary (e.g. Chrome/VS Code installer): returns `SignedValid`, non-Microsoft publisher.
  * Unsigned binary (compiled disposable .exe): returns `Unsigned`, preventing promotion to `AutoQuarantine`.
  * Tampered / Corrupted signature (appended byte to signed binary): returns `InvalidSignature`, flagged with maximum risk weight.

### 1.4 32-bit & 64-bit Uninstall Registry Views (`Registry32`, `Registry64`)
* **API / Subsystem**: `RegOpenKeyExW` with `KEY_WOW64_64KEY` and `KEY_WOW64_32KEY`.
* **Behavior Tested**:
  * Enumeration of both `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall` (64-bit) and `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` (32-bit).
  * Software attribution mapped accurately across architecture redirects without duplicate app entries.

### 1.5 Live Process File Lock Detection
* **API / Subsystem**: `CreateFileW` with `GENERIC_READ | GENERIC_WRITE`, `dwShareMode: 0` (exclusive).
* **Behavior Tested**:
  * File held with exclusive lock returns `ERROR_SHARING_VIOLATION` (OS Error 32).
  * Pre-flight engine identifies lock and sets `is_in_use: true`, prohibiting quarantine execution and leaving source untouched.
* **Disposable Fixture**:
  ```powershell
  $file = [System.IO.File]::Open("$env:TEMP\fixture_locked.log", [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
  # Run Core scan -> verify FILE_IN_USE reported
  $file.Close()
  ```

### 1.6 NTFS Reparse Points, Junctions, & Symbolic Links
* **API / Subsystem**: `GetFileAttributesW` (`FILE_ATTRIBUTE_REPARSE_POINT`), `FSCTL_GET_REPARSE_POINT`.
* **Behavior Tested**:
  * Junction points (e.g. `C:\Users\All Users` $\rightarrow$ `C:\ProgramData`) detected without recursive infinite loops.
  * Scanner does NOT traverse across volume mount points unless explicitly configured.
  * Hard links: Correctly reports identical file IDs (`nFileIndexLow`, `nFileIndexHigh`) to avoid double-counting reclaimable bytes.

### 1.7 Windows Protected Paths & WinSxS Component Store
* **API / Subsystem**: Native path normalization, case-insensitive comparison, hard-coded safety boundary.
* **Behavior Tested**:
  * `C:\Windows\WinSxS`: Classified as permanently locked component store (`is_locked: true`).
  * `C:\Windows\System32\drivers`: Classified as protected system directory (`verdict: never_delete`).
  * `C:\ProgramData\Microsoft\Windows Defender`: Protection maintained against accidental purge.

---

## 2. M4.2 — Real Electron ↔ Rust Core IPC Lifecycle

```text
[ React UI ] 
     ↕ contextBridge (window.smartCleanerIpc)
[ Electron Preload (sandbox: true) ]
     ↕ ipcRenderer.invoke('smart-cleaner:ipc')
[ Electron Main Process ]
     ↕ child_process.spawn stdio pipe (JSON-lines)
[ Rust Core Process (smart-cleaner-core.exe) ]
     ↕ Core Router / Dispatcher
[ Safety Engine & Scanner ]
```

### IPC Channel Protocol Properties
1. **Strict Channel Whitelist**: Electron main process accepts ONLY registered actions (`ping`, `start_scan`, `quarantine_selected`, etc.).
2. **Correlation IDs**: Every request carries a client-generated UUID. Responses strictly match this ID.
3. **Stdio Streaming**: Core emits newline-delimited JSON objects for progress events (`scan_progress`, `quarantine_progress`).
4. **Crash Recovery & Reconnect**: If the Core process exits unexpectedly, the Main process restarts it (up to 3 times/10s) and emits a diagnostic alert to the UI.

---

## 3. M4.3 — 13 Disposable Safety Scenarios Matrix

| Scenario # | Condition | Disposable Windows Fixture | Expected Core Behavior | Expected Desktop UI Behavior |
| :--- | :--- | :--- | :--- | :--- |
| **1** | Ordinary Temp Candidate | Dummy `.tmp` in `%TEMP%\sample.tmp` older than 7d | `SafetyVerdict::AutoQuarantine` | Checkbox enabled, classified as `Safe` |
| **2** | Windows Protected File | `%SYSTEMROOT%\System32\drivers\test.sys` | `SafetyVerdict::NeverDelete` | Disabled checkbox, lock icon, explainability prohibit reason |
| **3** | WinSxS File | `%SYSTEMROOT%\WinSxS\manifest.tmp` | Hard safety engine rejection | Reclaimable space = 0, selection blocked |
| **4** | Unsigned Executable | Local un-signed `sample.exe` in Downloads | Downgraded to `UserConfirm`, risk score $\ge 60$ | Marked `Review`, requires explicit user confirmation |
| **5** | Signed Userland Executable | Valid signed third-party installer | Risk evaluated on age and location | Clear publisher badge in explainability drawer |
| **6** | Signed Windows System Binary | Signed system component | `SafetyVerdict::NeverDelete` | Selection permanently forbidden |
| **7** | Locked File | File opened with `FileShare.None` | Pre-flight error `FILE_IN_USE` | Warning badge, operation aborted before move |
| **8** | State-Drifted File | File modified after scan completion | Pre-flight hash mismatch $\rightarrow$ `STATE_DRIFT` | Alert banner, candidates list auto-refreshed |
| **9** | Symlink / Junction | Reparse point created via `mklink` | Target inspected, reparse point link preserved | No recursive loop, link target safety enforced |
| **10** | User Exclusion Path | Path configured in user exclusions | Scanner skips path entirely | Never listed in cleanup candidates |
| **11** | Missing Source | File deleted between scan and quarantine | `SOURCE_NOT_FOUND` | Removed from candidate list without crash |
| **12** | Restore Conflict | New file already exists at restore destination | `RESTORE_CONFLICT` | Restore aborted, collision dialog displayed |
| **13** | Corrupted Quarantine Item | Quarantined vault payload altered manually | `HASH_MISMATCH` before restoring | Restoration rejected, vault corruption flagged |

---

## 4. M4.4 — Quarantine & Restore Cryptographic Integrity

1. **Pre-Quarantine SHA-256**: Calculated on live source file before relocation.
2. **Atomic Vault Isolation**:
   - File moved to vault directory: `%PROGRAMDATA%\SmartCleaner\Vault\{item_id}.dat`.
   - Manifest recorded in SQLite: `(item_id, original_path, sha256_hash, size_bytes, quarantined_at, retention_days)`.
3. **Pre-Restore SHA-256**: Hash computed on `{item_id}.dat` prior to copying back.
4. **Collision Safe**: Target path checked with `GetFileAttributesW`; if destination exists, returns `RESTORE_CONFLICT`.
5. **Zero-Byte / Low-Space Protection**: Vault partition free space validated against file size prior to initiating move.
