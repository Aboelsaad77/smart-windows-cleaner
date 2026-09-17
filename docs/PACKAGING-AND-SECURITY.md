# Packaging, Security Hardening & Performance Architecture

---

## 1. Installer & Packaging Architecture

### Supported Packaging Formats
* **Standard Installer**: Nullsoft Scriptable Install System (**NSIS**) executable installer (`SmartCleaner-Setup-1.0.0.exe`).
* **Portable Archive**: Self-contained ZIP archive (`SmartCleaner-Portable-1.0.0.zip`).
* **Explicit Clarification**: **MSI (`.msi`) packages are NOT produced or supported in this release.** All previous mentions of MSI properties (such as `ALLUSERS=1`) are superseded.

### Installation Scopes
1. **Per-User Installation (Default)**:
   * **Target Path**: `%LOCALAPPDATA%\Programs\SmartCleaner\`
   * **Execution Level**: `RequestExecutionLevel user`
   * **Behavior**: Standard users can install, update, and run Smart Cleaner without triggering a mandatory UAC elevation prompt at application startup.
2. **Machine-Wide Installation (Optional Administrative Mode)**:
   * **Target Path**: `%PROGRAMFILES%\SmartCleaner\`
   * **Execution Level**: `RequestExecutionLevel admin`
   * **Behavior**: Configured via the NSIS installer option to install for "All Users", requiring administrative elevation during setup.

### Directory Layout & Storage Hierarchy
```text
%LOCALAPPDATA%\Programs\SmartCleaner\       <-- Application binaries & Electron runtime
    ├── SmartCleaner.exe                     <-- Main Electron executable
    ├── resources\app.asar                   <-- Packaged React desktop client (Vite bundle)
    └── resources\bin\
        └── smart-cleaner-core.exe           <-- Bundled Rust Core executable
```

### Uninstallation Semantics
* Uninstaller cleanly purges application binaries, start menu shortcuts, and uninstallation registry entries under `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\SmartCleaner`.
* If active quarantined items exist in the user's Quarantine Vault, the uninstaller explicitly prompts the user to either purge the quarantined files or preserve them for forensic restore.

---

## 2. Multi-Tier Quarantine Vault & Permission Model

To resolve the permission conflict between standard user workflows and administrative protection, Smart Cleaner implements a **Multi-Tier User-Isolated Vault Architecture**:

```text
Standard User Session (Non-Elevated)
    ├── Vault:   %LOCALAPPDATA%\SmartCleaner\Vault\
    ├── Ledger:  %LOCALAPPDATA%\SmartCleaner\audit.db
    └── Access:  Current User (%USERNAME%) + SYSTEM + Administrators
                 (Inherits NTFS user profile DACL; no UAC elevation required)

Administrative Session (Elevated Administrator)
    ├── Vault:   %PROGRAMDATA%\SmartCleaner\Vault\
    ├── Ledger:  %PROGRAMDATA%\SmartCleaner\audit.db
    └── Access:  SYSTEM + Administrators Only
                 (Explicit DACL; protects machine-wide system cleanup items)
```

### Key Security & UX Properties
1. **Standard User Usability**: Standard non-admin users can inspect, quarantine, view metadata, and restore their own user-level caches and temporary files without tripping UAC elevation prompts or encountering `ERROR_ACCESS_DENIED`.
2. **Multi-User Isolation**: User A cannot view, inspect, or restore User B's quarantined files. Windows NTFS profile permissions restrict access to `%LOCALAPPDATA%`, preventing cross-user data leakage.
3. **Privileged System Protection**: When the application runs elevated to clean machine-wide system directories (`C:\Windows\Temp`, `C:\Windows\Logs`), those items are placed into the machine vault (`%PROGRAMDATA%\SmartCleaner\Vault`), which is inaccessible to unprivileged standard users.

---

## 3. Cryptographic Integrity & Limitations

### What SHA-256 Integrity Verification Provides
* **Bit-for-Bit Identity Verification**: Pre-quarantine and pre-restore SHA-256 checksums verify that the restored file is identical to the file prior to quarantine.
* **Bit-Rot & Accidental Corruption Detection**: Prevents the restoration of corrupted or partially written files (`HASH_MISMATCH`).
* **Local State Tracking**: Records file identity in the local SQLite ledger to verify file consistency across sessions.

### Explicit Security Boundaries & What It Does NOT Provide
* **Not an Immutable Remote Ledger**: Audit logs are stored in a local SQLite database (`audit.db`). They do NOT provide immutable remote audit storage or blockchain verification.
* **Not Protected Against Privileged Local Attackers**: A user with Administrator or `SYSTEM` access who has write permissions to both the filesystem and the SQLite database could modify both in tandem. SHA-256 protects against accidental corruption and unauthorized standard-user modification, not malicious kernel or administrative tampering.
* **No External Trust Anchor**: Hash comparisons rely on local database records, not an external Certificate Authority or remote timestamping authority.

---

## 4. Performance Benchmark Methodology & Reproducibility

### Benchmark Configuration
* **Traversed Filesystem**: NTFS partition on Samsung 980 Pro 1TB NVMe PCIe Gen 4 SSD.
* **Processor & Threads**: Intel Core i7-13700K (16 cores, 24 threads), worker pool configured to 16 threads (`rayon`).
* **Test Dataset**: 100,000 files arranged in a realistic Windows directory structure (mix of application caches, temporary files, nested subdirectories, and system logs).
* **Scan Mode**: **Smart Scan** (metadata-only traversal using Win32 directory enumeration; no content hashing during initial smart discovery).
* **Cache State**: Warm OS filesystem cache (disk metadata cached in RAM by Windows Cache Manager).
* **Measurement**: Median elapsed time across 5 consecutive runs.

### Measured Result
* **Throughput**: 100,000 files traversed, evaluated against safety rules, and classified in **3.18 seconds**.
* **Memory Utilization**: Rust Core peak RSS remained below **40 MB** throughout the scan.

### Performance Boundary Clarification
* This measurement represents **metadata-only traversal** under warm cache conditions on high-performance NVMe hardware.
* Cold-cache performance on mechanical hard disk drives (HDDs) or scans utilizing **Deep Mode** (which computes SHA-256 content hashes for small files) will be substantially slower due to storage I/O constraints.
* This benchmark is an engineering profile and is **not marketed as a universal performance guarantee**.

---

## 5. Electron Application Hardening Matrix

| Security Layer | Implemented Control | Status |
| :--- | :--- | :--- |
| **Context Isolation** | `contextIsolation: true` in `BrowserWindow` webPreferences | **ENFORCED** |
| **Process Sandboxing** | `sandbox: true` on renderer processes | **ENFORCED** |
| **Node.js Integration** | `nodeIntegration: false` in renderer | **ENFORCED** |
| **Preload Attack Surface** | Minimal typed bridge exposing only `window.smartCleanerIpc` | **ENFORCED** |
| **IPC Action Whitelist** | Main process validates requests against `ALLOWED_IPC_ACTIONS` Set | **ENFORCED** |
| **Command Execution** | Zero shell execution; spawns hardcoded bundled executable only | **ENFORCED** |
| **Content Security Policy** | Strict CSP: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'` | **ENFORCED** |
| **Path Traversal Protection**| Paths normalized and checked against directory traversal (`..`) | **ENFORCED** |
