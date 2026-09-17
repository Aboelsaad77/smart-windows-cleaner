# Release Architecture, Packaging & Verification Guide

This document defines the authoritative release procedure, CI/CD automation, local build reproduction, cryptographic verification, rollback operations, and cross-repository adaptation licensing for **Smart Windows Cleaner**.

---

## 1. Stage 1 Scope & Boundary Enforcement

This implementation represents **Stage 1: CI/CD + Windows Release Packaging**:
* **In Scope**:
  * Automated Windows CI/CD pipeline via GitHub Actions (`.github/workflows/build-windows.yml`).
  * Windows release packaging with Electron Builder producing **NSIS Installer** and **Portable ZIP**.
  * Bundling of the native Rust core executable (`smart-cleaner-core.exe`) into `resources/bin/`.
  * Cryptographic release manifests (`checksums.txt` and `checksums.json` with SHA-256 and SHA-512).
  * Automated verification gate preventing publication if artifacts are missing, truncated, or inconsistent.
  * Tag-triggered release publishing restricted to explicit version tags (`v*`).
* **Explicitly Out of Scope**:
  * **Stage 2 (Auto-Updater)**: No background update checks, feed polling, or in-place binary swaps are included. The future updater will require pinned public key verification (Ed25519) and will never rely on unauthenticated hash comparisons alone.
  * **Stage 3 (Licensing System)**: No device registration, token granting, or feature lockouts are included. Any future licensing integration will strictly gate UI presentation and convenience features, never safety rules or deletion invariants.
* **Core Invariant Freeze**:
  * All 13 core safety semantics, pre-flight revalidation gates, and multi-tier quarantine vault isolation models (`%LOCALAPPDATA%` and `%PROGRAMDATA%`) remain 100% byte-for-byte preserved and frozen.

---

## 2. Release Deliverables Specification

Each official release of Smart Windows Cleaner produces four deliverables:

| Deliverable | Filename Pattern | Distribution Type | Target Audience / Scope |
| :--- | :--- | :--- | :--- |
| **Interactive NSIS Setup** | `SmartCleaner-Setup-<version>.exe` | Executable Installer | Standard users & admins; defaults to per-user install (`%LOCALAPPDATA%\Programs\SmartCleaner`) without requiring UAC at launch. Optional machine-wide install available. |
| **Portable ZIP Archive** | `SmartCleaner-Portable-<version>.zip` | Standalone ZIP | Portable, zero-install environments, forensic workstations, and air-gapped systems. |
| **Cryptographic Manifest (Text)** | `checksums.txt` | GNU-format Text | Checksum verification via `sha256sum`, `sha512sum`, or `certutil`. |
| **Cryptographic Manifest (JSON)** | `checksums.json` | Canonical JSON | Structured metadata containing file sizes, SHA-256, SHA-512, release version, and git commit SHA. |

### Packaged Directory Hierarchy
```text
%LOCALAPPDATA%\Programs\SmartCleaner\
├── SmartCleaner.exe                  <-- Main Electron executable (hardened sandbox)
├── resources\
│   ├── app.asar                      <-- Transpiled React client & Electron main process
│   └── bin\
│       └── smart-cleaner-core.exe    <-- Native Rust Core (safety engine + scanner)
└── ... runtime dependencies
```

### Uninstallation & Storage Guarantees
* The NSIS uninstaller purges application binaries and registry keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\SmartCleaner`).
* In compliance with `PACKAGING-AND-SECURITY.md`, `deleteAppDataOnUninstall` is set to `false`. The user's quarantine vault (`%LOCALAPPDATA%\SmartCleaner\Vault\`) and forensic SQLite ledger (`audit.db`) are never deleted during application uninstall, ensuring users do not permanently lose recoverable quarantined files.

---

## 3. Local Build Instructions

### Prerequisites
1. **Operating System**: Windows 10 (Build 19041+) or Windows 11 64-bit (x64).
2. **Rust Toolchain**: Stable Rust (1.80+) with `x86_64-pc-windows-msvc` target, `clippy`, and `rustfmt`.
   ```bash
   rustup default stable
   rustup component add clippy rustfmt
   ```
3. **Node.js Environment**: Node.js 20 LTS (Active LTS) and npm 10+.
   ```bash
   node --version # v20.x
   npm --version
   ```

### Step-by-Step Compilation

#### 1. Compile Rust Core (Native Release Binary)
```bash
cd core
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --bin smart-cleaner-core
cd ..
```
*Output*: `core/target/release/smart-cleaner-core.exe`

#### 2. Build Frontend & Transpile Electron
```bash
cd desktop
npm ci
npm run typecheck
npm test
npm run build
```
*Output*: `desktop/dist/` (React SPA bundle) and `desktop/dist-electron/` (transpiled Electron scripts).

#### 3. Package Windows Deliverables
```bash
npm run package
```
*Output*: `desktop/dist-release/SmartCleaner-Setup-1.0.0.exe` and `desktop/dist-release/SmartCleaner-Portable-1.0.0.zip`.

#### 4. Run Release Integrity & Checksum Verification
```bash
npm run verify-release
```
*Output*: Validates deliverables, verifies size thresholds, and outputs `checksums.txt` and `checksums.json` into `desktop/dist-release/`.

---

## 4. CI/CD Pipeline Architecture (`build-windows.yml`)

The automated release pipeline is configured in `.github/workflows/build-windows.yml`.

### Pipeline Quality Gates & Execution Flow
```text
  [Git Tag (v*) or Push to main]
                 │
                 ▼
     Windows Runner (windows-latest)
                 │
        ┌────────┴────────┐
        ▼                 ▼
   Rust Setup        Node 20 Setup
   (toolchain +      (npm ci +
    rust-cache)       npm cache)
        │                 │
        ▼                 ▼
   Cargo fmt         TypeScript
   Cargo clippy      Typecheck
   Cargo test        Vitest Suite
   (157/157 pass)    (83/83 pass)
        │                 │
        └────────┬────────┘
                 ▼
    Build smart-cleaner-core.exe (Rust Release)
                 │
                 ▼
    Build Frontend Assets (Vite + Electron TSC)
                 │
                 ▼
    Package Deliverables (Electron Builder)
    ├── SmartCleaner-Setup-<ver>.exe
    └── SmartCleaner-Portable-<ver>.zip
                 │
                 ▼
    Integrity Verification Gate (verify-release-artifacts.mjs)
    ├── Checks minimum file size (> 5 MB)
    ├── Computes SHA-256 and SHA-512
    ├── Generates checksums.txt & checksums.json
    └── Fails workflow if any artifact is missing or corrupted
                 │
                 ▼
    Upload CI Run Artifacts (actions/upload-artifact@v4)
                 │
                 ▼
    Conditional GitHub Release (softprops/action-gh-release@v2)
    * Gated by: startsWith(github.ref, 'refs/tags/v')
    * Publishes binaries and manifests to GitHub Releases
```

### Tag-Only Release Publishing Security Guard
* The workflow triggers on pushes to `main` to run continuous integration tests and packaging validation.
* **Releases are NEVER published to GitHub on pushes to `main`.**
* The release publishing step includes the strict guard:
  ```yaml
  if: startsWith(github.ref, 'refs/tags/v')
  ```
* Creating an official release requires pushing an explicit Git tag:
  ```bash
  git tag -a v1.0.0 -m "Release v1.0.0"
  git push origin v1.0.0
  ```

---

## 5. Cryptographic Checksum Verification

End users and enterprise administrators can independently verify the authenticity and integrity of downloaded deliverables.

### Using PowerShell (Windows Native)
```powershell
# Compute SHA-256
Get-FileHash .\SmartCleaner-Setup-1.0.0.exe -Algorithm SHA256

# Compute SHA-512
Get-FileHash .\SmartCleaner-Setup-1.0.0.exe -Algorithm SHA512
```

### Using Windows `certutil`
```cmd
certutil -hashfile SmartCleaner-Setup-1.0.0.exe SHA256
certutil -hashfile SmartCleaner-Portable-1.0.0.zip SHA256
```

### Using Linux / macOS / WSL
```bash
sha256sum -c checksums.txt --ignore-missing
```

### Using the Bundled Node.js Verification Script
```bash
node desktop/scripts/verify-release-artifacts.mjs --dir /path/to/downloaded/release --verify
```

---

## 6. Rollback Procedures

### Local User Rollback
If a user encounters an issue with a newly installed version and wishes to revert to a previous release:
1. Run the existing version's uninstaller via Windows Settings -> Apps -> Installed Apps -> Smart Cleaner -> Uninstall.
   * *Safety Note*: The quarantine vault at `%LOCALAPPDATA%\SmartCleaner\Vault\` and the SQLite audit log at `%LOCALAPPDATA%\SmartCleaner\audit.db` are **retained intact**.
2. Install the previous known-good version installer (e.g., `SmartCleaner-Setup-1.0.0.exe`).
3. Upon launch, the previous version automatically binds to the existing SQLite ledger and vault, preserving full quarantine history and restoration capabilities.

### Distribution & Release Rollback (Repository Maintainers)
If an official release artifact is found to contain a defect post-publication:
1. **GitHub Release Retraction**:
   * Navigate to GitHub Repository -> Releases -> Edit Release -> Check **"Set as a pre-release"** or click **"Delete release"** to immediately prevent further end-user downloads.
2. **Git Tag Deletion**:
   ```bash
   # Delete remote tag
   git push --delete origin v1.0.0
   # Delete local tag
   git tag -d v1.0.0
   ```
3. **Hotfix Protocol**:
   * Create a patch branch from the release commit.
   * Apply necessary fixes.
   * Increment patch version in `desktop/package.json` and `core/Cargo.toml` (e.g., `1.0.1`).
   * Tag and push `v1.0.1` to trigger a clean automated build and publication.

---

## 7. Cross-Repository Adaptation & Licensing Attribution

### Sibling Audit Summary
Smart Windows Cleaner's CI/CD and packaging configuration was developed after conducting a formal cross-repository technical and licensing audit of six sibling repositories in the author's portfolio:
1. `PortSaid-Media-Downloader-v2` (Electron packaging, NSIS customization, workflow architectures)
2. `PortSaid-Store` (Backend token models and licensing infrastructure)
3. `PortSaid-Subtitle-Manager` (Safe file manipulation and desktop ergonomics, MIT License)
4. `phone-accessories-store` (Web storefront architecture)
5. `sandbox` (Exploratory tooling)
6. `youssef-1123/games` (Application distribution platform)

### Attribution & Licensing Compliance
* **Origin & Authorship**: The CI/CD workflows, NSIS configuration options, and integrity manifest verification scripts in this repository were adapted from proven patterns established by Abdelrahman Aboelsaad across the PortSaid software suite.
* **No License Contagion**: None of the adapted components incorporate GPL, AGPL, or reciprocal copyleft code. All adapted packaging logic is permissively licensed and compatible with internal or open-source distribution.
* **Dependency Isolation**: All third-party dependencies (`electron-builder`, `lucide-react`, `vite`, `rusqlite`, `serde`, etc.) use standard permissive licenses (MIT, Apache 2.0, BSD-3-Clause).
