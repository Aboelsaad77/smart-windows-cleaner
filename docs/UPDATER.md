# Secure Auto-Updater Architecture & Authenticity Specification

---

## 1. Executive Summary & Security Boundary

Smart Windows Cleaner implements a **Cryptographically Authenticated, Fail-Closed Auto-Updater** (Stage 2).

Unlike naive updater architectures that poll an unauthenticated HTTPS endpoint and compare raw hashes, Smart Windows Cleaner strictly bifurcates **Authenticity** from **Integrity**:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        AUTHENTICITY BOUNDARY                           │
│  Update Manifest (.json) MUST be signed with Ed25519 by Maintainer     │
│  Verified against embedded Pinned Public Key Allowlist (by 'kid')      │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ (Authenticity Verified)
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         INTEGRITY BOUNDARY                             │
│  Downloaded Artifact (.exe/.zip) verified via dual SHA-256 & SHA-512   │
│  Calculated locally and matched against signed manifest fields         │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ (Integrity Verified)
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        RUNTIME SAFETY BOUNDARY                         │
│  Never restart/apply during active Scan, Quarantine, Restore, or Purge │
│  Requires explicit user confirmation — Zero silent forced restarts     │
│  Portable Mode blocks in-place installation; offers verified ZIP path   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Cryptographic Architecture & Key Rotation

### Algorithmic Standards
* **Signature Algorithm**: **Ed25519** (RFC 8032 Edwards-curve Digital Signature Algorithm).
* **Payload Canonicalization**: RFC 8785 style deterministic JSON canonicalization (`canonicalizeJson`), sorting all dictionary keys recursively and stripping non-semantic whitespace.
* **Dual Hash Verification**: Both **SHA-256** (FIPS 180-4) and **SHA-512** (FIPS 180-4) dual hashes are verified.

### Pinned Public Key Allowlist
Public keys are pinned in the application binary (`desktop/electron/updater/keys.ts`). The application **never stores, ships, or transmits private keys**.

```typescript
export const PINNED_SIGNING_KEYS: Record<string, PinnedSigningKey> = {
  // Primary Production Release Signing Key
  'smartcleaner-release-2026-1': {
    kid: 'smartcleaner-release-2026-1',
    algorithm: 'ed25519',
    publicKeyPem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA+57X/ekyAT46Gf8ncu/LHnqiL3Q5iAs+rQ5TCffk1f8=\n-----END PUBLIC KEY-----',
    validFrom: '2026-09-01T00:00:00Z',
    description: 'Smart Windows Cleaner Primary 2026 Ed25519 Release Key',
    status: 'active',
  },

  // Transition Key for Planned Key Rotation
  'smartcleaner-release-2026-rotation': {
    kid: 'smartcleaner-release-2026-rotation',
    algorithm: 'ed25519',
    publicKeyPem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAhnAAPygdJKgSMQO94LnwqRx7PhZfbRyEiEZEDFMFBrw=\n-----END PUBLIC KEY-----',
    validFrom: '2026-09-15T00:00:00Z',
    description: 'Smart Windows Cleaner 2026 Transition Key for Rotation',
    status: 'transition',
  },
};
```

### Key Rotation Lifecycle
1. **Introduction**: A new key (e.g. `smartcleaner-release-2027-1`) is added with `status: 'transition'` in an application update while the older key remains `'active'`.
2. **Promotion**: Once the client base has adopted the new version, the new key is promoted to `'active'` and releases are signed with it.
3. **Retirement**: Older keys are marked `'retired'`. Manifests referencing retired keys are rejected (`UNKNOWN_SIGNING_KEY`).

---

## 3. Signed Update Manifest Specification

Update manifests are published as canonical JSON documents at the update release feed.

### Schema
```json
{
  "schema_version": "1.0.0",
  "version": "1.1.0",
  "channel": "stable",
  "release_date": "2026-09-18T12:00:00Z",
  "architecture": "x64",
  "artifact_filename": "SmartCleaner-Setup-1.1.0.exe",
  "artifact_size": 85123400,
  "sha256": "1f5805f99bedcf615a4f5bb28cb4cf38a82713ea967308bfbd3ff640c0bc0d4b",
  "sha512": "fb67e6145dab468c70fa01ed2e306140590a07185a8542c38cb6be44d9361ad28a6fcf74e2d09df28a38a7c21f8a846f49749eb403b983577d64380ebcd120aa",
  "download_url": "https://github.com/Aboelsaad77/smart-windows-cleaner/releases/download/v1.1.0/SmartCleaner-Setup-1.1.0.exe",
  "min_supported_version": "1.0.0",
  "release_notes": "Security hardening, improved WinSxS heuristics, and performance improvements.",
  "kid": "smartcleaner-release-2026-1",
  "signature": "base64_encoded_ed25519_signature_over_canonical_payload"
}
```

### Canonical Signing & Verification Procedure
1. Extract all properties except `"signature"` into an unsigned payload object.
2. Canonicalize the object via `canonicalizeJson(unsigned)` (recursive lexicographical sorting of keys, zero superfluous spaces).
3. Convert the canonical UTF-8 string into a byte buffer.
4. Sign with maintainer's offline Ed25519 private key.
5. Encode signature as Base64 and assign to `"signature"`.

---

## 4. End-to-End Update Flow

```text
App Starts or User Checks Updates
                │
                ▼
      Fetch Manifest (.json)
                │
                ▼
     Lookup 'kid' in Pinned Keys
     ├── Unknown / Retired? ───────────────► FAIL CLOSED: UNKNOWN_SIGNING_KEY
     └── Found Active/Transition Key
                │
                ▼
  Ed25519 Signature Verification
     ├── Invalid / Tampered? ──────────────► FAIL CLOSED: METADATA_SIGNATURE_INVALID
     └── Signature Valid
                │
                ▼
   Semantic Version Validation
     ├── Malformed Semver? ────────────────► FAIL CLOSED: UNSUPPORTED_VERSION
     ├── Version <= Current? ──────────────► HALT: DOWNGRADE_ATTEMPT / UP_TO_DATE
     └── Version > Current (Upgrade)
                │
                ▼
   Channel Compatibility Check
     ├── Channel Mismatch? ────────────────► HALT: CHANNEL_MISMATCH (No auto-switch)
     └── Channel Compatible
                │
                ▼
     State: Update Available
                │
                ▼
     User Initiates Download
                │
                ▼
Download Artifact to Secure Temp Directory
                │
                ▼
 Dual-Hash Cryptographic Verification
 ├── SHA-256 !== manifest.sha256? ────────► FAIL CLOSED: ARTIFACT_HASH_MISMATCH (Purge Staged File)
 ├── SHA-512 !== manifest.sha512? ────────► FAIL CLOSED: ARTIFACT_HASH_MISMATCH (Purge Staged File)
 └── Size !== manifest.artifact_size? ────► FAIL CLOSED: ARTIFACT_HASH_MISMATCH (Purge Staged File)
                │
                ▼
      State: Downloaded & Ready
                │
                ▼
     User Clicks [Restart & Apply]
                │
                ▼
  Check Runtime Engine Busy State
  ├── Scan / Quarantine Running? ─────────► DEFER: "Update Ready — Restart when current operation finishes."
  ├── Portable Mode Active? ──────────────► BLOCK: PORTABLE_MODE_BLOCKED (Manual ZIP download only)
  └── Engine Idle & User Confirmed
                │
                ▼
     Launch Installer & Exit App
```

---

## 5. Version Security & Channel Enforcement

### Downgrade Protection
* Any manifest offering a version `v_new <= v_current` is blocked with `DOWNGRADE_ATTEMPT`.
* Prevents malicious network adversaries or compromised mirrors from replaying older, vulnerable release packages.

### Channel Hierarchy
* Supported channels: `stable`, `beta`, `rc`.
* A client configured for `stable` will never download or prompt for `beta` or `rc` builds.
* Channel switching requires explicit user selection in Settings and is never performed automatically.

---

## 6. Runtime Safety & Deferred Restarts

Smart Windows Cleaner strictly prevents process termination or updater relaunch while critical disk operations are in flight:

| Active Operation | Engine Safety Behavior | Updater Response |
| :--- | :--- | :--- |
| **Active Scan** | File descriptors are held open; memory caches active. | Blocks restart; sets state to `deferred_busy`; displays: `Update Ready — Restart when current operation finishes.` |
| **Quarantine in Progress** | Atomic moving of files and SQLite ledger updates. | Blocks restart; preserves vault integrity; update remains staged. |
| **Restore in Progress** | Atomic restitution of files from vault to original path. | Blocks restart; prevents partial or corrupted file restorations. |
| **Purge in Progress** | Secure unlinking and ledger pruning. | Blocks restart; prevents corrupted audit database states. |

Once all active operations complete and the engine returns to idle, the user can click **Restart & Apply Update**.

---

## 7. Portable Mode Protection

When Smart Windows Cleaner detects that it is operating in Portable Mode (via `PORTABLE_EXECUTABLE_DIR`, `SMART_CLEANER_PORTABLE`, or external execution outside `%LOCALAPPDATA%\Programs\SmartCleaner`):
1. **In-Place Execution Blocked**: Running the NSIS installer is prohibited to prevent polluting host system registries or directories.
2. **User Notification**: The UI clearly displays:
   `New Release v<version> Available (Portable Mode Active)`
   `Automatic in-place updater is disabled in Portable Mode to preserve system isolation. Please download the verified ZIP package manually.`
3. **Verified Download Link**: Provides a direct link to `SmartCleaner-Portable-<version>.zip` along with its verified SHA-256 hash.

---

## 8. IPC Architecture & Threat Model

* All updater operations are executed in the **Electron main process**.
* The sandboxed React renderer cannot:
  * Fetch binary executables directly.
  * Execute files or spawn subprocesses.
  * Access arbitrary filesystem paths.
* Whitelisted IPC commands:
  * `updater_get_status`
  * `updater_check_for_updates`
  * `updater_download_update`
  * `updater_apply_update` (enforces `confirm: true`)
  * `updater_set_channel`
  * `updater_cancel`

---

## 9. Failure Modes & Handling Matrix

| Failure Mode | Trigger Condition | System Action | Error Code |
| :--- | :--- | :--- | :--- |
| **Network Unavailable** | DNS failure, connection reset, offline | Retains existing state; informs user | `NETWORK_UNAVAILABLE` |
| **Metadata Unavailable** | HTTP 404 / 500 on manifest URL | Retains existing state; informs user | `METADATA_UNAVAILABLE` |
| **Invalid Signature** | Ed25519 signature does not match payload | Fails closed; halts update check | `METADATA_SIGNATURE_INVALID` |
| **Unknown Key** | Manifest `kid` missing from pinned table | Fails closed; halts update check | `UNKNOWN_SIGNING_KEY` |
| **Downgrade Attempt** | Version <= current installed version | Fails closed; blocks download | `DOWNGRADE_ATTEMPT` |
| **Channel Mismatch** | Manifest channel incompatible with user config | Ignores update; logs mismatch | `CHANNEL_MISMATCH` |
| **Hash Mismatch** | SHA-256 or SHA-512 differs post-download | Deletes staged file immediately | `ARTIFACT_HASH_MISMATCH` |
| **Truncated Download** | Download byte count < `artifact_size` | Deletes staged file immediately | `INTERRUPTED_DOWNLOAD` |
| **Engine Busy** | User triggers restart during scan/quarantine | Defers restart until idle | `ENGINE_BUSY` |
| **Portable Mode** | In-place install attempted in portable mode | Blocks execution; shows manual link | `PORTABLE_MODE_BLOCKED` |
| **Missing Confirm** | `apply_update` called without `confirm: true` | Rejects execution | `CONFIRMATION_REQUIRED` |

---

## 10. Windows Authenticode Code Signing Status

### Distinction: Ed25519 Manifest Signing vs. Windows Authenticode
* **Current Implementation**: All update manifests and releases are verified using **Ed25519 digital signatures** against pinned public keys, alongside dual **SHA-256** and **SHA-512** integrity verification.
* **Authenticode Code Signing**: Windows native Authenticode signing requires an **Extended Validation (EV)** or **Organization Validation (OV)** hardware token or cloud-based Hardware Security Module (HSM) certificate (e.g., Azure Key Vault / DigiCert ONE) recognized by the Microsoft SmartScreen filter.
* **Production Deployment Status**:
  * Because physical cryptographic hardware tokens cannot and must not be checked into Git repositories or exposed in ephemeral sandboxes, **Authenticode signing is explicitly documented as a pre-release publication step** rather than faked with an unverified self-signed certificate.
  * In production CI, `signtool.exe` signs `smart-cleaner-core.exe` and `SmartCleaner-Setup-*.exe` via GitHub Actions environment secrets prior to packaging.
  * The updater's Ed25519 signature verification operates independently of Windows Authenticode, ensuring application-level cryptographic trust even in air-gapped or non-standard environments.

---

## 11. Privacy & Zero-Telemetry Guarantee

* **No Telemetry**: The update check performs a simple anonymous GET request to the static manifest JSON endpoint.
* **Zero Data Transmission**: No user identifiers, hardware UUIDs, IP logs, scan summaries, file names, hashes, or SQLite audit ledger records are ever transmitted to the update endpoint.
