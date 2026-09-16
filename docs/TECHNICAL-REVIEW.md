# Technical Review — Points to Lock Down Before Code

- **Date:** 2026-09-16
- **Applies to:** `SPEC-ar.md` (original design spec) and M0 core
- **Milestone mapping:** see "Feeds" on each point

---

## 1. Path Canonicalization

Windows is case-insensitive, has 8.3 short names, and full of junctions /
symlinks / reparse points. Every path must be **normalized before** the Risk
Engine sees it and before duplicate detection:

- lowercase + resolve reparse points (do not follow junctions into the same
  physical file)
- strip `\?\` and other prefix forms
- store the canonical form as the dedup key in `db.files`

> This is the #1 correctness bug source in this class of apps — an
> un-canonicalized path can slip past "is this a Windows path?" and past
> duplicate detection simultaneously.

**Feeds:** M1 (scanner), M4 (duplicates), `sc-db` schema.

## 2. In-Use Detection

Checking the process list (`GetModuleFileNameEx` etc.) is not sufficient —
locks exist without an obvious owning process. Best practical order:

1. Try to **rename** the file to a temp name (an in-use file cannot be
   renamed on NTFS) → rename back.
2. Or `CreateFile` with `FILE_SHARE_READ | FILE_SHARE_WRITE` (no `DELETE`).
3. Then, as attribution only, map to the owning process for the UI.

The verdict `IN_USE` must be set by (1)/(2), not by (3).

**Feeds:** M1 (`FILE_ATTRIBUTE_*`, process lock detection).

## 3. Browser Caches — Delete as a Block

Chrome's cache is a **LevelDB** database (Discord, Edge, etc. similar).
Deleting individual files from it corrupts the store. Rule:

- Treat `<browser>/Cache` (and similar DB-backed cache dirs) as **one unit**.
- Quarantine the whole directory atomically.
- Only when the owning browser is not running (in-use check, §2).

**Feeds:** M1 (software awareness), M2 (cleanup UX — one "Chrome Cache"
item, not thousands of rows).

## 4. Windows\Installer and WinSxS — Don't Hack, Delegate

- `Windows\Installer` contents (old MSI packages, `$PatchCache$`) are often
  **required for uninstall/repair**. Never score them as junk.
- For OS-level component cleanup, surface the built-in tools instead of
  manual deletion:
  - `Dism /Online /Cleanup-Image /StartComponentCleanup` (WinSxS)
  - Disk Cleanup / Storage Sense for system temp.
- `DriverStore`: only allow "superseded driver" removal via
  `pnputil /Delete-Oem` semantics, never raw file deletion.

**Feeds:** M1 (protected-location handling), M2 (Settings → "OS maintenance"
section).

## 5. Hash Budget

Full SHA-256 of a 72 GB game ISO takes 30+ minutes — it cannot be part of a
default scan. Enforce the pipeline strictly:

```
size + mtime bucket  →  partial hash (first + last 4 MB)  →  full SHA-256
```

- Full hash: **candidates only**, and **on-demand** from the UI, not
  automatic.
- Show ETA/progress and allow per-group skip for duplicate candidates.

**Feeds:** M4 (duplicate detection).

## 6. Quarantine Vault Location

If the vault lives on the same drive as the quarantined files, the user's
free space does not actually grow until they purge the vault.

- Vault location must be **user-configurable** (default: user profile,
  e.g. `%LOCALAPPDATA%\SmartCleaner\Quarantine`), not hardcoded to the
  source drive.
- Enforce a **maximum vault size** (e.g. default 20 GB) with a clear warning
  + explicit confirm when exceeded.
- UI must show: space freed so far vs. space held in vault.

**Feeds:** M1 (settings), M2 (Quarantine page), M5 (installer defaults).

## 7. Rollback Must Preserve NTFS ACLs

Quarantine must snapshot more than the hash:

- **ACL/SID** (and ownership) so `Restore` returns the file to the original
  user/permissions — a restored cache file owned by `SYSTEM` breaks the app
  that owns it.
- Also record: file attributes (hidden/system), USN journal id if available.

Restore checks (already in spec §10): path valid, no unexpected conflict,
hash match, disk space — add **permission restoration** to this list.

**Feeds:** M0 `sc-quarantine` (extend item record), M1 (Windows APIs).

## 8. Trust Boundary — Safety Engine Stays Native

This program will hold admin + full-disk access. Therefore:

- The **Safety Engine is the only code path that can delete/move a file**.
  It lives in Rust (`sc-safety-engine`); the Electron/JS layer can only send
  *intents* ("quarantine item X") which the engine re-validates.
- The IPC layer must **re-run the full rule check** on every request —
  never trust a verdict computed by the renderer (a compromised/hacked
  renderer must not be able to call delete directly).
- Every verdict carries the rule IDs that fired → audit log shows *which*
  hard rule blocked/allowed it.
- Distribution: **code-signing** for the binary *and* signed auto-updates
  (M5). An unsigned update to a full-disk tool is a footgun.

**Feeds:** M2 (IPC sidecar design), M5 (signing/packaging).
