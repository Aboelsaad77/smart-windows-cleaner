# M0 Code Audit

- **Date:** 2026-09-16
- **Scope:** all 8 crates + `schema.sql` (full manual read), `cargo test --workspace` = 50/50 green
- **Checklist:** `docs/TECHNICAL-REVIEW.md` (8 points) + general robustness

---

## Scorecard — the 8 review points

| # | Point | Status | Notes |
|---|-------|--------|-------|
| 1 | Path canonicalization | ⚠️ partial | `known_paths::norm()` (lowercase + backslash) is used for prefix matching in scanner/safety — good. But: exact-file exclusions compare raw `PathBuf`s (case-sensitive), and `db.files` stores raw paths with case-sensitive `UNIQUE(session_id, path)`. No reparse/8.3 resolution yet (M1). |
| 2 | In-use detection | 🔲 M1 stub | `FileRecord.in_use` exists; risk engine (+80, floor 95) and hard rule `CURRENTLY_IN_USE` are ready. Nothing ever sets the field. **M1 must use the rename-test** (review §2), not process-list only. |
| 3 | Browser caches as a block | ⚠️ partial | Heuristics are right (cache subdirs only — profile with cookies/passwords correctly excluded). But the vault is **file-only** (`quarantine()` requires `is_file()`), so cleanup would quarantine thousands of individual LevelDB files instead of the `Cache` directory as one unit. Directory-unit quarantine/restore is unimplemented. |
| 4 | WinSxS / Installer delegation | ⚠️ partial | Protection half is solid: `c:\windows\` prefix, WinSxS, DriverStore, `Windows\Installer`, servicing, System32, syswow64, boot → `WINDOWS_PROTECTED_PATH` → `NEVER_DELETE`. Gaps: drive letter **hardcoded to C:**; `is_system` / `is_windows_component` are never set in M0 (scanner hardcodes `is_system: false`); Dism/`pnputil` delegation is an M2 feature (expected). |
| 5 | Hash budget | ⚠️ partial | No partial-hash pipeline (M4, expected). But Deep mode's default `hash_max_size = 512 MB` means a deep scan can full-hash many hundreds of MB-class files — consider a lower default or per-group opt-in. |
| 6 | Vault location | ⚠️ partial | Good default: `%LOCALAPPDATA%\SmartCleaner\quarantine` (off the scanned drive), and the scanner excludes the vault from walks. Missing: **max vault size** (retention-only purge today), user-configurable location, and the CLI never opens a vault at all (quarantine ops aren't exposed yet — M2). |
| 7 | Rollback preserves ACLs | 🔲 missing | `QuarantineItem` has no ACL/owner/attributes fields; `restore()` is a plain move. M1 must snapshot + restore the NTFS security descriptor (review §7). |
| 8 | Trust boundary | ⚠️ partial | Architecture is right: Safety Engine is Rust, CLI is a thin wrapper, AI can only move Review→AutoQuarantine (conf ≥ 0.9, `QUARANTINE` only, never unblocks hard rules). Gaps: `SafetyPolicy.self_root` is `None` by default — self-protection is **dormant unless the caller wires it**; the M2 IPC design must state that every operation re-runs `enforce()` on fresh data (never trust a renderer-computed verdict). |

**Bottom line:** the *architecture* of the safety model is genuinely correct and unusually well done for M0. The findings below are about gaps in data plumbing and two behavioral decisions that contradict the spec's own examples.

---

## Findings (ranked)

### F1 — 🔴 High (behavior): "signed PE ⇒ NEVER_DELETE" is too broad

`safety-engine::enforce()` blocks **any** `is_signed && is_pe` file:

```rust
if record.is_signed && record.is_pe { blocked.push("SIGNED_CRITICAL_BINARY"); }
```

The spec (§6) says `SignedCriticalBinary => NEVER_DELETE` — *critical* binaries (OS components, drivers). As written, this rule makes the dashboard's own "Old Installers — 5.1 GB" bucket **permanently uncleanable**: installers are almost always signed PEs. This directly contradicts the risk engine's own test `old_signed_installer_is_review` (a 400-day-old signed VS installer is expected to be **Review**, but `enforce()` returns `NeverDelete`).

**Suggested fix:** restrict the hard rule to
`is_signed && is_pe && (is_windows_component || is_signed_critical)` — or simply `is_windows_component || is_driver` — and let signed non-system binaries fall through to band-based verdicts (old signed installer → Review → UserConfirm). Needs product-owner sign-off since it changes a safety semantic.

### F2 — 🔴 High (behavior): `.dat` ⇒ `ContentKind::Cache` auto-quietly classifies app data as junk

`file-models::infer_content_kind()` maps the extension `"dat"` to `Cache`. The risk engine then applies `CACHE_KIND` (−15) **even when the file is not in any cache directory**. Concrete consequence:

```
D:\Games\GTA\saves.dat, 2 years old:
50 (baseline) −15 (CACHE_KIND) −10 (AGE_30D) −5 (AGE_90D) = 20  ⇒  SAFE  ⇒  AutoQuarantine
```

A game save / app data file silently becomes one-click auto-clean. The spec is explicit that type must not rely on extension alone (§3A) — M1's signature checks will help, but the M0 heuristic itself is the source of the mis-score.

**Suggested fix:** remove `"dat"` from the Cache mapping (keep `"ldat"`), and/or require a cache-path context (`is_bcache` / dir-name heuristic) before applying `CACHE_KIND`.

### F3 — 🟠 Medium (robustness): `move_file` cross-device fallback is too broad

```rust
fn move_file(src, dest) {
    match fs::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::Other => { copy(src,dest)?; remove_file(src) }
        Err(e) => Err(e),
    }
}
```

`ErrorKind::Other` is not only EXDEV — on some platforms a sharing violation (file in use) also surfaces as `Other`. That would trigger **copy + delete-source**: if the copy succeeds but the source is locked, `remove_file` fails *after* a full copy already exists — orphaned duplicate in the vault, original untouched, no manifest entry (save never runs).

**Suggested fix:** match EXDEV specifically (`raw_os_error() == EXDEV` on unix; the Windows cross-volume code), and inside the fallback: copy → verify → delete source; if delete fails, **delete the copy and return the error** so the source remains the single source of truth.

### F4 — 🟠 Medium (robustness): crash window between move and manifest save

`Vault::quarantine()` order: hash → create item dir → **move** → push entry → save manifest. A crash *after the move, before save* leaves a file in `items/<uuid>/` with no manifest entry — un-restorable, and invisible to `restore` (no id).

**Suggested fix:** pre-create the manifest entry (with final `vault_path` and hash) and `save()` **before** the move; roll back the entry if the move fails. Optionally add an open-time recovery pass that lists `items/*` and reconciles orphans.

### F5 — 🟠 Medium (portability): OS drive hardcoded to `C:`

`known_paths::is_windows_protected_path()` checks `starts_with("c:\\windows\\")`. Windows is not guaranteed to live on C: (WDS, custom installs, OS drive letters). The scanner's platform layer already reads `WINDIR` — the model should too, e.g. via a `PlatformInfo { windir, os_drive }` filled by `platform::` and passed into path checks (file-models stays platform-free).

### F6 — 🟡 Low: two sources of truth for quarantine state

`vault.json` (vault crate) and the `quarantine_items` table (db crate) both track items. Declare **vault.json canonical** (it is what `restore` verifies against) and the DB table a read-side index; document the reconciliation rule.

### F7 — 🟡 Low (UI contract): band and verdict can disagree

`C:\Windows\Temp\x.tmp` scores **Safe** in the risk engine (TEMP_PATH −25) but is blocked by `WINDOWS_PROTECTED_PATH` in the safety engine. The UI must always render the **final verdict**, never the band alone, or users will see "Safe" on items that can never be touched. (No code fix in M0 — this is an M2 rendering contract; noting it here so it's not forgotten.)

### F8 — 🟡 Low (M1 trap): the scary signals are all dormant

In M0 nothing sets `in_use`, `is_pe`, `is_driver`, `is_signed`, `is_windows_component` (scanner hardcodes `is_system: false`). Every scary hard rule is currently inert — fine for cross-platform dev, but it means an **M1 Windows build that ships with signature parsing incomplete will silently downgrade risks**: an unsigned exe in Downloads with `is_pe=false` scores 50 (Review → UserConfirm) instead of 100 (Protected).

**Suggested fix (cheap, closes the gap early):** conservative extension-based fallback in the intelligence layer — if PE parsing is unavailable and the extension is `exe|dll|sys|drv`, assume `is_pe = true, is_signed = false`. Track a `signals_available` flag so the safety engine can log/escalate when running on Windows with M1 detection incomplete.

---

## What's done well (keep, don't touch)

- **Fail-closed defaults:** `RiskBand::default() = Review`; AI can only *promote* Review→AutoQuarantine, gated at confidence ≥ 0.9 and recommendation `QUARANTINE`, and can never unblock a hard rule.
- **Browser profile vs cache distinction** — cookies/passwords/history are explicitly *not* cache; tested.
- **Symlinks recorded, never followed** — no traversal loops; tested.
- **Vault hygiene:** self-ingestion guard (`UnderVaultRoot`), double-quarantine rejection, restore verifies hash → parent validity → conflict → free space → move → hash-in-place.
- **Explainability:** every `RiskFactor` has a stable rule id + human text; `SafetyDecision.blocked_rules` carries the exact rule ids for the audit log.
- **Privacy:** `sanitize_path()` masks the user segment before anything could leave the machine.
- **Test hygiene:** 50 tests green, tests use real temp trees with known hashes, CI on Linux + Windows.

## Recommended order before M1

1. **F1 + F2** (behavior) — needs product-owner decision on F1 semantics, then small code changes + test updates.
2. **F3 + F4** (robustness) — local, well-scoped, testable.
3. **F5 + F8** — land *inside* M1 (they're M1-shaped), with F8's extension fallback possibly backported to M0.
4. **F6 + F7** — document the contracts now, implement in M2.

---

## Fixes landed (2026-09-16)

Status after the fix pass (55/55 tests green):

- **F1 — FIXED.** Product decision (owner, 2026-09-16): `SIGNED_CRITICAL_BINARY` now fires only for
  `is_signed && is_pe && (is_windows_component || is_driver)`. Signed userland binaries (old
  installers, app executables) follow the risk band. New tests:
  `signed_old_installer_is_not_never_delete` (Review → UserConfirm), `signed_driver_is_still_never_delete`.
- **F2 — FIXED.** `"dat"` removed from the Cache extension mapping in `infer_content_kind`
  (cache classification now requires a path context). New assertion: `saves.dat` ⇒ `Unknown`.
- **F3 — FIXED.** `move_file` falls back to copy+delete **only** on an actual cross-device error
  (`is_cross_device`: `EXDEV` on unix; on Windows std's rename already handles cross-volume).
  Any other rename failure propagates untouched with the source intact; if the fallback copy
  succeeds but the source can't be removed, the copy is deleted too. New test:
  `is_cross_device_matches_exdev_only`.
- **F4 — FIXED.** `Vault::quarantine` now writes and saves the manifest entry **before** the move
  and rolls the entry back (plus item dir) if the move fails — a crash mid-move leaves a
  recoverable record, never an un-restorable orphan. New invariant test:
  `failed_quarantine_leaves_no_entry_and_source_intact`. Bonus: `Vault::recover_orphans()` finds
  item dirs with no manifest entry (pre-F4 crashes / corrupted manifests) for UI surfacing.
  New test: `recover_orphans_finds_unlisted_item_dirs`.
- **F8 — backported.** The scanner now assumes `is_pe = true` (unsigned) for
  `exe|dll|sys|drv` extensions until M1 parses PE headers + Authenticode — fails closed, so an
  unanalyzed binary can never score below "review". New assertion in `smart_scan_walks_and_reports`.

Remaining: **F5** (OS-drive hardcoding) and **F8** remainder (full PE/Authenticode parsing,
`signals_available` flag) → M1. **F6** (vault.json canonical over `quarantine_items`) and **F7**
(verdict, not band, in UI) → documented contracts for M2.
