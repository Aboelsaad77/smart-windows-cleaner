//! `sc-quarantine` — the safe-delete vault (spec §9, §10, §11).
//!
//! Nothing is ever deleted directly. Items are *moved* into the vault with a
//! manifest (hash, size, reason, risk score). They can be restored at any
//! time, and are only purged after a retention period or an explicit
//! force-purge.
//!
//! Vault layout:
//! ```text
//! <vault root>/
//!   vault.json          ← manifest (index of all items)
//!   items/<uuid>/       ← one directory per quarantined file
//!     <original name>
//! ```

use sc_file_models::{now_secs, RiskBand};
pub use sc_safety_engine::preflight::{
    self, PreflightError, PreflightOptions, PreflightOutcome, RequestedAction,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub use sc_safety_engine::preflight::{PreflightError as ExportedPreflightError, PreflightOptions as ExportedPreflightOptions, RequestedAction as ExportedRequestedAction};

#[derive(Debug)]
pub enum GuardedQuarantineError {
    Preflight(PreflightError),
    Vault(VaultError),
}

impl fmt::Display for GuardedQuarantineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preflight(e) => write!(f, "Pre-flight failed: {e}"),
            Self::Vault(e) => write!(f, "Vault failed: {e}"),
        }
    }
}

impl std::error::Error for GuardedQuarantineError {}

impl From<PreflightError> for GuardedQuarantineError {
    fn from(e: PreflightError) -> Self {
        GuardedQuarantineError::Preflight(e)
    }
}

impl From<VaultError> for GuardedQuarantineError {
    fn from(e: VaultError) -> Self {
        GuardedQuarantineError::Vault(e)
    }
}

pub const MANIFEST_FILE: &str = "vault.json";
pub const ITEMS_DIR: &str = "items";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    Quarantined,
    Restored,
    Purged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: PathBuf,
    pub vault_path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub quarantined_at: i64,
    pub reason: String,
    pub risk_score: u16,
    pub risk_band: RiskBand,
    pub status: ItemStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub vault_version: u32,
    pub items: Vec<QuarantineItem>,
}

/// Metadata the caller (cleanup layer) provides when quarantining.
#[derive(Debug, Clone)]
pub struct QuarantineMeta {
    pub original_path: PathBuf,
    pub reason: String,
    pub risk_score: u16,
    pub risk_band: RiskBand,
}

#[derive(Debug)]
pub enum VaultError {
    Io(io::Error),
    Json(String),
    SourceMissing(PathBuf),
    UnderVaultRoot(PathBuf),
    AlreadyQuarantined,
    ItemNotFound(String),
    NotQuarantined(String),
    DestinationExists(PathBuf),
    DestinationInvalid(PathBuf),
    HashMismatch { expected: String, actual: String },
    InsufficientSpace { needed: u64, available: u64 },
    PreflightBlocked(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Io(e) => write!(f, "io error: {e}"),
            VaultError::Json(e) => write!(f, "vault manifest error: {e}"),
            VaultError::SourceMissing(p) => write!(f, "source file missing: {}", p.display()),
            VaultError::UnderVaultRoot(p) => {
                write!(
                    f,
                    "refusing to quarantine a path inside the vault: {}",
                    p.display()
                )
            }
            VaultError::AlreadyQuarantined => write!(f, "file is already in the quarantine vault"),
            VaultError::ItemNotFound(id) => write!(f, "quarantine item not found: {id}"),
            VaultError::NotQuarantined(id) => write!(f, "item is no longer in the vault: {id}"),
            VaultError::DestinationExists(p) => {
                write!(f, "destination already exists: {}", p.display())
            }
            VaultError::DestinationInvalid(p) => {
                write!(f, "original location is no longer valid: {}", p.display())
            }
            VaultError::HashMismatch { expected, actual } => {
                write!(f, "hash mismatch: expected {expected}, got {actual}")
            }
            VaultError::InsufficientSpace { needed, available } => {
                write!(f, "not enough space: need {needed}, have {available}")
            }
            VaultError::PreflightBlocked(reason) => {
                write!(f, "preflight blocked quarantine: {reason}")
            }
        }
    }
}

impl std::error::Error for VaultError {}

impl From<io::Error> for VaultError {
    fn from(e: io::Error) -> Self {
        VaultError::Io(e)
    }
}

pub type VaultResult<T> = Result<T, VaultError>;

/// Resolves the secure vault root directory depending on process elevation and user context.
///
/// Multi-Tier Security & Isolation Model:
/// - Standard Non-Elevated User Mode: Defaults to `%LOCALAPPDATA%\SmartCleaner\Vault`.
///   Inherits the current user's Windows profile NTFS ACLs (only the user and Administrators have access).
///   Guarantees standard users can inspect, quarantine, and restore their own files without UAC elevation.
///   Enforces multi-user isolation: User A cannot see or restore User B's files.
/// - Elevated Administrator Mode: Defaults to `%PROGRAMDATA%\SmartCleaner\Vault`.
///   Protected with explicit DACL (`SYSTEM` + `Administrators` only).
///   Used when cleaning machine-wide system directories.
pub fn resolve_vault_root(is_elevated: bool, custom_root: Option<PathBuf>) -> PathBuf {
    if let Some(custom) = custom_root {
        return custom;
    }

    #[cfg(windows)]
    {
        if is_elevated {
            if let Some(progdata) = std::env::var_os("PROGRAMDATA") {
                return PathBuf::from(progdata).join("SmartCleaner").join("Vault");
            }
            PathBuf::from("C:\\ProgramData\\SmartCleaner\\Vault")
        } else {
            if let Some(localappdata) = std::env::var_os("LOCALAPPDATA") {
                return PathBuf::from(localappdata).join("SmartCleaner").join("Vault");
            }
            if let Some(userprofile) = std::env::var_os("USERPROFILE") {
                return PathBuf::from(userprofile).join("AppData").join("Local").join("SmartCleaner").join("Vault");
            }
            PathBuf::from("C:\\Users\\Default\\AppData\\Local\\SmartCleaner\\Vault")
        }
    }

    #[cfg(not(windows))]
    {
        if is_elevated {
            PathBuf::from("/var/lib/smart-cleaner/vault")
        } else {
            if let Some(home) = std::env::var_os("HOME") {
                return PathBuf::from(home).join(".local/share/smart-cleaner/vault");
            }
            PathBuf::from("/tmp/smart-cleaner-vault")
        }
    }
}

pub struct Vault {
    root: PathBuf,
    manifest: Manifest,
}

impl Vault {
    /// Open (or initialize) the vault at `root`.
    pub fn open(root: PathBuf) -> VaultResult<Vault> {
        fs::create_dir_all(root.join(ITEMS_DIR))?;
        let mp = root.join(MANIFEST_FILE);
        let manifest = if mp.exists() {
            let raw = fs::read_to_string(&mp)?;
            serde_json::from_str(&raw).map_err(|e| VaultError::Json(e.to_string()))?
        } else {
            Manifest {
                vault_version: 1,
                items: vec![],
            }
        };
        Ok(Vault { root, manifest })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn items(&self) -> &[QuarantineItem] {
        &self.manifest.items
    }

    pub fn find(&self, id: &str) -> Option<&QuarantineItem> {
        self.manifest.items.iter().find(|i| i.id == id)
    }

    /// Move a file into the vault.
    ///
    /// Even direct/lower-level quarantine calls MUST pass through the pre-flight gate.
    /// Lower-level APIs cannot bypass the safety/preflight path.
    pub fn quarantine(&mut self, src: &Path, meta: QuarantineMeta) -> VaultResult<QuarantineItem> {
        let policy = sc_safety_engine::SafetyPolicy::default();
        let action = if meta.risk_band <= RiskBand::Safe {
            RequestedAction::AutoQuarantine
        } else {
            RequestedAction::UserConfirmed
        };
        let opts = PreflightOptions::new(&policy, action).with_vault_root(&self.root);
        if let Err(e) = preflight::revalidate(src, &opts) {
            return match e {
                PreflightError::SourceMissing(p) => Err(VaultError::SourceMissing(p)),
                PreflightError::UnderVaultRoot(p) => Err(VaultError::UnderVaultRoot(p)),
                other => Err(VaultError::PreflightBlocked(other.to_string())),
            };
        }
        self.quarantine_raw(src, meta)
    }

    /// Move a file into the vault after executing the mandatory pre-flight gate.
    ///
    /// Re-reads metadata, rejects symlinks/reparse points/directories, probes live
    /// process locks (`is_in_use`), checks for state drift against scan-time snapshot,
    /// and re-runs the risk and safety policy engine immediately before moving the file.
    pub fn quarantine_guarded(
        &mut self,
        src: &Path,
        options: &PreflightOptions,
    ) -> Result<(QuarantineItem, PreflightOutcome), GuardedQuarantineError> {
        let mut opts = options.clone();
        opts.vault_root = Some(&self.root);
        let outcome = preflight::revalidate(src, &opts)?;
        let meta = QuarantineMeta {
            original_path: src.to_path_buf(),
            reason: outcome.decision.notes.join("; "),
            risk_score: outcome.assessment.score,
            risk_band: outcome.assessment.band,
        };
        let item = self.quarantine_raw(src, meta)?;
        Ok((item, outcome))
    }

    /// Internal vault ingestion logic. Private to the vault crate so callers
    /// can never bypass the preflight safety gate.
    fn quarantine_raw(&mut self, src: &Path, meta: QuarantineMeta) -> VaultResult<QuarantineItem> {
        if !src.is_file() {
            return Err(VaultError::SourceMissing(src.to_path_buf()));
        }
        if let Ok(f) = fs::File::open(src) {
            use fs2::FileExt;
            if f.try_lock_exclusive().is_err() {
                return Err(VaultError::PreflightBlocked("file is currently locked or in use".into()));
            }
        }
        // The vault can never swallow itself.
        if self.under_vault(src) {
            return Err(VaultError::UnderVaultRoot(src.to_path_buf()));
        }
        if self
            .manifest
            .items
            .iter()
            .any(|i| i.status == ItemStatus::Quarantined && i.original_path == meta.original_path)
        {
            return Err(VaultError::AlreadyQuarantined);
        }
        let size = fs::metadata(src)?.len();
        let sha = hash_file(src)?;
        let id = uuid::Uuid::new_v4().to_string();
        let file_name = src
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_else(|| std::ffi::OsString::from("item"));
        let item_dir = self.root.join(ITEMS_DIR).join(&id);
        fs::create_dir_all(&item_dir)?;
        let dest = item_dir.join(file_name);
        let item = QuarantineItem {
            id: id.clone(),
            original_path: meta.original_path.clone(),
            vault_path: dest.clone(),
            sha256: sha,
            size,
            quarantined_at: now_secs(),
            reason: meta.reason.clone(),
            risk_score: meta.risk_score,
            risk_band: meta.risk_band,
            status: ItemStatus::Quarantined,
        };
        // Pre-save: the record must exist before the file moves.
        self.manifest.items.push(item.clone());
        self.save()?;
        if let Err(e) = move_file(src, &dest) {
            // Roll back the manifest entry so state stays consistent.
            if let Some(pos) = self.manifest.items.iter().position(|i| i.id == id) {
                self.manifest.items.remove(pos);
            }
            let _ = fs::remove_dir_all(&item_dir);
            let _ = self.save();
            return Err(VaultError::Io(e));
        }
        Ok(item)
    }

    /// Restore an item to its original location (spec §10, Rollback).
    ///
    /// Checks, in order: item state → integrity hash → destination validity →
    /// destination conflict → free space → move → verify hash in place.
    pub fn restore(&mut self, id: &str) -> VaultResult<QuarantineItem> {
        let idx = self
            .manifest
            .items
            .iter()
            .position(|i| i.id == id)
            .ok_or_else(|| VaultError::ItemNotFound(id.to_string()))?;
        let item = self.manifest.items[idx].clone();
        if item.status != ItemStatus::Quarantined {
            return Err(VaultError::NotQuarantined(id.to_string()));
        }
        if !item.vault_path.is_file() {
            return Err(VaultError::SourceMissing(item.vault_path.clone()));
        }
        // 1) integrity
        let actual = hash_file(&item.vault_path)?;
        if actual != item.sha256 {
            return Err(VaultError::HashMismatch {
                expected: item.sha256.clone(),
                actual,
            });
        }
        // 2) destination validity
        let dest_parent = item.original_path.parent();
        if !dest_parent.map(|p| p.is_dir()).unwrap_or(false) {
            return Err(VaultError::DestinationInvalid(item.original_path.clone()));
        }
        // 3) destination conflict
        if item.original_path.exists() {
            return Err(VaultError::DestinationExists(item.original_path.clone()));
        }
        // 4) free space
        if let Ok(avail) = fs2::available_space(dest_parent.unwrap_or_else(|| Path::new("/"))) {
            if avail < item.size {
                return Err(VaultError::InsufficientSpace {
                    needed: item.size,
                    available: avail,
                });
            }
        }
        // 5) move back
        move_file(&item.vault_path, &item.original_path)?;
        // 6) verify in place
        let final_hash = hash_file(&item.original_path)?;
        if final_hash != item.sha256 {
            return Err(VaultError::HashMismatch {
                expected: item.sha256.clone(),
                actual: final_hash,
            });
        }
        self.manifest.items[idx].status = ItemStatus::Restored;
        self.save()?;
        Ok(self.manifest.items[idx].clone())
    }

    /// Permanently delete items older than `retention_days` (spec §11).
    /// Returns the ids of the purged items.
    pub fn purge_expired(&mut self, retention_days: u32) -> VaultResult<Vec<String>> {
        let now = now_secs();
        let cutoff = now.saturating_sub(retention_days as i64 * 86_400);
        let mut purged = Vec::new();
        for item in self.manifest.items.iter_mut() {
            if item.status == ItemStatus::Quarantined && item.quarantined_at < cutoff {
                if let Some(dir) = item.vault_path.parent() {
                    let _ = fs::remove_dir_all(dir);
                }
                item.status = ItemStatus::Purged;
                purged.push(item.id.clone());
            }
        }
        if !purged.is_empty() {
            self.save()?;
        }
        Ok(purged)
    }

    /// Force-purge a single item ("Delete permanently now" — spec §11).
    pub fn purge(&mut self, id: &str) -> VaultResult<()> {
        let idx = self
            .manifest
            .items
            .iter()
            .position(|i| i.id == id)
            .ok_or_else(|| VaultError::ItemNotFound(id.to_string()))?;
        if self.manifest.items[idx].status != ItemStatus::Quarantined {
            return Err(VaultError::NotQuarantined(id.to_string()));
        }
        if let Some(dir) = self.manifest.items[idx].vault_path.parent() {
            let _ = fs::remove_dir_all(dir);
        }
        self.manifest.items[idx].status = ItemStatus::Purged;
        self.save()
    }

    /// Find vault item directories that have no manifest entry — orphans left
    /// by a crash in the move window before audit F4's pre-save, or by a
    /// corrupted manifest. Their original path is unknown, so they cannot be
    /// restored automatically; the UI should surface them for manual review.
    pub fn recover_orphans(&self) -> VaultResult<Vec<PathBuf>> {
        let mut orphans = Vec::new();
        let items_root = self.root.join(ITEMS_DIR);
        let known: std::collections::HashSet<&str> = self
            .manifest
            .items
            .iter()
            .map(|i| i.id.as_str())
            .collect();
        let rd = match fs::read_dir(&items_root) {
            Ok(rd) => rd,
            Err(_) => return Ok(orphans),
        };
        for e in rd {
            let e = match e {
                Ok(e) => e,
                Err(_) => continue,
            };
            let file_name = e.file_name();
            let name = file_name.to_string_lossy();
            if !known.contains(name.as_ref()) {
                orphans.push(e.path());
            }
        }
        Ok(orphans)
    }

    pub fn save(&self) -> VaultResult<()> {
        let raw = serde_json::to_string_pretty(&self.manifest)
            .map_err(|e| VaultError::Json(e.to_string()))?;
        fs::write(self.root.join(MANIFEST_FILE), raw)?;
        Ok(())
    }

    fn under_vault(&self, p: &Path) -> bool {
        let abs = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
        let root = self
            .root
            .canonicalize()
            .unwrap_or_else(|_| self.root.clone());
        abs.starts_with(root)
    }
}

/// SHA-256 of a file, streamed in 64 KiB chunks.
pub fn hash_file(path: &Path) -> VaultResult<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// `rename` when possible; on a *cross-device* rename (EXDEV) fall back to
/// copy + delete. Any other rename failure (sharing violation, permissions,
/// ...) is propagated untouched — the source must stay intact.
fn move_file(src: &Path, dest: &Path) -> io::Result<()> {
    match fs::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(e) if is_cross_device(&e) => {
            fs::copy(src, dest)?;
            if let Err(err) = fs::remove_file(src) {
                let _ = fs::remove_file(dest);
                return Err(io::Error::new(
                    err.kind(),
                    format!("source could not be removed after cross-device copy: {err}"),
                ));
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn is_cross_device(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(libc::EXDEV)
    }
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sc-quarantine-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn setup(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let root = tmp_root(tag);
        let work = root.join("work/app/cache");
        fs::create_dir_all(&work).unwrap();
        let src = work.join("blob.tmp");
        fs::write(&src, b"hello vault").unwrap();
        let vault_dir = root.join("vault");
        (root, src, vault_dir)
    }

    fn meta(src: &Path) -> QuarantineMeta {
        QuarantineMeta {
            original_path: src.to_path_buf(),
            reason: "application cache".into(),
            risk_score: 8,
            risk_band: RiskBand::VerySafe,
        }
    }

    #[test]
    fn quarantine_restore_roundtrip() {
        let (_root, src, vault_dir) = setup("roundtrip");
        let mut vault = Vault::open(vault_dir).unwrap();
        let item = vault.quarantine(&src, meta(&src)).unwrap();
        assert!(!src.exists());
        assert!(item.vault_path.is_file());
        assert_eq!(item.size, 11);
        assert_eq!(item.status, ItemStatus::Quarantined);
        assert!(!item.sha256.is_empty());

        let restored = vault.restore(&item.id).unwrap();
        assert!(src.is_file());
        assert_eq!(fs::read(&src).unwrap(), b"hello vault");
        assert_eq!(restored.status, ItemStatus::Restored);
    }

    #[test]
    fn restore_conflict_is_rejected() {
        let (_root, src, vault_dir) = setup("conflict");
        let mut vault = Vault::open(vault_dir).unwrap();
        let item = vault.quarantine(&src, meta(&src)).unwrap();
        fs::write(&src, b"new data").unwrap();
        let err = vault.restore(&item.id).unwrap_err();
        assert!(matches!(err, VaultError::DestinationExists(_)));
    }

    #[test]
    fn restore_missing_parent_is_rejected() {
        let (root, src, vault_dir) = setup("missing-parent");
        let mut vault = Vault::open(vault_dir).unwrap();
        let item = vault.quarantine(&src, meta(&src)).unwrap();
        let parent = src.parent().unwrap().to_path_buf();
        fs::remove_dir_all(parent).unwrap();
        let err = vault.restore(&item.id).unwrap_err();
        assert!(matches!(err, VaultError::DestinationInvalid(_)));
        assert!(root.exists());
    }

    #[test]
    fn tampered_vault_file_is_rejected() {
        let (_root, _src, vault_dir) = setup("tampered");
        let mut vault = Vault::open(vault_dir).unwrap();
        let item = vault.quarantine(&_src, meta(&_src)).unwrap();
        fs::write(&item.vault_path, b"tampered!!").unwrap();
        let err = vault.restore(&item.id).unwrap_err();
        assert!(matches!(err, VaultError::HashMismatch { .. }));
    }

    #[test]
    fn double_quarantine_is_rejected() {
        let (_root, src, vault_dir) = setup("double");
        let mut vault = Vault::open(vault_dir).unwrap();
        vault.quarantine(&src, meta(&src)).unwrap();
        fs::create_dir_all(src.parent().unwrap()).unwrap();
        fs::write(&src, b"again").unwrap();
        let err = vault.quarantine(&src, meta(&src)).unwrap_err();
        assert!(matches!(err, VaultError::AlreadyQuarantined));
    }

    #[test]
    fn vault_never_swallows_itself() {
        let (_root, _src, vault_dir) = setup("self");
        let mut vault = Vault::open(vault_dir.clone()).unwrap();
        let inner = vault_dir.join("inner.txt");
        fs::write(&inner, b"inside the vault").unwrap();
        let err = vault
            .quarantine(
                &inner,
                QuarantineMeta {
                    original_path: inner.clone(),
                    reason: "x".into(),
                    risk_score: 1,
                    risk_band: RiskBand::VerySafe,
                },
            )
            .unwrap_err();
        assert!(matches!(err, VaultError::UnderVaultRoot(_)));
    }

    #[test]
    fn purge_expired_after_retention() {
        let (_root, src, vault_dir) = setup("expiry");
        let mut vault = Vault::open(vault_dir.clone()).unwrap();
        let item = vault.quarantine(&src, meta(&src)).unwrap();
        let manifest_path = vault_dir.join(MANIFEST_FILE);
        let raw = fs::read_to_string(&manifest_path).unwrap();
        let mut m: serde_json::Value = serde_json::from_str(&raw).unwrap();
        for it in m["items"].as_array_mut().unwrap() {
            it["quarantined_at"] =
                serde_json::json!(it["quarantined_at"].as_i64().unwrap() - 30 * 86_400);
        }
        fs::write(&manifest_path, serde_json::to_string(&m).unwrap()).unwrap();

        let mut vault = Vault::open(vault_dir).unwrap();
        let purged = vault.purge_expired(7).unwrap();
        assert_eq!(purged, vec![item.id.clone()]);
        assert!(!item.vault_path.exists());
        assert_eq!(vault.find(&item.id).unwrap().status, ItemStatus::Purged);
    }

    #[test]
    fn force_purge_single_item() {
        let (_root, src, vault_dir) = setup("force");
        let mut vault = Vault::open(vault_dir).unwrap();
        let item = vault.quarantine(&src, meta(&src)).unwrap();
        vault.purge(&item.id).unwrap();
        assert!(!item.vault_path.exists());
        assert_eq!(vault.find(&item.id).unwrap().status, ItemStatus::Purged);
        let err = vault.purge(&item.id).unwrap_err();
        assert!(matches!(err, VaultError::NotQuarantined(_)));
    }

    #[cfg(unix)]
    #[test]
    fn failed_quarantine_leaves_no_entry_and_source_intact() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root, permission bits do not apply");
            return;
        }
        let (_root, src, vault_dir) = setup("rollback");
        let mut vault = Vault::open(vault_dir.clone()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let items = vault_dir.join(ITEMS_DIR);
        fs::set_permissions(&items, fs::Permissions::from_mode(0o555)).unwrap();
        let err = vault.quarantine(&src, meta(&src)).unwrap_err();
        fs::set_permissions(&items, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(err, VaultError::Io(_)));
        assert!(vault.items().is_empty(), "no manifest entry may survive a failure");
        assert!(src.is_file(), "the source must stay intact");
        let on_disk = Vault::open(vault_dir).unwrap();
        assert!(on_disk.items().is_empty());
    }

    #[test]
    fn recover_orphans_finds_unlisted_item_dirs() {
        let (_root, src, vault_dir) = setup("orphans");
        let mut vault = Vault::open(vault_dir.clone()).unwrap();
        assert!(vault.recover_orphans().unwrap().is_empty());
        let orphan = vault_dir.join(ITEMS_DIR).join("deadbeef-dead-dead-dead-deadbeefdeadbe");
        fs::create_dir_all(&orphan).unwrap();
        fs::write(orphan.join("leftover.tmp"), b"orphan").unwrap();
        let item = vault.quarantine(&src, meta(&src)).unwrap();
        let orphans = vault.recover_orphans().unwrap();
        assert_eq!(orphans, vec![orphan.clone()]);
        assert_ne!(item.vault_path.parent().unwrap(), orphan.as_path());
    }

    #[cfg(unix)]
    #[test]
    fn is_cross_device_matches_exdev_only() {
        use io::Error as IoError;
        assert!(is_cross_device(&IoError::from_raw_os_error(libc::EXDEV)));
        assert!(!is_cross_device(&IoError::from_raw_os_error(libc::EACCES)));
        assert!(!is_cross_device(&IoError::from_raw_os_error(libc::ENOENT)));
        assert!(!is_cross_device(&IoError::other("no os code")));
    }

    #[test]
    fn quarantine_guarded_success_roundtrip() {
        let (_root, src, vault_dir) = setup("guarded_success");
        let mut vault = Vault::open(vault_dir).unwrap();
        let policy = sc_safety_engine::SafetyPolicy::default();
        let opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine);
        let (item, outcome) = vault.quarantine_guarded(&src, &opts).unwrap();
        assert_eq!(item.status, ItemStatus::Quarantined);
        assert!(item.vault_path.is_file());
        assert!(!src.exists());
        assert_eq!(outcome.decision.verdict, sc_safety_engine::SafetyVerdict::AutoQuarantine);
    }

    #[test]
    fn quarantine_guarded_rejects_missing_file() {
        let (_root, _src, vault_dir) = setup("guarded_missing");
        let mut vault = Vault::open(vault_dir).unwrap();
        let policy = sc_safety_engine::SafetyPolicy::default();
        let opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine);
        let missing = _root.join("does_not_exist.tmp");
        let err = vault.quarantine_guarded(&missing, &opts).unwrap_err();
        match err {
            GuardedQuarantineError::Preflight(PreflightError::SourceMissing(_)) => {}
            other => panic!("expected SourceMissing, got {other:?}"),
        }
    }

    #[test]
    fn quarantine_guarded_rejects_state_drift() {
        let (_root, src, vault_dir) = setup("guarded_drift");
        let mut vault = Vault::open(vault_dir).unwrap();
        let policy = sc_safety_engine::SafetyPolicy::default();
        let expected = sc_file_models::FileRecord::new(&src, 9999, 100);
        let opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine)
            .with_expected(&expected);
        let err = vault.quarantine_guarded(&src, &opts).unwrap_err();
        match err {
            GuardedQuarantineError::Preflight(PreflightError::StateDrift { .. }) => {}
            other => panic!("expected StateDrift, got {other:?}"),
        }
    }

    #[test]
    fn quarantine_guarded_rejects_locked_file() {
        use fs2::FileExt;
        let (_root, src, vault_dir) = setup("guarded_locked");
        let mut vault = Vault::open(vault_dir).unwrap();
        let lock_file = fs::File::open(&src).unwrap();
        let _ = lock_file.lock_exclusive();
        let policy = sc_safety_engine::SafetyPolicy::default();
        let opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine);
        let err = vault.quarantine_guarded(&src, &opts).unwrap_err();
        match err {
            GuardedQuarantineError::Preflight(PreflightError::FileInUse(_)) => {}
            other => panic!("expected FileInUse, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_guarded_rejects_symlink() {
        let (root, src, vault_dir) = setup("guarded_symlink");
        let mut vault = Vault::open(vault_dir).unwrap();
        let link = root.join("link_to_src");
        std::os::unix::fs::symlink(&src, &link).unwrap();
        let policy = sc_safety_engine::SafetyPolicy::default();
        let opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine);
        let err = vault.quarantine_guarded(&link, &opts).unwrap_err();
        match err {
            GuardedQuarantineError::Preflight(PreflightError::SymlinkBlocked(_)) => {}
            other => panic!("expected SymlinkBlocked, got {other:?}"),
        }
    }

    #[test]
    fn lower_level_quarantine_cannot_bypass_preflight_gate() {
        let (_root, src, vault_dir) = setup("lower-level-bypass");
        let mut vault = Vault::open(vault_dir).unwrap();

        // Lock the file
        let file = fs::OpenOptions::new().write(true).open(&src).unwrap();
        use fs2::FileExt;
        file.lock_exclusive().unwrap();

        // Attempting to call lower-level vault.quarantine directly must still fail!
        let err = vault.quarantine(&src, meta(&src)).unwrap_err();
        assert!(matches!(err, VaultError::PreflightBlocked(_)));
        assert!(src.is_file(), "file must remain untouched");
        assert!(vault.items().is_empty(), "vault must have no entries");
        drop(file);
    }

    #[test]
    fn resolve_vault_root_respects_custom_and_elevation() {
        let custom = PathBuf::from("/custom/vault/path");
        assert_eq!(resolve_vault_root(false, Some(custom.clone())), custom);
        assert_eq!(resolve_vault_root(true, Some(custom.clone())), custom);

        // When custom is None, resolves differently for elevated vs non-elevated
        let user_vault = resolve_vault_root(false, None);
        let admin_vault = resolve_vault_root(true, None);
        assert_ne!(user_vault, admin_vault);
    }
}
