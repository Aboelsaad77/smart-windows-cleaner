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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

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

    /// Move a file into the vault. Returns the created manifest entry.
    pub fn quarantine(&mut self, src: &Path, meta: QuarantineMeta) -> VaultResult<QuarantineItem> {
        if !src.is_file() {
            return Err(VaultError::SourceMissing(src.to_path_buf()));
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
        move_file(src, &dest)?;
        let item = QuarantineItem {
            id,
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
        self.manifest.items.push(item.clone());
        self.save()?;
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

/// `rename` when possible, else copy + delete (cross-device fallback).
fn move_file(src: &Path, dest: &Path) -> io::Result<()> {
    match fs::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::Other => {
            fs::copy(src, dest)?;
            fs::remove_file(src)
        }
        Err(e) => Err(e),
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
        // cleanup so the parent test doesn't leak
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
        // put a file back at the original path to retry
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
        // Age the item by 30 days via the on-disk manifest.
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
        // purging twice is a clean error
        let err = vault.purge(&item.id).unwrap_err();
        assert!(matches!(err, VaultError::NotQuarantined(_)));
    }
}
