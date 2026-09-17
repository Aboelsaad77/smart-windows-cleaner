//! Pre-flight revalidation gate (spec §6, §23; Technical Review §8).
//!
//! Substantial time may pass between initial filesystem discovery (scan) and
//! quarantine execution. Files can be modified, locked by running processes,
//! replaced with symlinks/reparse points, or moved into protected directories.
//!
//! This module implements the mandatory final pre-flight verification gate:
//! ```text
//! Scan ──▶ Risk ──▶ Safety ──▶ ... time passes ... ──▶ PRE-FLIGHT ──▶ Quarantine
//!                                                         │
//!                                                         ├─ Fresh metadata
//!                                                         ├─ Symlink / reparse check
//!                                                         ├─ In-use / lock probe
//!                                                         ├─ State drift verification
//!                                                         ├─ Path & vault bounds
//!                                                         └─ Re-run enforce()
//! ```

use crate::{enforce, SafetyDecision, SafetyPolicy, SafetyVerdict};
use sc_file_models::{
    infer_content_kind, now_secs, pe, AiSignal, FileClass, FileRecord,
};
use sc_risk_engine::{assess, AssessContext, RiskAssessment};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Requested mode of cleanup for this item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedAction {
    /// Automated cleanup (e.g. "Clean all safe items").
    /// Requires that the fresh verdict is `AutoQuarantine`. Any demotion to
    /// `UserConfirm` or state drift triggers immediate abort.
    AutoQuarantine,
    /// Explicit user-confirmed cleanup of this specific item.
    /// Accepts both `AutoQuarantine` and `UserConfirm`.
    UserConfirmed,
}

/// Options and context provided to the pre-flight gate.
#[derive(Debug, Clone)]
pub struct PreflightOptions<'a> {
    pub policy: &'a SafetyPolicy,
    pub action: RequestedAction,
    /// Snapshot from scan time (if available), used for drift detection.
    pub expected: Option<&'a FileRecord>,
    pub ai: Option<&'a AiSignal>,
    pub now: Option<i64>,
    pub vault_root: Option<&'a Path>,
    /// When true, rejects any modification drift (size/mtime) even under
    /// `UserConfirmed`. Defaults to `false` for UserConfirmed and `true` for
    /// AutoQuarantine.
    pub strict_drift: bool,
}

impl<'a> PreflightOptions<'a> {
    pub fn new(policy: &'a SafetyPolicy, action: RequestedAction) -> Self {
        let strict_drift = action == RequestedAction::AutoQuarantine;
        Self {
            policy,
            action,
            expected: None,
            ai: None,
            now: None,
            vault_root: None,
            strict_drift,
        }
    }

    pub fn with_expected(mut self, expected: &'a FileRecord) -> Self {
        self.expected = Some(expected);
        self
    }

    pub fn with_ai(mut self, ai: &'a AiSignal) -> Self {
        self.ai = Some(ai);
        self
    }

    pub fn with_now(mut self, now: i64) -> Self {
        self.now = Some(now);
        self
    }

    pub fn with_vault_root(mut self, root: &'a Path) -> Self {
        self.vault_root = Some(root);
        self
    }

    pub fn with_strict_drift(mut self, strict: bool) -> Self {
        self.strict_drift = strict;
        self
    }
}

/// Result of a successful pre-flight revalidation.
#[derive(Debug, Clone, PartialEq)]
pub struct PreflightOutcome {
    pub record: FileRecord,
    pub assessment: RiskAssessment,
    pub decision: SafetyDecision,
    pub had_drift: bool,
    pub drift_notes: Vec<String>,
}

/// Errors surfaced by the pre-flight gate.
#[derive(Debug)]
pub enum PreflightError {
    SourceMissing(PathBuf),
    SymlinkBlocked(PathBuf),
    DirectoryBlocked(PathBuf),
    OtherSpecialFile(PathBuf),
    UnderVaultRoot(PathBuf),
    FileInUse(PathBuf),
    StateDrift {
        path: PathBuf,
        reason: String,
    },
    Blocked {
        decision: SafetyDecision,
    },
    ConfirmationRequired {
        decision: SafetyDecision,
        reason: String,
    },
    Io(io::Error),
}

impl fmt::Display for PreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PreflightError::SourceMissing(p) => {
                write!(f, "source file no longer exists: {}", p.display())
            }
            PreflightError::SymlinkBlocked(p) => {
                write!(
                    f,
                    "source is a symlink or reparse point (quarantine refused): {}",
                    p.display()
                )
            }
            PreflightError::DirectoryBlocked(p) => {
                write!(
                    f,
                    "source is a directory (file vault requires regular file): {}",
                    p.display()
                )
            }
            PreflightError::OtherSpecialFile(p) => {
                write!(f, "source is not a regular file: {}", p.display())
            }
            PreflightError::UnderVaultRoot(p) => {
                write!(
                    f,
                    "refusing to quarantine a path inside the vault: {}",
                    p.display()
                )
            }
            PreflightError::FileInUse(p) => {
                write!(
                    f,
                    "file is currently locked or in use by another process: {}",
                    p.display()
                )
            }
            PreflightError::StateDrift { path, reason } => {
                write!(
                    f,
                    "state drift detected on {}: {}",
                    path.display(),
                    reason
                )
            }
            PreflightError::Blocked { decision } => {
                write!(
                    f,
                    "blocked by safety engine: {}",
                    decision.notes.join("; ")
                )
            }
            PreflightError::ConfirmationRequired { decision, reason } => {
                write!(
                    f,
                    "user confirmation required ({}): {}",
                    decision.verdict, reason
                )
            }
            PreflightError::Io(e) => write!(f, "i/o error during pre-flight check: {e}"),
        }
    }
}

impl std::error::Error for PreflightError {}

impl From<io::Error> for PreflightError {
    fn from(e: io::Error) -> Self {
        PreflightError::Io(e)
    }
}

/// Probes whether a file is currently locked or held open by another process.
///
/// Windows: uses the rename probe (ground truth on NTFS for handles lacking
/// `FILE_SHARE_DELETE`).
/// Cross-platform / Unix: tests acquiring a non-blocking exclusive file lock via fs2.
pub fn is_in_use(path: &Path) -> bool {
    #[cfg(windows)]
    {
        // Try exclusive lock probe first
        use fs2::FileExt;
        if let Ok(file) = std::fs::OpenOptions::new().read(true).open(path) {
            if file.try_lock_exclusive().is_err() {
                return true;
            }
            let _ = file.unlock();
        }
        // Then rename probe
        let stem = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file");
        let probe = path.with_file_name(format!("{stem}.sc-lock-probe-{}", std::process::id()));
        match std::fs::rename(path, &probe) {
            Err(_) => true,
            Ok(()) => {
                for _ in 0..10 {
                    if std::fs::rename(&probe, path).is_ok() {
                        return false;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                true
            }
        }
    }
    #[cfg(not(windows))]
    {
        use fs2::FileExt;
        if let Ok(file) = std::fs::OpenOptions::new().read(true).write(true).open(path) {
            if file.try_lock_exclusive().is_err() {
                return true;
            }
            let _ = file.unlock();
            false
        } else if let Ok(file) = std::fs::OpenOptions::new().read(true).open(path) {
            if file.try_lock_exclusive().is_err() {
                return true;
            }
            let _ = file.unlock();
            false
        } else {
            false
        }
    }
}

/// Execute the explicit pre-flight revalidation immediately before quarantine.
pub fn revalidate(
    path: &Path,
    options: &PreflightOptions,
) -> Result<PreflightOutcome, PreflightError> {
    // 1. Vault root self-ingestion check
    if let Some(vr) = options.vault_root {
        if crate::under(path, vr) {
            return Err(PreflightError::UnderVaultRoot(path.to_path_buf()));
        }
    }

    // 2. Query fresh metadata (symlink-aware)
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(PreflightError::SourceMissing(path.to_path_buf()));
        }
        Err(e) => return Err(PreflightError::Io(e)),
    };

    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(PreflightError::SymlinkBlocked(path.to_path_buf()));
    }
    if ft.is_dir() {
        return Err(PreflightError::DirectoryBlocked(path.to_path_buf()));
    }
    if !ft.is_file() {
        return Err(PreflightError::OtherSpecialFile(path.to_path_buf()));
    }

    // 3. Live lock / in-use probe
    let locked = is_in_use(path);
    if locked {
        return Err(PreflightError::FileInUse(path.to_path_buf()));
    }

    // 4. Construct fresh FileRecord
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .filter(|e| !e.is_empty());

    let is_hidden = path
        .file_name()
        .map(|n| n.to_string_lossy().starts_with('.'))
        .unwrap_or(false);

    let is_pe_ext = matches!(
        ext.as_deref(),
        Some("exe") | Some("dll") | Some("sys") | Some("drv")
    );
    let is_driver = matches!(ext.as_deref(), Some("sys") | Some("drv"));

    let mut is_pe = is_pe_ext;
    if is_pe_ext {
        if let Ok(mut f) = fs::File::open(path) {
            let mut head = [0u8; 4096];
            if let Ok(n) = f.read(&mut head) {
                is_pe = pe::inspect(&head[..n]).is_pe;
            }
        }
    }

    let modified = to_epoch(meta.modified());
    let created = to_opt_epoch(meta.created());
    let accessed = to_opt_epoch(meta.accessed());
    let size = meta.len();
    let content_kind = infer_content_kind(path);

    // Carry over verified metadata if scan-time snapshot exists and PE status didn't mutate
    let mut is_signed = false;
    let mut is_windows_component = false;
    let mut is_system = false;
    let mut owner_app = None;
    if let Some(exp) = options.expected {
        if exp.is_pe == is_pe {
            is_signed = exp.is_signed;
            is_windows_component = exp.is_windows_component;
            is_system = exp.is_system;
            owner_app = exp.owner_app.clone();
        }
    }

    let fresh = FileRecord {
        path: path.to_path_buf(),
        size,
        file_class: FileClass::RegularFile,
        modified,
        created,
        accessed,
        extension: ext,
        content_kind,
        is_hidden,
        is_system,
        is_pe,
        is_signed,
        is_driver,
        is_windows_component,
        in_use: false,
        owner_app,
        ..Default::default()
    };

    // 5. State drift detection
    let mut drift_notes = Vec::new();
    if let Some(exp) = options.expected {
        if exp.size != fresh.size {
            drift_notes.push(format!("size changed from {} to {}", exp.size, fresh.size));
        }
        if exp.modified != fresh.modified {
            drift_notes.push(format!(
                "modified timestamp changed from {} to {}",
                exp.modified, fresh.modified
            ));
        }
        if exp.is_pe != fresh.is_pe {
            drift_notes.push(format!(
                "executable structure changed (is_pe: {} -> {})",
                exp.is_pe, fresh.is_pe
            ));
        }
        if exp.content_kind != fresh.content_kind {
            drift_notes.push(format!(
                "content kind changed from {:?} to {:?}",
                exp.content_kind, fresh.content_kind
            ));
        }
    }

    let had_drift = !drift_notes.is_empty();
    if had_drift && options.strict_drift {
        return Err(PreflightError::StateDrift {
            path: path.to_path_buf(),
            reason: drift_notes.join("; "),
        });
    }

    // 6. Fresh risk assessment
    let now = options.now.unwrap_or_else(now_secs);
    let assessment = assess(&fresh, &AssessContext { now });

    // 7. Fresh safety policy enforcement
    let decision = enforce(&fresh, &assessment, options.policy, options.ai);
    if decision.is_blocked() {
        return Err(PreflightError::Blocked { decision });
    }

    // 8. Action compatibility check
    if options.action == RequestedAction::AutoQuarantine
        && decision.verdict != SafetyVerdict::AutoQuarantine
    {
        return Err(PreflightError::ConfirmationRequired {
            decision,
            reason: "file does not meet AutoQuarantine criteria under live evaluation".into(),
        });
    }

    Ok(PreflightOutcome {
        record: fresh,
        assessment,
        decision,
        had_drift,
        drift_notes,
    })
}

fn to_epoch(t: io::Result<SystemTime>) -> i64 {
    t.ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn to_opt_epoch(t: io::Result<SystemTime>) -> Option<i64> {
    t.ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs2::FileExt;

    fn tmp_file(tag: &str, content: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sc-preflight-{tag}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_item.tmp");
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn clean_temp_file_passes_preflight() {
        let path = tmp_file("clean", b"clean temp content");
        let policy = SafetyPolicy::default();
        let opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine);
        let outcome = revalidate(&path, &opts).unwrap();

        assert_eq!(outcome.record.size, 18);
        assert!(!outcome.had_drift);
        assert_eq!(outcome.decision.verdict, SafetyVerdict::AutoQuarantine);
    }

    #[test]
    fn missing_source_is_rejected() {
        let path = std::env::temp_dir().join("does_not_exist_file.tmp");
        let policy = SafetyPolicy::default();
        let opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine);
        let err = revalidate(&path, &opts).unwrap_err();
        assert!(matches!(err, PreflightError::SourceMissing(_)));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_is_blocked_never_followed() {
        let target = tmp_file("target", b"target data");
        let link_path = target.parent().unwrap().join("symlink_to_target");
        let _ = fs::remove_file(&link_path);
        std::os::unix::fs::symlink(&target, &link_path).unwrap();

        let policy = SafetyPolicy::default();
        let opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine);
        let err = revalidate(&link_path, &opts).unwrap_err();
        assert!(matches!(err, PreflightError::SymlinkBlocked(_)));
    }

    #[test]
    fn directory_is_blocked() {
        let dir = std::env::temp_dir().join(format!("sc-dir-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let policy = SafetyPolicy::default();
        let opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine);
        let err = revalidate(&dir, &opts).unwrap_err();
        assert!(matches!(err, PreflightError::DirectoryBlocked(_)));
    }

    #[test]
    fn locked_file_is_detected_in_use() {
        let path = tmp_file("locked", b"locked data");
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.lock_exclusive().unwrap();

        let policy = SafetyPolicy::default();
        let opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine);
        let err = revalidate(&path, &opts).unwrap_err();
        assert!(matches!(err, PreflightError::FileInUse(_)));
        file.unlock().unwrap();
    }

    #[test]
    fn state_drift_size_change_is_rejected_in_auto() {
        let path = tmp_file("drift_size", b"original");
        let mut expected = FileRecord::new(path.to_string_lossy().to_string(), 8, now_secs());
        expected.size = 8;
        expected.content_kind = sc_file_models::ContentKind::Temp;

        // Mutate file on disk before quarantine:
        fs::write(&path, b"mutated content with longer size").unwrap();

        let policy = SafetyPolicy::default();
        let opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine)
            .with_expected(&expected);
        let err = revalidate(&path, &opts).unwrap_err();
        assert!(matches!(err, PreflightError::StateDrift { .. }));
    }

    #[test]
    fn state_drift_accepted_with_reassessment_when_user_confirmed() {
        let path = tmp_file("drift_user", b"original");
        let mut expected = FileRecord::new(path.to_string_lossy().to_string(), 8, now_secs());
        expected.size = 8;

        // Mutate file:
        fs::write(&path, b"changed").unwrap();

        let policy = SafetyPolicy::default();
        // UserConfirmed without strict_drift allows re-evaluating fresh state
        let opts = PreflightOptions::new(&policy, RequestedAction::UserConfirmed)
            .with_expected(&expected);
        let outcome = revalidate(&path, &opts).unwrap();
        assert!(outcome.had_drift);
        assert_eq!(outcome.record.size, 7);
    }

    #[test]
    fn under_vault_root_is_rejected() {
        let vault_root = std::env::temp_dir().join(format!("sc-vault-test-{}", std::process::id()));
        fs::create_dir_all(&vault_root).unwrap();
        let file_inside = vault_root.join("inside.tmp");
        fs::write(&file_inside, b"x").unwrap();

        let policy = SafetyPolicy::default();
        let opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine)
            .with_vault_root(&vault_root);
        let err = revalidate(&file_inside, &opts).unwrap_err();
        assert!(matches!(err, PreflightError::UnderVaultRoot(_)));
    }

    #[test]
    fn user_exclusion_is_blocked_by_safety() {
        let path = tmp_file("excluded", b"data");
        let mut policy = SafetyPolicy::default();
        policy.excluded_files.push(path.clone());

        let opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine);
        let err = revalidate(&path, &opts).unwrap_err();
        assert!(matches!(err, PreflightError::Blocked { .. }));
    }

    #[test]
    fn demoted_verdict_demands_confirmation() {
        let path = tmp_file("demoted", b"not a temp");
        let policy = SafetyPolicy::default();
        // Create an executable file:
        let exe_path = path.parent().unwrap().join("fresh_prog.exe");
        fs::write(&exe_path, b"raw non-pe binary data").unwrap();

        // Attempting AutoQuarantine on an unknown executable must require user confirmation
        let opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine);
        let err = revalidate(&exe_path, &opts).unwrap_err();
        assert!(matches!(err, PreflightError::ConfirmationRequired { .. }));
    }
}
