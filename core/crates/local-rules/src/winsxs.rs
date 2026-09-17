//! Windows Side-by-Side (WinSxS) Component Store Intelligence (spec §3; Milestone M2.2).
//!
//! WinSxS is the Windows native component store containing OS servicing payloads,
//! manifest stores, and hard-link targets for Windows binaries.
//!
//! STRICT SAFETY CONTRACTS:
//! - WinSxS is a protected storage area, NOT a cleanup candidate.
//! - Files under WinSxS must NEVER become ordinary cleanup candidates merely
//!   because they are old, large, or appear duplicated.
//! - Manual file or folder deletion from WinSxS is strictly forbidden.
//! - Cleanup must only be performed via supported Windows servicing mechanisms
//!   (e.g. DISM `dism.exe /Online /Cleanup-Image /StartComponentCleanup`).

use sc_file_models::{known_paths, RuleCategory, RuleConfidence, RuleEvidence};
use std::path::{Path, PathBuf};

/// Recommended Windows native servicing command for WinSxS cleanup.
pub const WINSXS_DISM_RECOMMENDATION: &str =
    "Do not manually delete files or directories in WinSxS. Use Windows native servicing: \
     'dism.exe /Online /Cleanup-Image /StartComponentCleanup' or Windows Storage Sense.";

/// Structured intelligence regarding the Windows WinSxS component store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinSxSInfo {
    /// Resolved absolute path to the WinSxS directory.
    pub path: PathBuf,
    /// Whether the directory exists on the current filesystem.
    pub exists: bool,
    /// Always true: WinSxS is permanently protected.
    pub is_protected: bool,
    /// Advisory guidance for servicing rather than deleting.
    pub recommendation: &'static str,
}

impl WinSxSInfo {
    /// Detect WinSxS component store using configured or default Windows directory.
    pub fn detect(windir: Option<&str>) -> Self {
        let base_win = windir.unwrap_or("C:\\Windows");
        let path = if base_win.contains('/') {
            PathBuf::from(format!("{}/WinSxS", base_win.trim_end_matches('/')))
        } else {
            PathBuf::from(format!("{}\\WinSxS", base_win.trim_end_matches('\\')))
        };
        let exists = path.is_dir();
        Self {
            path,
            exists,
            is_protected: true,
            recommendation: WINSXS_DISM_RECOMMENDATION,
        }
    }
}

/// Check if a given file or directory path is located inside the WinSxS component store.
pub fn is_winsxs_path(path: &Path, windir: Option<&str>) -> bool {
    let p_norm = known_paths::norm(path);
    let win = windir.unwrap_or("c:\\windows");
    let winsxs_prefix = format!("{}\\winsxs", win.trim_end_matches('\\').to_lowercase());

    p_norm.starts_with(&winsxs_prefix)
}

/// Create structured evidence when a path is recognized within WinSxS.
pub fn evaluate_winsxs_evidence(path: &Path, windir: Option<&str>) -> Option<RuleEvidence> {
    if !is_winsxs_path(path, windir) {
        return None;
    }

    Some(RuleEvidence {
        rule_id: "WINSXS_COMPONENT_STORE".into(),
        category: RuleCategory::WinSxSComponentStore,
        matched_pattern: "%windir%\\WinSxS\\*".into(),
        reason: "File resides within the Windows Side-by-Side (WinSxS) component store. \
                 WinSxS stores OS packages, manifests, and component hard-links vital for system boot and servicing."
            .into(),
        confidence: RuleConfidence::High,
        reclaimable_size: 0, // Manual reclamation is prohibited
        safety_implications: format!(
            "STRICTLY PROTECTED: Manual deletion corrupts the Windows component store and breaks updates. {WINSXS_DISM_RECOMMENDATION}"
        ),
    })
}

/// Safely measure approximate size of the component store if accessible.
///
/// Reads shallow top-level entries without recursively walking 100,000+ hard-linked
/// servicing files to prevent I/O thrashing.
pub fn measure_approximate_size(winsxs_dir: &Path) -> std::io::Result<u64> {
    if !winsxs_dir.is_dir() {
        return Ok(0);
    }
    let mut total: u64 = 0;
    // Read only top-level directory entries and direct files
    if let Ok(entries) = std::fs::read_dir(winsxs_dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    Ok(total)
}
