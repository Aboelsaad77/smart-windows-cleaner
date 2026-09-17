//! `sc-local-rules` — Deterministic local cleanup rules and storage intelligence (spec §3; Milestone M2).
//!
//! Provides an evidence-producing, advisory rule evaluation layer for discovering
//! reclaimable storage candidates across Windows and userland applications.
//!
//! Important design constraints:
//! - Purely deterministic, offline, and local (zero network, zero cloud/AI dependency).
//! - Produces structured `RuleEvidence`, NOT destructive deletion decisions.
//! - The Safety Engine remains the final, absolute gate for all destructive actions.
//! - Age alone or extension alone NEVER classifies a file as disposable junk.
//! - Application attribution alone NEVER implies files are disposable.
//! - WinSxS is recognized as permanently protected component storage.

pub mod winsxs;

use sc_file_models::{
    known_paths, ContentKind, FileRecord, RuleCategory, RuleConfidence, RuleEvidence,
};

pub use winsxs::{evaluate_winsxs_evidence, is_winsxs_path, WinSxSInfo};

/// Alias for `WinSxSInfo::detect`.
pub fn detect_winsxs_info(windir: Option<&str>) -> WinSxSInfo {
    WinSxSInfo::detect(windir)
}

/// Context provided to the local rules engine during evaluation.
#[derive(Debug, Clone)]
pub struct RuleContext {
    /// Current unix epoch timestamp (seconds).
    pub now: i64,
    /// Configured Windows system root directory (defaults to "C:\Windows").
    pub windir: Option<String>,
    /// Configured user home profile directory.
    pub user_profile: Option<String>,
}

impl Default for RuleContext {
    fn default() -> Self {
        Self {
            now: sc_file_models::now_secs(),
            windir: None,
            user_profile: None,
        }
    }
}

/// Deterministic local cleanup and storage intelligence engine.
#[derive(Debug, Clone, Default)]
pub struct LocalRulesEngine;

impl LocalRulesEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluate a scanned file record against all local rules and return accumulated evidence.
    ///
    /// If no rules match, returns an empty `Vec`. Unknown files remain unclassified.
    pub fn evaluate(&self, record: &FileRecord, ctx: &RuleContext) -> Vec<RuleEvidence> {
        let mut evidences = Vec::new();
        let path = &record.path;
        let norm_path = known_paths::norm(path);
        let ext = record.extension.as_deref().unwrap_or("");

        // 1. WinSxS Component Store Protection Rule (Milestone M2.2)
        if let Some(sxs_ev) = winsxs::evaluate_winsxs_evidence(path, ctx.windir.as_deref()) {
            evidences.push(sxs_ev);
            // WinSxS files are strictly protected; return immediately so they are never
            // misclassified by secondary heuristics or cache rules.
            return evidences;
        }

        // 2. Windows System Temporary Directory
        let win = ctx.windir.as_deref().unwrap_or("c:\\windows");
        let win_temp_prefix = format!("{}\\temp\\", win.trim_end_matches('\\').to_lowercase());
        if norm_path.starts_with(&win_temp_prefix) {
            evidences.push(RuleEvidence {
                rule_id: "WIN_TEMP_FILE".into(),
                category: RuleCategory::WindowsTemp,
                matched_pattern: "%windir%\\Temp\\*".into(),
                reason: "File is located in the Windows operating system temporary folder.".into(),
                confidence: RuleConfidence::High,
                reclaimable_size: record.size,
                safety_implications:
                    "System temporary files are generally safe to clean if unlocked, \
                                      but active OS installers may lock files currently in use."
                        .into(),
            });
        }

        // 3. User Temporary Directory
        if norm_path.contains("\\appdata\\local\\temp\\")
            || norm_path.contains("\\local settings\\temp\\")
        {
            evidences.push(RuleEvidence {
                rule_id: "USER_TEMP_FILE".into(),
                category: RuleCategory::UserTemp,
                matched_pattern: "%LOCALAPPDATA%\\Temp\\*".into(),
                reason: "File is located in the user profile temporary directory.".into(),
                confidence: RuleConfidence::High,
                reclaimable_size: record.size,
                safety_implications:
                    "User temporary files are safe to clean when not locked by running processes. \
                                      Files younger than 24 hours should be treated with care."
                        .into(),
            });
        }

        // 4. Known Web Browser Caches
        if known_paths::is_browser_cache_path(path) {
            evidences.push(RuleEvidence {
                rule_id: "BROWSER_CACHE_FILE".into(),
                category: RuleCategory::BrowserCache,
                matched_pattern: "*\\User Data\\*\\Cache\\*".into(),
                reason: "File belongs to a known web browser HTTP/disk cache store.".into(),
                confidence: RuleConfidence::High,
                reclaimable_size: record.size,
                safety_implications:
                    "Browser caches are safe to purge; browsers will automatically \
                                      re-download required web assets as needed."
                        .into(),
            });
        }

        // 5. Known Desktop Application Caches (Electron, Spotify, Slack, Discord, Dev tools)
        if is_application_cache_path(&norm_path) {
            evidences.push(RuleEvidence {
                rule_id: "APP_CACHE_FILE".into(),
                category: RuleCategory::ApplicationCache,
                matched_pattern: "*\\AppData\\*\\Cache\\*".into(),
                reason: "File is located in a recognized third-party application cache directory."
                    .into(),
                confidence: RuleConfidence::High,
                reclaimable_size: record.size,
                safety_implications:
                    "Application caches can be safely cleared when the target app is closed; \
                                      ensure the application is not actively running."
                        .into(),
            });
        }

        // 6. Crash Dumps and Stale Diagnostic Logs
        if is_crash_dump_or_log(&norm_path, ext, record) {
            evidences.push(RuleEvidence {
                rule_id: "CRASH_DUMP_FILE".into(),
                category: RuleCategory::CrashDumps,
                matched_pattern: "*.dmp | *\\CrashDumps\\*".into(),
                reason: "File is a post-mortem crash dump or stale error diagnostic dump.".into(),
                confidence: RuleConfidence::High,
                reclaimable_size: record.size,
                safety_implications: "Crash dumps are non-essential diagnostic artifacts that consume substantial disk space."
                    .into(),
            });
        }

        // 7. Recycle Bin Awareness
        if norm_path.contains("\\$recycle.bin\\") || norm_path.contains("\\recycler\\") {
            evidences.push(RuleEvidence {
                rule_id: "RECYCLE_BIN_FILE".into(),
                category: RuleCategory::RecycleBin,
                matched_pattern: "*\\$Recycle.Bin\\*".into(),
                reason: "File resides within the Windows shell Recycle Bin.".into(),
                confidence: RuleConfidence::High,
                reclaimable_size: record.size,
                safety_implications:
                    "Recycle Bin files require shell recycling API integration and \
                                      should not be deleted blindly via raw filesystem access."
                        .into(),
            });
        }

        // 8. Old Downloaded Installer Artifacts (spec §3, audit F1/F8)
        // Multi-signal requirement: must be an installer kind + installer extension + age > 30 days
        // Neither age alone nor extension alone can trigger this rule!
        if (record.content_kind == ContentKind::Installer || matches!(ext, "msi" | "iso"))
            && matches!(ext, "exe" | "msi" | "iso")
            && record.age_days(ctx.now) > 30
            && (norm_path.contains("\\downloads\\")
                || norm_path.contains("\\package cache\\")
                || norm_path.contains("\\appdata\\local\\temp\\"))
        {
            evidences.push(RuleEvidence {
                rule_id: "OLD_INSTALLER_ARTIFACT".into(),
                category: RuleCategory::InstallerArtifacts,
                matched_pattern: "*\\Downloads\\*.msi | *.iso (>30d)".into(),
                reason: "Stale software installer or setup package not modified for over 30 days."
                    .into(),
                confidence: RuleConfidence::Medium,
                reclaimable_size: record.size,
                safety_implications:
                    "Installers are re-downloadable, but user confirmation is required \
                                      before removing executables or packages."
                        .into(),
            });
        }

        // 9. Application-Specific Temporary Working Data
        if is_app_specific_temp(&norm_path, ext) {
            evidences.push(RuleEvidence {
                rule_id: "APP_SPECIFIC_TEMP".into(),
                category: RuleCategory::AppSpecificTemp,
                matched_pattern: "Office / Adobe working temp patterns".into(),
                reason: "Application working scratch or auto-recovery temporary lock artifact.".into(),
                confidence: RuleConfidence::Medium,
                reclaimable_size: record.size,
                safety_implications: "Ensure the parent creative application is closed to avoid discarding unsaved changes."
                    .into(),
            });
        }

        evidences
    }
}

/// Matches recognized third-party desktop application caches.
fn is_application_cache_path(norm: &str) -> bool {
    norm.contains("\\discord\\cache\\")
        || norm.contains("\\discord\\code cache\\")
        || norm.contains("\\slack\\cache\\")
        || norm.contains("\\slack\\service worker\\cachestorage\\")
        || norm.contains("\\spotify\\storage\\")
        || norm.contains("\\code\\cache\\")
        || norm.contains("\\code\\cacheddata\\")
        || norm.contains("\\.npm\\_cacache\\")
        || norm.contains("\\.cache\\pip\\")
        || norm.contains("\\.gradle\\caches\\")
        || norm.contains("\\jetbrains\\") && norm.contains("\\system\\caches\\")
}

/// Matches post-mortem crash dumps and stale diagnostic logs.
fn is_crash_dump_or_log(norm: &str, ext: &str, record: &FileRecord) -> bool {
    if norm.contains("\\crashdumps\\") {
        return true;
    }
    if norm.contains("\\minidump\\") || norm.ends_with("memory.dmp") {
        return true;
    }
    if ext == "dmp" || ext == "mdmp" {
        return true;
    }
    if (ext == "log" || norm.ends_with(".log.old"))
        && record.content_kind == ContentKind::Log
        && norm.contains("\\windows\\logs\\cbs\\")
        && norm.ends_with(".log")
    {
        // CBS logs are Windows servicing logs
        return true;
    }
    false
}

/// Matches application-specific scratch / working temp files.
fn is_app_specific_temp(norm: &str, ext: &str) -> bool {
    let filename = norm.split('\\').next_back().unwrap_or("");
    // Office temporary locks and auto-recovery
    if filename.starts_with("~$") || matches!(ext, "asd" | "wbk") {
        return true;
    }
    // Adobe scratch and temporary files
    if filename.starts_with("photoshop temp") || filename.starts_with("acrobat temp") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    const NOW: i64 = 1_700_000_000;

    fn make_rec(path: &str, size: u64, age_days: i64, kind: ContentKind) -> FileRecord {
        let mut r = FileRecord::new(path, size, NOW - (age_days * 86_400));
        r.content_kind = kind;
        r.extension = Path::new(path)
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase());
        r
    }

    #[test]
    fn known_windows_temp_path() {
        let engine = LocalRulesEngine::new();
        let ctx = RuleContext {
            now: NOW,
            windir: Some("C:\\Windows".into()),
            ..Default::default()
        };
        let r = make_rec(
            "C:\\Windows\\Temp\\sess_123.tmp",
            4096,
            5,
            ContentKind::Temp,
        );
        let ev = engine.evaluate(&r, &ctx);

        assert!(ev.iter().any(|e| e.rule_id == "WIN_TEMP_FILE"));
        let win_temp = ev.iter().find(|e| e.rule_id == "WIN_TEMP_FILE").unwrap();
        assert_eq!(win_temp.category, RuleCategory::WindowsTemp);
        assert_eq!(win_temp.confidence, RuleConfidence::High);
    }

    #[test]
    fn known_user_temp_path() {
        let engine = LocalRulesEngine::new();
        let ctx = RuleContext {
            now: NOW,
            ..Default::default()
        };
        let r = make_rec(
            "C:\\Users\\Alice\\AppData\\Local\\Temp\\update.tmp",
            1024,
            2,
            ContentKind::Temp,
        );
        let ev = engine.evaluate(&r, &ctx);

        assert!(ev.iter().any(|e| e.rule_id == "USER_TEMP_FILE"));
        let user_temp = ev.iter().find(|e| e.rule_id == "USER_TEMP_FILE").unwrap();
        assert_eq!(user_temp.category, RuleCategory::UserTemp);
        assert_eq!(user_temp.confidence, RuleConfidence::High);
    }

    #[test]
    fn known_browser_cache_path() {
        let engine = LocalRulesEngine::new();
        let ctx = RuleContext {
            now: NOW,
            ..Default::default()
        };
        let r = make_rec(
            "C:\\Users\\Alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\data_0",
            65536,
            10,
            ContentKind::Cache,
        );
        let ev = engine.evaluate(&r, &ctx);

        assert!(ev.iter().any(|e| e.rule_id == "BROWSER_CACHE_FILE"));
        let b_cache = ev
            .iter()
            .find(|e| e.rule_id == "BROWSER_CACHE_FILE")
            .unwrap();
        assert_eq!(b_cache.category, RuleCategory::BrowserCache);
    }

    #[test]
    fn known_application_cache_path() {
        let engine = LocalRulesEngine::new();
        let ctx = RuleContext {
            now: NOW,
            ..Default::default()
        };
        let r = make_rec(
            "C:\\Users\\Alice\\AppData\\Roaming\\Discord\\Cache\\f_0001a",
            32768,
            8,
            ContentKind::Cache,
        );
        let ev = engine.evaluate(&r, &ctx);

        assert!(ev.iter().any(|e| e.rule_id == "APP_CACHE_FILE"));
        let app_cache = ev.iter().find(|e| e.rule_id == "APP_CACHE_FILE").unwrap();
        assert_eq!(app_cache.category, RuleCategory::ApplicationCache);
    }

    #[test]
    fn crash_dump_locations_detected() {
        let engine = LocalRulesEngine::new();
        let ctx = RuleContext {
            now: NOW,
            ..Default::default()
        };
        let r = make_rec(
            "C:\\Users\\Alice\\AppData\\Local\\CrashDumps\\app.exe.1234.dmp",
            10_000_000,
            3,
            ContentKind::Unknown,
        );
        let ev = engine.evaluate(&r, &ctx);

        assert!(ev.iter().any(|e| e.rule_id == "CRASH_DUMP_FILE"));
        let dmp = ev.iter().find(|e| e.rule_id == "CRASH_DUMP_FILE").unwrap();
        assert_eq!(dmp.category, RuleCategory::CrashDumps);
    }

    #[test]
    fn unknown_path_returns_no_rules() {
        let engine = LocalRulesEngine::new();
        let ctx = RuleContext {
            now: NOW,
            ..Default::default()
        };
        let r = make_rec(
            "C:\\Users\\Alice\\Documents\\Quarterly_Report.docx",
            50000,
            50,
            ContentKind::Document,
        );
        let ev = engine.evaluate(&r, &ctx);
        assert!(
            ev.is_empty(),
            "Unknown personal documents must match 0 cleanup rules"
        );
    }

    #[test]
    fn age_only_false_positive_prevention() {
        let engine = LocalRulesEngine::new();
        let ctx = RuleContext {
            now: NOW,
            ..Default::default()
        };
        // Very old personal photo (500 days old): Age alone MUST NEVER match a cleanup rule!
        let r = make_rec(
            "C:\\Users\\Alice\\Pictures\\Family_2024.jpg",
            2_000_000,
            500,
            ContentKind::Media,
        );
        let ev = engine.evaluate(&r, &ctx);
        assert!(ev.is_empty(), "Age alone must NEVER trigger a cleanup rule");
    }

    #[test]
    fn extension_only_false_positive_prevention() {
        let engine = LocalRulesEngine::new();
        let ctx = RuleContext {
            now: NOW,
            ..Default::default()
        };
        // Executable in personal tools folder: Extension alone MUST NEVER trigger a cleanup rule!
        let r = make_rec(
            "C:\\Users\\Alice\\Tools\\MyCustomTool.exe",
            1_000_000,
            5,
            ContentKind::Executable,
        );
        let ev = engine.evaluate(&r, &ctx);
        assert!(
            ev.is_empty(),
            "Extension alone must NEVER trigger a cleanup rule"
        );
    }

    #[test]
    fn application_attribution_alone_does_not_trigger_cleanup_rules() {
        let engine = LocalRulesEngine::new();
        let ctx = RuleContext {
            now: NOW,
            ..Default::default()
        };
        let mut r = make_rec(
            "C:\\Program Files\\Blender Foundation\\Blender 4.0\\blender.exe",
            100_000_000,
            120,
            ContentKind::Executable,
        );
        r.owner_app = Some("Blender".into());

        let ev = engine.evaluate(&r, &ctx);
        assert!(
            ev.is_empty(),
            "Application attribution alone must NEVER trigger a cleanup rule"
        );
    }

    #[test]
    fn old_installer_multi_signal_detection() {
        let engine = LocalRulesEngine::new();
        let ctx = RuleContext {
            now: NOW,
            ..Default::default()
        };
        // Multi-signal: Downloads + .iso + ContentKind::Installer + age > 30d
        let r = make_rec(
            "C:\\Users\\Alice\\Downloads\\ubuntu-22.04.iso",
            4_000_000_000,
            45,
            ContentKind::Installer,
        );
        let ev = engine.evaluate(&r, &ctx);
        assert!(ev.iter().any(|e| e.rule_id == "OLD_INSTALLER_ARTIFACT"));
    }

    // ---- WinSxS Intelligence Tests (Milestone M2.2) ----

    #[test]
    fn winsxs_path_detection_default() {
        assert!(is_winsxs_path(
            Path::new("C:\\Windows\\WinSxS\\amd64_microsoft-windows-servicing_31bf3856ad364e35_10.0.19041.1_none_123456\\servicing.dll"),
            None
        ));
        assert!(is_winsxs_path(
            Path::new("c:/windows/winsxs/manifests/amd64_1234.manifest"),
            None
        ));
        assert!(!is_winsxs_path(
            Path::new("C:\\Windows\\System32\\kernel32.dll"),
            None
        ));
    }

    #[test]
    fn winsxs_path_detection_custom_windir() {
        let custom = "D:\\CustomOS\\Windows";
        assert!(is_winsxs_path(
            Path::new("D:\\CustomOS\\Windows\\WinSxS\\File.dll"),
            Some(custom)
        ));
        assert!(!is_winsxs_path(
            Path::new("C:\\Windows\\WinSxS\\File.dll"),
            Some(custom)
        ));
    }

    #[test]
    fn winsxs_intelligence_emits_protected_evidence_no_reclamation() {
        let engine = LocalRulesEngine::new();
        let ctx = RuleContext {
            now: NOW,
            windir: Some("C:\\Windows".into()),
            ..Default::default()
        };
        let r = make_rec(
            "C:\\Windows\\WinSxS\\Manifests\\component.manifest",
            2048,
            600, // Very old, but MUST NOT be considered junk!
            ContentKind::Unknown,
        );
        let ev = engine.evaluate(&r, &ctx);

        assert_eq!(ev.len(), 1);
        let sxs = &ev[0];
        assert_eq!(sxs.rule_id, "WINSXS_COMPONENT_STORE");
        assert_eq!(sxs.category, RuleCategory::WinSxSComponentStore);
        assert_eq!(
            sxs.reclaimable_size, 0,
            "WinSxS must report 0 reclaimable bytes"
        );
        assert!(sxs.safety_implications.contains("dism.exe"));
        assert!(sxs.is_winsxs());
    }

    #[test]
    fn winsxs_info_struct_detection() {
        let info = WinSxSInfo::detect(Some("C:\\Windows"));
        assert_eq!(info.path, PathBuf::from("C:\\Windows\\WinSxS"));
        assert!(info.is_protected);
        assert!(info.recommendation.contains("dism.exe"));
    }
}
