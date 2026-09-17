//! `sc-risk-engine` — scores the risk *of deleting* each file (0..=100).
//!
//! Design notes:
//! - The score is a **deletion risk**, NOT a junkiness score.
//! - Every contributing rule is recorded as a [`RiskFactor`] so the UI can
//!   answer "Why is this safe / dangerous?" (spec §17, Explainability).
//! - The engine is deterministic and 100% local. AI signals are applied later,
//!   by the safety engine, as a *bounded* second opinion (spec §23).

use sc_file_models::{known_paths, now_secs, ContentKind, FileRecord, RiskBand};
use serde::Serialize;
use std::path::PathBuf;

/// Unknown context starts in the middle: "review" until proven otherwise.
pub const BASELINE: i32 = 50;

/// One explainable contribution to the final score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RiskFactor {
    /// Stable rule id, e.g. `TEMP_PATH`, `PE_EXECUTABLE`.
    pub rule: &'static str,
    /// Negative = safer to delete, positive = more dangerous to delete.
    pub delta: i32,
}

impl RiskFactor {
    pub fn explanation(&self) -> &'static str {
        match self.rule {
            "BASELINE" => "Unknown context — treated as 'review' until classified",
            "TEMP_PATH" => "File lives in a known temporary folder",
            "BROWSER_CACHE" => "File lives in a browser cache directory",
            "TEMP_KIND" => "Content looks like a temporary file",
            "CACHE_KIND" => "Content looks like application cache",
            "LOG_KIND" => "Content looks like a log file",
            "TEMP_EXT" => "Temporary file extension",
            "AGE_30D" => "Not modified for more than 30 days",
            "AGE_90D" => "Not modified for more than 90 days",
            "INSTALLER_KIND" => "Content looks like a software installer",
            "OLD_INSTALLER" => "Old installer (installers are re-downloadable)",
            "DRIVER" => "Kernel driver",
            "WINDOWS_COMPONENT" => "Part of the Windows OS",
            "IN_USE" => "Currently locked / used by a running process",
            "HIDDEN" => "Hidden file",
            "PE_EXECUTABLE" => "Portable executable (PE) binary",
            "PE_INSTALLER" => "PE binary identified as an installer",
            "LIBRARY" => "Shared library (.dll / .ocx)",
            "SIGNED_BINARY" => "Digitally signed binary (Authenticode)",
            "UNSIGNED_PE" => "Unsigned PE binary — unknown origin",
            "PERSONAL_AREA" => "Located in the user's personal area",
            "PERSONAL_CONTENT" => "User document or media in a personal area",
            other => other,
        }
    }
}

/// Inputs the risk engine needs beyond the record itself.
#[derive(Debug, Clone, Copy)]
pub struct AssessContext {
    /// Current unix time (seconds).
    pub now: i64,
}

impl Default for AssessContext {
    fn default() -> Self {
        Self { now: now_secs() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RiskAssessment {
    pub path: PathBuf,
    /// Clamped 0..=100. Higher = more dangerous to delete.
    pub score: u16,
    pub band: RiskBand,
    pub factors: Vec<RiskFactor>,
}

impl RiskAssessment {
    /// Human-readable explanation for the UI ("Why is this safe?").
    pub fn explanation(&self) -> String {
        self.factors
            .iter()
            .map(|f| format!("{:+3}  {} — {}", f.delta, f.rule, f.explanation()))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

pub fn assess(record: &FileRecord, ctx: &AssessContext) -> RiskAssessment {
    let mut f: Vec<RiskFactor> = Vec::new();
    f.push(RiskFactor {
        rule: "BASELINE",
        delta: BASELINE,
    });

    let is_temp = known_paths::is_temp_path(&record.path);
    let is_bcache = known_paths::is_browser_cache_path(&record.path);
    let is_personal = known_paths::is_personal_path(&record.path);
    let age = record.age_days(ctx.now);

    // ---- junk indicators (lower deletion risk) ----
    if is_temp {
        f.push(RiskFactor {
            rule: "TEMP_PATH",
            delta: -25,
        });
    }
    if is_bcache {
        f.push(RiskFactor {
            rule: "BROWSER_CACHE",
            delta: -20,
        });
    }
    match record.content_kind {
        // Avoid double-counting when the path already told us.
        ContentKind::Temp if !is_temp => f.push(RiskFactor {
            rule: "TEMP_KIND",
            delta: -10,
        }),
        ContentKind::Cache if !is_bcache => f.push(RiskFactor {
            rule: "CACHE_KIND",
            delta: -15,
        }),
        ContentKind::Log => f.push(RiskFactor {
            rule: "LOG_KIND",
            delta: -10,
        }),
        ContentKind::Installer => f.push(RiskFactor {
            rule: "INSTALLER_KIND",
            delta: -10,
        }),
        ContentKind::Document | ContentKind::Media if is_personal => f.push(RiskFactor {
            rule: "PERSONAL_CONTENT",
            delta: 10,
        }),
        _ => {}
    }
    let ext = record.extension.as_deref().map(|e| e.to_ascii_lowercase());
    let temp_ext = matches!(
        ext.as_deref(),
        Some("tmp") | Some("temp") | Some("dmp") | Some("chk") | Some("swp") | Some("old")
    );
    if temp_ext && !is_temp {
        f.push(RiskFactor {
            rule: "TEMP_EXT",
            delta: -10,
        });
    }
    if age > 30 {
        f.push(RiskFactor {
            rule: "AGE_30D",
            delta: -10,
        });
    }
    if age > 90 {
        f.push(RiskFactor {
            rule: "AGE_90D",
            delta: -5,
        });
    }
    if record.content_kind == ContentKind::Installer && age > 60 {
        f.push(RiskFactor {
            rule: "OLD_INSTALLER",
            delta: -25,
        });
    }

    // ---- deletion-risk indicators ----
    if record.is_driver {
        f.push(RiskFactor {
            rule: "DRIVER",
            delta: 50,
        });
    }
    if record.is_windows_component {
        f.push(RiskFactor {
            rule: "WINDOWS_COMPONENT",
            delta: 60,
        });
    }
    if record.in_use {
        f.push(RiskFactor {
            rule: "IN_USE",
            delta: 80,
        });
    }
    if record.is_hidden {
        f.push(RiskFactor {
            rule: "HIDDEN",
            delta: 5,
        });
    }

    if let Some(attr) = record.windows_attributes {
        if attr.is_readonly {
            f.push(RiskFactor {
                rule: "READONLY_ATTRIBUTE",
                delta: 15,
            });
        }
        if attr.is_system {
            f.push(RiskFactor {
                rule: "SYSTEM_ATTRIBUTE",
                delta: 25,
            });
        }
    } else if record.is_system {
        f.push(RiskFactor {
            rule: "SYSTEM_ATTRIBUTE",
            delta: 25,
        });
    }

    if let Some(sig) = &record.signature {
        if sig.status == sc_file_models::SignatureStatus::SignedInvalid {
            f.push(RiskFactor {
                rule: "INVALID_SIGNATURE",
                delta: 35,
            });
        } else if sig.status == sc_file_models::SignatureStatus::SignedUnknown {
            f.push(RiskFactor {
                rule: "UNVERIFIED_SIGNATURE",
                delta: 20,
            });
        }
    }

    if record.is_pe {
        if record.content_kind == ContentKind::Installer {
            // Installers are self-extracting archives: lower (but not zero) risk.
            f.push(RiskFactor {
                rule: "PE_INSTALLER",
                delta: 20,
            });
        } else if record.content_kind == ContentKind::Library {
            f.push(RiskFactor {
                rule: "LIBRARY",
                delta: 35,
            });
        } else {
            f.push(RiskFactor {
                rule: "PE_EXECUTABLE",
                delta: 40,
            });
        }
        if record.is_signed {
            f.push(RiskFactor {
                rule: "SIGNED_BINARY",
                delta: 30,
            });
        } else {
            f.push(RiskFactor {
                rule: "UNSIGNED_PE",
                delta: 30,
            });
        }
    } else if record.content_kind == ContentKind::Library && !record.is_driver {
        f.push(RiskFactor {
            rule: "LIBRARY",
            delta: 35,
        });
    }

    if is_personal {
        f.push(RiskFactor {
            rule: "PERSONAL_AREA",
            delta: 15,
        });
    }

    let raw: i32 = f.iter().map(|x| x.delta).sum();
    let mut score = raw.clamp(0, 100) as u16;
    // A file that is in use is never "safe to delete", no matter how junky.
    if record.in_use {
        score = score.max(95);
    }
    let band = RiskBand::from_score(score);
    RiskAssessment {
        path: record.path.clone(),
        score,
        band,
        factors: f,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_file_models::ContentKind;

    const NOW: i64 = 1_750_000_000;
    const DAY: i64 = 86_400;

    fn rec(path: &str, kind: ContentKind, age_days: i64) -> FileRecord {
        let mut r = FileRecord::new(path, 1024, NOW - age_days * DAY);
        r.content_kind = kind;
        r
    }

    #[test]
    fn temp_file_10d_is_safe() {
        let r = rec(
            "C:\\Users\\U\\AppData\\Local\\Temp\\abc.tmp",
            ContentKind::Temp,
            10,
        );
        let a = assess(&r, &AssessContext { now: NOW });
        assert_eq!(a.score, 25);
        assert_eq!(a.band, RiskBand::Safe);
    }

    #[test]
    fn old_temp_file_is_safety() {
        let r = rec(
            "C:\\Users\\U\\AppData\\Local\\Temp\\abc.tmp",
            ContentKind::Temp,
            45,
        );
        let a = assess(&r, &AssessContext { now: NOW });
        assert_eq!(a.score, 15);
        assert_eq!(a.band, RiskBand::Safe);
    }

    #[test]
    fn old_browser_cache_is_safety() {
        let r = rec(
            "C:\\Users\\U\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\f_000001",
            ContentKind::Cache,
            184,
        );
        let a = assess(&r, &AssessContext { now: NOW });
        assert!(a.score <= 30, "score was {}", a.score);
        assert!(a.band <= RiskBand::Safe);
    }

    #[test]
    fn chrome_dll_is_protected() {
        let mut r = rec(
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.dll",
            ContentKind::Library,
            5,
        );
        r.is_pe = true;
        r.is_signed = true;
        r.owner_app = Some("Google Chrome".into());
        let a = assess(&r, &AssessContext { now: NOW });
        assert_eq!(a.score, 100);
        assert_eq!(a.band, RiskBand::Protected);
    }

    #[test]
    fn windows_driver_is_protected() {
        let mut r = rec(
            "C:\\Windows\\System32\\drivers\\foo.sys",
            ContentKind::Library,
            999,
        );
        r.is_driver = true;
        r.is_windows_component = true;
        r.is_system = true;
        let a = assess(&r, &AssessContext { now: NOW });
        assert_eq!(a.score, 100);
        assert_eq!(a.band, RiskBand::Protected);
    }

    #[test]
    fn in_use_binary_is_protected() {
        let mut r = rec(
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            ContentKind::Executable,
            5,
        );
        r.is_pe = true;
        r.is_signed = true;
        r.in_use = true;
        let a = assess(&r, &AssessContext { now: NOW });
        assert_eq!(a.score, 100);
        assert_eq!(a.band, RiskBand::Protected);
    }

    #[test]
    fn in_use_temp_file_is_still_protected() {
        let mut r = rec(
            "C:\\Users\\U\\AppData\\Local\\Temp\\locked.tmp",
            ContentKind::Temp,
            1,
        );
        r.in_use = true;
        let a = assess(&r, &AssessContext { now: NOW });
        assert_eq!(a.score, 100);
        assert_eq!(a.band, RiskBand::Protected);
    }

    #[test]
    fn personal_document_is_dangerous() {
        let r = rec(
            "C:\\Users\\U\\Documents\\resume.docx",
            ContentKind::Document,
            2,
        );
        let a = assess(&r, &AssessContext { now: NOW });
        assert_eq!(a.score, 75);
        assert_eq!(a.band, RiskBand::Dangerous);
    }

    #[test]
    fn unsigned_exe_is_protected() {
        let mut r = rec(
            "C:\\Users\\U\\Downloads\\crack.exe",
            ContentKind::Executable,
            1,
        );
        r.is_pe = true;
        let a = assess(&r, &AssessContext { now: NOW });
        assert_eq!(a.score, 100);
        assert_eq!(a.band, RiskBand::Protected);
    }

    #[test]
    fn old_signed_installer_is_review() {
        let mut r = rec(
            "C:\\Users\\U\\Downloads\\vs-setup.exe",
            ContentKind::Installer,
            400,
        );
        r.is_pe = true;
        r.is_signed = true;
        let a = assess(&r, &AssessContext { now: NOW });
        assert_eq!(a.score, 50);
        assert_eq!(a.band, RiskBand::Review);
    }

    #[test]
    fn old_game_image_is_review() {
        let r = rec("D:\\Games\\gta.iso", ContentKind::Archive, 200);
        let a = assess(&r, &AssessContext { now: NOW });
        assert_eq!(a.score, 35);
        assert_eq!(a.band, RiskBand::Review);
    }

    #[test]
    fn assessment_is_explainable() {
        let r = rec(
            "C:\\Users\\U\\AppData\\Local\\Temp\\abc.tmp",
            ContentKind::Temp,
            10,
        );
        let a = assess(&r, &AssessContext { now: NOW });
        assert!(a.factors.iter().any(|f| f.rule == "TEMP_PATH"));
        let text = a.explanation();
        assert!(text.contains("TEMP_PATH"));
        assert!(text.contains("temporary folder"));
    }

    #[test]
    fn invalid_signed_pe_has_invalid_signature_factor() {
        let mut r = rec("C:\\app\\corrupt.exe", ContentKind::Executable, 10);
        r.is_pe = true;
        r.signature = Some(sc_file_models::SignatureInfo::signed_invalid(
            sc_file_models::TrustStatus::BadDigest,
            Some(0x80096010),
            "Tampered",
            None,
        ));
        let ctx = AssessContext { now: NOW };
        let a = assess(&r, &ctx);
        assert!(a.factors.iter().any(|f| f.rule == "INVALID_SIGNATURE"));
    }

    #[test]
    fn unverified_signature_pe_has_unverified_factor() {
        let mut r = rec("C:\\app\\unknown.exe", ContentKind::Executable, 10);
        r.is_pe = true;
        r.signature = Some(sc_file_models::SignatureInfo {
            status: sc_file_models::SignatureStatus::SignedUnknown,
            is_pe: true,
            trust_status: sc_file_models::TrustStatus::UnknownTrust,
            ..Default::default()
        });
        let ctx = AssessContext { now: NOW };
        let a = assess(&r, &ctx);
        assert!(a.factors.iter().any(|f| f.rule == "UNVERIFIED_SIGNATURE"));
    }

    #[test]
    fn readonly_attribute_raises_risk() {
        let mut r = rec("C:\\app\\file.txt", ContentKind::Document, 10);
        r.windows_attributes = Some(sc_file_models::WindowsAttributes {
            is_readonly: true,
            ..Default::default()
        });
        let ctx = AssessContext { now: NOW };
        let a = assess(&r, &ctx);
        assert!(a.factors.iter().any(|f| f.rule == "READONLY_ATTRIBUTE"));
    }

    #[test]
    fn system_attribute_raises_risk_to_review_not_never_delete() {
        let mut r = rec("C:\\app\\file.txt", ContentKind::Document, 10);
        r.is_system = true;
        let ctx = AssessContext { now: NOW };
        let a = assess(&r, &ctx);
        assert!(a.factors.iter().any(|f| f.rule == "SYSTEM_ATTRIBUTE"));
        assert_ne!(a.score, 100);
    }
}
