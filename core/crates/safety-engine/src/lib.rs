//! `sc-safety-engine` — the FINAL GATE (spec §6, §23).
//!
//! The risk engine scores, the AI may second-guess, but only this engine
//! decides whether an action is allowed. Hard rules override everything,
//! including AI recommendations:
//!
//! ```text
//! AI ──recommendation──▶ Risk Engine ──▶ SAFETY ENGINE ─▶ NO  → BLOCK
//!                                              │
//!                                              └────▶ YES → QUARANTINE (never direct delete)
//! ```

use sc_file_models::{known_paths, AiSignal, FileRecord, RiskBand};
use sc_risk_engine::RiskAssessment;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

/// What the safety engine allows for this item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyVerdict {
    /// A hard rule fired. Nothing may be deleted, quarantined or touched.
    NeverDelete,
    /// Deletion risk is low: eligible for one-click "clean all safe items".
    /// The performed action is still *quarantine* — never direct deletion.
    AutoQuarantine,
    /// Quarantine is allowed, but only after explicit user confirmation.
    UserConfirm,
}

impl fmt::Display for SafetyVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SafetyVerdict::NeverDelete => write!(f, "never_delete"),
            SafetyVerdict::AutoQuarantine => write!(f, "auto_quarantine"),
            SafetyVerdict::UserConfirm => write!(f, "user_confirm"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyPolicy {
    /// Root directory of this program itself — it never touches its own files.
    pub self_root: Option<PathBuf>,
    /// User-managed "never touch" roots (spec §18, Ignore Rules).
    pub excluded_roots: Vec<PathBuf>,
    /// Exact files the user excluded.
    pub excluded_files: Vec<PathBuf>,
    /// Whether an AI second opinion may promote UserConfirm → AutoQuarantine.
    pub allow_ai_second_opinion: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SafetyDecision {
    pub verdict: SafetyVerdict,
    /// Ids of the hard rules that fired (empty if none).
    pub blocked_rules: Vec<&'static str>,
    /// Human-readable notes for the UI ("Why is this blocked / safe?").
    pub notes: Vec<String>,
}

impl SafetyDecision {
    pub fn is_blocked(&self) -> bool {
        self.verdict == SafetyVerdict::NeverDelete
    }
}

/// Confidence at/above which an AI second opinion is trusted (spec §7).
pub const AI_MIN_CONFIDENCE: f32 = 0.9;

pub fn enforce(
    record: &FileRecord,
    assessment: &RiskAssessment,
    policy: &SafetyPolicy,
    ai: Option<&AiSignal>,
) -> SafetyDecision {
    let mut blocked: Vec<&'static str> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // ---- hard rules (spec §6): highest priority, override AI ----
    if let Some(root) = &policy.self_root {
        if under(&record.path, root) {
            blocked.push("SELF_PROTECTION");
        }
    }
    if policy.excluded_roots.iter().any(|r| under(&record.path, r))
        || policy.excluded_files.iter().any(|f| f == &record.path)
    {
        blocked.push("USER_EXCLUSION");
    }
    if known_paths::is_windows_protected_path(&record.path) {
        blocked.push("WINDOWS_PROTECTED_PATH");
    }
    if record.is_system {
        blocked.push("SYSTEM_FILE");
    }
    if record.is_driver {
        blocked.push("DRIVER");
    }
    if record.in_use {
        blocked.push("CURRENTLY_IN_USE");
    }
    if record.is_signed && record.is_pe {
        blocked.push("SIGNED_CRITICAL_BINARY");
    }
    if assessment.band == RiskBand::Protected {
        blocked.push("PROTECTED_BAND");
    }

    if !blocked.is_empty() {
        notes.push(format!(
            "Blocked by hard safety rules: {}",
            blocked.join(", ")
        ));
        return SafetyDecision {
            verdict: SafetyVerdict::NeverDelete,
            blocked_rules: blocked,
            notes,
        };
    }

    // ---- no hard rule fired: decide from the risk band ----
    let mut verdict = match assessment.band {
        RiskBand::VerySafe | RiskBand::Safe => SafetyVerdict::AutoQuarantine,
        RiskBand::Review | RiskBand::Dangerous => SafetyVerdict::UserConfirm,
        RiskBand::Protected => unreachable!("protected band is handled above"),
    };
    notes.push(format!(
        "Risk of deletion: {} ({})",
        assessment.band.label(),
        assessment.score
    ));

    // UnknownExecutable => NEVER_AUTO_DELETE (spec §6)
    if record.is_pe && !record.is_signed && verdict == SafetyVerdict::AutoQuarantine {
        verdict = SafetyVerdict::UserConfirm;
        notes.push("Unsigned executable: automatic cleanup disabled".into());
    }

    // ---- bounded AI second opinion (spec §7, §23) ----
    // The AI can only move a decision *toward* quarantine for Review-band
    // items. It can never unblock a hard rule and can never trigger deletion.
    if let Some(sig) = ai {
        if policy.allow_ai_second_opinion
            && sig.confidence >= AI_MIN_CONFIDENCE
            && sig.recommendation.as_deref() == Some("QUARANTINE")
            && verdict == SafetyVerdict::UserConfirm
            && assessment.band == RiskBand::Review
        {
            verdict = SafetyVerdict::AutoQuarantine;
            notes.push(format!(
                "AI second opinion ({}: {} @ {:.2}) promoted to auto-quarantine",
                sig.source,
                sig.classification.clone().unwrap_or_default(),
                sig.confidence
            ));
        } else if sig.recommendation.as_deref() == Some("KEEP") {
            notes.push(format!(
                "AI suggests keeping ({})",
                sig.reason.clone().unwrap_or_default()
            ));
        }
    }

    SafetyDecision {
        verdict,
        blocked_rules: blocked,
        notes,
    }
}

/// True if `path` equals `root` or lies underneath it (case-insensitive).
fn under(path: &Path, root: &Path) -> bool {
    let p = known_paths::norm(path);
    let normed = known_paths::norm(root);
    let r = normed.trim_end_matches('\\');
    p == r || p.starts_with(&format!("{r}\\"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_file_models::ContentKind;

    const NOW: i64 = 1_750_000_000;

    fn temp_rec() -> FileRecord {
        let mut r = FileRecord::new(
            "C:\\Users\\U\\AppData\\Local\\Temp\\a.tmp",
            10,
            NOW - 86_400,
        );
        r.extension = Some("tmp".into());
        r.content_kind = ContentKind::Temp;
        r
    }

    fn local(rec: &FileRecord) -> RiskAssessment {
        sc_risk_engine::assess(rec, &sc_risk_engine::AssessContext { now: NOW })
    }

    fn synth(score: u16) -> RiskAssessment {
        RiskAssessment {
            path: PathBuf::from("synthetic"),
            score,
            band: RiskBand::from_score(score),
            factors: vec![],
        }
    }

    fn ai(rec: &str, conf: f32) -> AiSignal {
        AiSignal {
            source: rec.into(),
            classification: Some("LIKELY_JUNK".into()),
            confidence: conf,
            recommendation: Some("QUARANTINE".into()),
            reason: Some("old application cache".into()),
        }
    }

    #[test]
    fn safe_temp_file_is_auto_quarantine() {
        let r = temp_rec();
        let a = local(&r);
        let d = enforce(&r, &a, &SafetyPolicy::default(), None);
        assert_eq!(d.verdict, SafetyVerdict::AutoQuarantine);
        assert!(d.blocked_rules.is_empty());
    }

    #[test]
    fn signed_windows_binary_is_never_delete() {
        let mut r = FileRecord::new("C:\\Windows\\System32\\x.dll", 10, NOW);
        r.is_pe = true;
        r.is_signed = true;
        r.is_windows_component = true;
        r.is_system = true;
        let a = local(&r);
        let d = enforce(&r, &a, &SafetyPolicy::default(), Some(&ai("cloud", 0.99)));
        assert_eq!(d.verdict, SafetyVerdict::NeverDelete);
        assert!(d.blocked_rules.contains(&"WINDOWS_PROTECTED_PATH"));
        assert!(d.blocked_rules.contains(&"SIGNED_CRITICAL_BINARY"));
    }

    #[test]
    fn in_use_file_is_never_delete() {
        let mut r = temp_rec();
        r.in_use = true;
        let a = local(&r);
        let d = enforce(&r, &a, &SafetyPolicy::default(), Some(&ai("cloud", 0.99)));
        assert_eq!(d.verdict, SafetyVerdict::NeverDelete);
        assert!(d.blocked_rules.contains(&"CURRENTLY_IN_USE"));
    }

    #[test]
    fn driver_is_never_delete() {
        let mut r = FileRecord::new("C:\\Windows\\System32\\drivers\\d.sys", 10, NOW);
        r.is_driver = true;
        let a = local(&r);
        let d = enforce(&r, &a, &SafetyPolicy::default(), None);
        assert_eq!(d.verdict, SafetyVerdict::NeverDelete);
        assert!(d.blocked_rules.contains(&"DRIVER"));
    }

    #[test]
    fn user_exclusion_is_absolute() {
        let r = FileRecord::new("D:\\MyProjects\\src\\main.rs", 10, NOW);
        let mut policy = SafetyPolicy::default();
        policy.excluded_roots.push(PathBuf::from("D:\\MyProjects"));
        let d = enforce(&r, &synth(5), &policy, Some(&ai("cloud", 0.99)));
        assert_eq!(d.verdict, SafetyVerdict::NeverDelete);
        assert!(d.blocked_rules.contains(&"USER_EXCLUSION"));
    }

    #[test]
    fn self_protection() {
        let r = FileRecord::new("C:\\Program Files\\SmartCleaner\\Cleaner.exe", 10, NOW);
        let policy = SafetyPolicy {
            self_root: Some(PathBuf::from("C:\\Program Files\\SmartCleaner")),
            ..Default::default()
        };
        let d = enforce(&r, &synth(5), &policy, None);
        assert_eq!(d.verdict, SafetyVerdict::NeverDelete);
        assert!(d.blocked_rules.contains(&"SELF_PROTECTION"));
    }

    #[test]
    fn unsigned_pe_is_never_auto() {
        let mut r = temp_rec();
        r.is_pe = true;
        // Synthetic "safe" score to isolate the downgrade rule.
        let d = enforce(&r, &synth(20), &SafetyPolicy::default(), None);
        assert_eq!(d.verdict, SafetyVerdict::UserConfirm);
        assert!(d.notes.join(" ").contains("Unsigned executable"));
    }

    #[test]
    fn ai_promotes_review_when_confident() {
        let r = FileRecord::new(
            "C:\\Users\\U\\Downloads\\someapp\\cache.dat",
            10,
            NOW - 100 * 86_400,
        );
        let a = local(&r);
        assert_eq!(a.band, RiskBand::Review);
        let policy = SafetyPolicy {
            allow_ai_second_opinion: true,
            ..Default::default()
        };
        let d = enforce(&r, &a, &policy, Some(&ai("cloud/test", 0.96)));
        assert_eq!(d.verdict, SafetyVerdict::AutoQuarantine);
    }

    #[test]
    fn ai_low_confidence_does_not_promote() {
        let r = FileRecord::new(
            "C:\\Users\\U\\Downloads\\someapp\\cache.dat",
            10,
            NOW - 100 * 86_400,
        );
        let a = local(&r);
        let policy = SafetyPolicy {
            allow_ai_second_opinion: true,
            ..Default::default()
        };
        let d = enforce(&r, &a, &policy, Some(&ai("cloud/test", 0.85)));
        assert_eq!(d.verdict, SafetyVerdict::UserConfirm);
    }

    #[test]
    fn ai_cannot_promote_dangerous_band() {
        let r = FileRecord::new("C:\\Users\\U\\Documents\\x", 10, NOW);
        let policy = SafetyPolicy {
            allow_ai_second_opinion: true,
            ..Default::default()
        };
        let d = enforce(&r, &synth(75), &policy, Some(&ai("cloud/test", 0.99)));
        assert_eq!(d.verdict, SafetyVerdict::UserConfirm);
    }

    #[test]
    fn ai_keep_adds_note_but_changes_nothing() {
        let r = FileRecord::new(
            "C:\\Users\\U\\Downloads\\someapp\\cache.dat",
            10,
            NOW - 100 * 86_400,
        );
        let a = local(&r);
        let sig = AiSignal {
            source: "cloud/test".into(),
            classification: Some("KEEP".into()),
            confidence: 0.9,
            recommendation: Some("KEEP".into()),
            reason: Some("active application data".into()),
        };
        let d = enforce(&r, &a, &SafetyPolicy::default(), Some(&sig));
        assert_eq!(d.verdict, SafetyVerdict::UserConfirm);
        assert!(d.notes.join(" ").contains("AI suggests keeping"));
    }
}
