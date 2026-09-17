//! Local rules and storage intelligence evidence models (spec §3; Milestone M2).
//!
//! Provides structured evidence produced by deterministic local cleanup rules.
//! Rules are strictly informational / evidence-producing; the Safety Engine
//! remains the final authority.

use serde::{Deserialize, Serialize};

/// Categories of local cleanup rules and storage areas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    /// Windows OS temporary folders (e.g. `C:\Windows\Temp`).
    WindowsTemp,
    /// User profile temporary and cache locations (e.g. `%LOCALAPPDATA%\Temp`).
    UserTemp,
    /// Known web browser cache directories (Chrome, Edge, Firefox, Brave, Opera, Vivaldi).
    BrowserCache,
    /// Known desktop application caches (Discord, Slack, Spotify, VS Code, dev tool caches).
    ApplicationCache,
    /// Crash dumps, minidumps, and stale diagnostic error logs.
    CrashDumps,
    /// Recycle Bin awareness and metadata.
    RecycleBin,
    /// Old downloaded installer packages and setup stubs.
    InstallerArtifacts,
    /// Application-specific temporary working data.
    AppSpecificTemp,
    /// Windows Side-by-Side (WinSxS) component store — strictly protected storage intelligence.
    WinSxSComponentStore,
}

impl RuleCategory {
    pub fn label(self) -> &'static str {
        match self {
            RuleCategory::WindowsTemp => "WINDOWS_TEMP",
            RuleCategory::UserTemp => "USER_TEMP",
            RuleCategory::BrowserCache => "BROWSER_CACHE",
            RuleCategory::ApplicationCache => "APP_CACHE",
            RuleCategory::CrashDumps => "CRASH_DUMPS",
            RuleCategory::RecycleBin => "RECYCLE_BIN",
            RuleCategory::InstallerArtifacts => "INSTALLER_ARTIFACTS",
            RuleCategory::AppSpecificTemp => "APP_SPECIFIC_TEMP",
            RuleCategory::WinSxSComponentStore => "WINSXS_COMPONENT_STORE",
        }
    }
}

/// Confidence degree of the local rule match.
///
/// Kept strictly separate from the deletion risk score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleConfidence {
    /// Low confidence heuristic pattern match.
    Low,
    /// Medium confidence match (e.g. standard known directory structure).
    Medium,
    /// High confidence match (e.g. exact path match in vendor-documented cache directory).
    High,
}

/// Structured evidence produced by a local rule match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleEvidence {
    /// Unique identifier of the rule (e.g. `"WIN_TEMP_FILE"`, `"CHROME_CACHE"`).
    pub rule_id: String,
    /// Category of the matched rule.
    pub category: RuleCategory,
    /// Path pattern or expression that matched.
    pub matched_pattern: String,
    /// Human-readable explanation of why this file matched the rule.
    pub reason: String,
    /// Confidence degree of the rule match.
    pub confidence: RuleConfidence,
    /// Potential reclaimable bytes if the item is later verified and approved for quarantine.
    pub reclaimable_size: u64,
    /// Safety considerations, caveats, or servicing recommendations.
    pub safety_implications: String,
}

impl RuleEvidence {
    /// Whether this evidence pertains to the protected WinSxS component store.
    pub fn is_winsxs(&self) -> bool {
        self.category == RuleCategory::WinSxSComponentStore
    }
}
