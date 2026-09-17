//! Installed software and application attribution data models (spec §4; Milestone M1 Component #4).
//!
//! Separates:
//! - Software catalog discovered from Windows Uninstall registry keys.
//! - Deterministic file attribution with explicit confidence levels.
//! - Informational intelligence vs safety/deletion authority (attribution alone
//!   NEVER makes a file safe to delete or bypasses the Safety Engine).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Windows registry view where the software entry was enumerated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryView {
    /// Native 64-bit registry view (`KEY_WOW64_64KEY`).
    View64Bit,
    /// 32-bit / WOW6432Node registry view (`KEY_WOW64_32KEY`).
    View32Bit,
    /// Architecture unknown or not applicable.
    #[default]
    Unknown,
}

/// Scope of software installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareScope {
    /// Machine-wide installation (`HKEY_LOCAL_MACHINE`).
    #[default]
    MachineWide,
    /// Per-user installation (`HKEY_CURRENT_USER`).
    PerUser,
}

/// Confidence of attributing a scanned file to an installed software package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionConfidence {
    /// No attribution match found.
    #[default]
    Unknown,
    /// Weak heuristic match (e.g. folder name substring match only). Not authoritative.
    WeakHeuristic,
    /// Strong structural path match (e.g. canonical vendor + app path hierarchy).
    StrongPathMatch,
    /// Executable match derived from registered uninstall executable or main binary.
    ExecutableMatch,
    /// Exact containment inside the registered `InstallLocation`.
    ExactInstallLocation,
}

impl AttributionConfidence {
    /// Whether this attribution is considered strong enough for software-aware categorization.
    pub fn is_authoritative(self) -> bool {
        matches!(
            self,
            AttributionConfidence::ExactInstallLocation
                | AttributionConfidence::ExecutableMatch
                | AttributionConfidence::StrongPathMatch
        )
    }
}

/// Application attribution result attached to a file.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SoftwareAttribution {
    /// Display name of the matched installed application.
    pub app_name: String,
    /// Publisher/vendor if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// Degree of confidence in the attribution.
    pub confidence: AttributionConfidence,
    /// Matched install root directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_location: Option<PathBuf>,
}

/// A structured record representing an installed application from the Windows Uninstall registry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SoftwareRecord {
    /// Application display name (mandatory for a valid record).
    pub display_name: String,
    /// Software publisher or company.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// Display version string (e.g. "1.2.3.4").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_version: Option<String>,
    /// Install location directory path if registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_location: Option<PathBuf>,
    /// Standard command to uninstall the application.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uninstall_string: Option<String>,
    /// Silent / quiet uninstall command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiet_uninstall_string: Option<String>,
    /// Installation date string (e.g. "YYYYMMDD").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_date: Option<String>,
    /// Estimated size in kilobytes (from `EstimatedSize` DWORD).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_size_kb: Option<u64>,
    /// Registry view / architecture (64-bit or 32-bit).
    pub architecture: RegistryView,
    /// Registry key path where this record was read.
    pub registry_source: String,
    /// Machine-wide vs per-user installation.
    pub scope: SoftwareScope,
}

impl SoftwareRecord {
    /// Normalized lowercase display name used for matching and deduplication.
    pub fn normalized_name(&self) -> String {
        self.display_name.trim().to_lowercase()
    }

    /// Merge fields from `other` into `self` when `other` represents the same application.
    pub fn merge(&mut self, other: SoftwareRecord) {
        if self.publisher.is_none() && other.publisher.is_some() {
            self.publisher = other.publisher;
        }
        if self.display_version.is_none() && other.display_version.is_some() {
            self.display_version = other.display_version;
        }
        if self.install_location.is_none() && other.install_location.is_some() {
            self.install_location = other.install_location;
        }
        if self.uninstall_string.is_none() && other.uninstall_string.is_some() {
            self.uninstall_string = other.uninstall_string;
        }
        if self.quiet_uninstall_string.is_none() && other.quiet_uninstall_string.is_some() {
            self.quiet_uninstall_string = other.quiet_uninstall_string;
        }
        if self.install_date.is_none() && other.install_date.is_some() {
            self.install_date = other.install_date;
        }
        if self.estimated_size_kb.is_none() && other.estimated_size_kb.is_some() {
            self.estimated_size_kb = other.estimated_size_kb;
        }
        // If one entry is 64-bit and the other is 32-bit, prefer native 64-bit
        if self.architecture == RegistryView::View32Bit
            && other.architecture == RegistryView::View64Bit
        {
            self.architecture = RegistryView::View64Bit;
        }
    }
}
