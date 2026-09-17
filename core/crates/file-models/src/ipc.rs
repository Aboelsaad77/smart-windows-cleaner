//! Desktop UI IPC / Local API Protocol Contract (spec §15, Milestone M3.1).
//!
//! Defines the strongly-typed message contract between the presentation layer (Desktop UI)
//! and the Rust application core.
//!
//! Architectural safety rules:
//! 1. The UI is a presentation and orchestration layer only.
//! 2. The UI NEVER executes direct filesystem deletions, direct quarantine moves,
//!    direct registry writes, or elevation calls.
//! 3. All sensitive operations flow through the Rust core:
//!    `UI -> IPC Command -> Core -> Pre-flight -> Safety Engine -> Guarded Quarantine`.
//! 4. Every destructive or mutating action returns structured outcomes with explicit
//!    error reasons; failures are never silently swallowed or collapsed.

use crate::rules::{RuleCategory, RuleConfidence};
use crate::signature::{SignatureStatus, TrustStatus};
use crate::software::AttributionConfidence;
use crate::{ContentKind, FileClass, RiskBand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Standard message envelope for IPC requests sent from Desktop UI to Rust core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcRequest {
    /// Unique request identifier for request-response correlation.
    pub id: String,
    /// Message payload (either a Query or a Command).
    pub payload: IpcPayload,
}

/// Request payloads distinguished by type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", content = "data", rename_all = "snake_case")]
pub enum IpcPayload {
    // ---- Queries ----
    GetSystemStatus,
    GetScanStatus,
    GetScanSummary,
    GetStorageSummary,
    GetCleanupCandidates(CandidateFilter),
    GetQuarantineContents(QuarantineFilter),
    GetAuditHistory(AuditFilter),
    GetSettings,
    GetApplicationCatalog,

    // ---- Commands ----
    StartScan(StartScanCommand),
    CancelScan {
        session_id: String,
    },
    RequestAnalysis {
        path: PathBuf,
    },
    SelectCandidate {
        path: PathBuf,
        selected: bool,
    },
    SelectAllCandidates {
        filter: Option<CandidateFilter>,
        selected: bool,
    },
    QuarantineSelected(QuarantineSelectedCommand),
    RestoreQuarantineItem(RestoreItemCommand),
    PurgeQuarantineItem {
        item_id: String,
    },
    Rescan,
    SaveSettings(SaveSettingsCommand),
}

/// Standard response envelope returned by Rust core to Desktop UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcResponse {
    /// Matches the `id` of the originating `IpcRequest`.
    pub id: String,
    /// Response status.
    pub status: ResponseStatus,
    /// Structured data payload if successful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Explicit error details if failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Ok,
    Error,
}

/// Detailed error returned on failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcError {
    /// Machine-readable error code.
    pub code: String,
    /// Clear human-readable error message.
    pub message: String,
    /// Additional structured context (path, os error, blocked rules).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

// ============================================================================
// Query Filters & Parameters
// ============================================================================

/// Filter and pagination criteria for querying cleanup candidates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<RuleCategory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_band: Option<RiskBand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety_verdict: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search_query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
}

/// Filter criteria for querying the quarantine vault.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search_query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
}

/// Filter criteria for querying audit logs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_timestamp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
}

// ============================================================================
// Command Payloads
// ============================================================================

/// Command to initiate a filesystem scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartScanCommand {
    /// Scan mode: Quick (known junk only), Smart (recommended), or Deep (full signature hashing).
    pub mode: String,
    /// Target scan root paths (if empty, uses default system and profile roots).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<PathBuf>,
    /// Additional exclusions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_exclusions: Vec<PathBuf>,
}

/// Command to quarantine selected candidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineSelectedCommand {
    /// List of file paths selected for quarantine.
    pub paths: Vec<PathBuf>,
    /// Explicit confirmation token ensuring user initiated the action.
    pub user_confirmed: bool,
}

/// Command to restore a quarantined file back to its original location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreItemCommand {
    /// Quarantine item UUID.
    pub item_id: String,
    /// Optional alternative restore destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_destination: Option<PathBuf>,
}

/// Command to persist application settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveSettingsCommand {
    pub default_scan_mode: String,
    pub custom_excluded_paths: Vec<PathBuf>,
    pub vault_retention_days: u32,
    pub allow_ai_second_opinion: bool,
}

// ============================================================================
// Data Transfer Objects (DTOs) for UI Presentation
// ============================================================================

/// Complete explainability and evidence for a candidate file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateExplainabilityDto {
    /// File display name.
    pub name: String,
    /// Absolute path.
    pub path: PathBuf,
    /// File size in bytes.
    pub size: u64,
    /// File class (RegularFile, Symlink, Directory).
    pub file_class: FileClass,
    /// Extension (e.g. "tmp", "cache").
    pub extension: Option<String>,
    /// Inferred content kind.
    pub content_kind: ContentKind,
    /// Attributed parent application if recognized.
    pub owner_app: Option<String>,
    /// Attribution confidence if attributed.
    pub attribution_confidence: Option<AttributionConfidence>,
    /// Unix timestamp of last modification.
    pub modified_at: i64,
    /// Age in days since modification or creation.
    pub age_days: i64,
    /// Whether file is hidden via OS attribute or dot-prefix.
    pub is_hidden: bool,
    /// Whether file has Windows SYSTEM attribute.
    pub is_system_attribute: bool,

    // ---- Signature intelligence ----
    pub is_pe: bool,
    pub signature_status: SignatureStatus,
    pub signature_trust: TrustStatus,
    pub signer_name: Option<String>,

    // ---- Risk and Local Rules ----
    pub risk_score: u16,
    pub risk_band: RiskBand,
    pub risk_factors: Vec<RiskFactorDto>,
    pub local_rules: Vec<RuleEvidenceDto>,

    // ---- Safety & Policy final determination ----
    pub safety_verdict: String,
    pub can_quarantine: bool,
    pub requires_user_confirm: bool,
    pub is_blocked: bool,
    pub blocked_reasons: Vec<String>,
    pub allowed_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskFactorDto {
    pub rule: String,
    pub delta: i16,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleEvidenceDto {
    pub rule_id: String,
    pub category: RuleCategory,
    pub matched_pattern: String,
    pub reason: String,
    pub confidence: RuleConfidence,
    pub reclaimable_size: u64,
    pub safety_implications: String,
}

/// DTO for an item stored inside the quarantine vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineItemDto {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantined_at: i64,
    pub size: u64,
    pub reason: String,
    pub risk_score: u16,
    pub risk_band: RiskBand,
    pub sha256: String,
    pub days_remaining: Option<u32>,
    pub is_intact: bool,
}

/// High-level system and elevation status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemStatusDto {
    pub is_elevated: bool,
    pub elevation_type: String,
    pub can_elevate: bool,
    pub is_admin_member: bool,
    pub os_name: String,
    pub os_version: String,
    pub vault_path: PathBuf,
    pub vault_item_count: usize,
    pub vault_total_bytes: u64,
}

/// Summary of storage drives and Windows component store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSummaryDto {
    pub drives: Vec<DriveInfoDto>,
    pub winsxs: WinSxSSummaryDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriveInfoDto {
    pub mount_point: String,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinSxSSummaryDto {
    pub detected: bool,
    pub path: PathBuf,
    pub is_protected: bool,
    pub recommendation: String,
}

/// Aggregated results from a completed scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSummaryDto {
    pub session_id: String,
    pub elapsed_ms: u64,
    pub files_scanned: u64,
    pub total_bytes_scanned: u64,
    pub total_candidates: u64,
    pub potential_reclaimable_bytes: u64,
    pub count_auto_quarantine: u64,
    pub count_user_confirm: u64,
    pub count_never_delete: u64,
    pub candidates_by_category: Vec<(String, u64, u64)>, // (Category, count, bytes)
}

/// Structured outcome of a quarantine operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineOperationResultDto {
    pub total_attempted: usize,
    pub successful_count: usize,
    pub blocked_count: usize,
    pub failed_count: usize,
    pub total_reclaimed_bytes: u64,
    pub successful_items: Vec<QuarantinedSuccessItemDto>,
    pub blocked_items: Vec<BlockedItemDto>,
    pub failed_items: Vec<FailedItemDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantinedSuccessItemDto {
    pub item_id: String,
    pub original_path: PathBuf,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedItemDto {
    pub path: PathBuf,
    pub blocked_rules: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedItemDto {
    pub path: PathBuf,
    pub error_code: String,
    pub error_message: String,
}

// ============================================================================
// Streaming Events (Core -> UI)
// ============================================================================

/// Real-time streaming events broadcast from the Rust core to the Desktop UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum IpcEvent {
    /// Scan has started.
    ScanStarted {
        session_id: String,
        mode: String,
        roots: Vec<PathBuf>,
        timestamp: i64,
    },
    /// Periodic progress report during active scan.
    ScanProgress {
        session_id: String,
        elapsed_ms: u64,
        entries_scanned: u64,
        files_scanned: u64,
        dirs_scanned: u64,
        current_path: PathBuf,
        current_category: Option<String>,
        candidates_found: u64,
        estimated_reclaimable_bytes: u64,
    },
    /// Scan completed successfully.
    ScanCompleted { summary: ScanSummaryDto },
    /// Scan cancelled by user.
    ScanCancelled {
        session_id: String,
        elapsed_ms: u64,
        files_scanned_before_cancel: u64,
    },
    /// A single candidate was discovered and classified.
    CandidateDiscovered(CandidateExplainabilityDto),
    /// Re-assessment or preflight updated a candidate's verdict.
    CandidateVerdictUpdated {
        path: PathBuf,
        old_verdict: String,
        new_verdict: String,
        reasons: Vec<String>,
    },
    /// Batch quarantine execution started.
    QuarantineStarted {
        total_items: usize,
        total_bytes: u64,
    },
    /// Progress during item-by-item quarantine execution.
    QuarantineProgress {
        current_index: usize,
        total_items: usize,
        current_path: PathBuf,
    },
    /// Batch quarantine execution completed.
    QuarantineCompleted(QuarantineOperationResultDto),
    /// An item was restored from quarantine.
    RestoreCompleted {
        item_id: String,
        restored_path: PathBuf,
        success: bool,
        error: Option<String>,
    },
    /// An operation requires elevated administrator permissions.
    ElevationRequired {
        target_path: PathBuf,
        reason: String,
        can_elevate_uac: bool,
    },
    /// Core diagnostic error or warning.
    DiagnosticMessage {
        level: String, // "info", "warning", "error"
        code: String,
        message: String,
        details: Option<serde_json::Value>,
    },
}
