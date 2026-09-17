/**
 * Strongly-typed IPC Contract Types for Smart Cleaner Desktop UI
 * Matching docs/IPC-CONTRACT.md and core/crates/file-models/src/ipc.rs
 */

// --- Base Framing Types ---

export type RequestId = string;

export interface IpcRequest<T = unknown> {
  id: RequestId;
  action: string;
  payload: T;
}

export type ResponseStatus = 'ok' | 'error';

export interface IpcResponse<T = unknown> {
  id: RequestId;
  status: ResponseStatus;
  data?: T;
  error?: IpcError;
}

export interface IpcError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

// Well-known structured IPC Error Codes
export const IpcErrorCodes = {
  ACCESS_DENIED: 'ACCESS_DENIED',
  ELEVATION_REQUIRED: 'ELEVATION_REQUIRED',
  FILE_IN_USE: 'FILE_IN_USE',
  SOURCE_MISSING: 'SOURCE_MISSING',
  STATE_DRIFT: 'STATE_DRIFT',
  PROTECTED_ITEM: 'PROTECTED_ITEM',
  QUARANTINE_FAILED: 'QUARANTINE_FAILED',
  RESTORE_CONFLICT: 'RESTORE_CONFLICT',
  INSUFFICIENT_SPACE: 'INSUFFICIENT_SPACE',
  UNSUPPORTED_CAPABILITY: 'UNSUPPORTED_CAPABILITY',
  INTERNAL_CORE_ERROR: 'INTERNAL_CORE_ERROR',
} as const;

export type IpcErrorCode = (typeof IpcErrorCodes)[keyof typeof IpcErrorCodes] | string;

// --- Domain Models & DTOs ---

export type RiskBand = 'Safe' | 'Review' | 'Dangerous' | 'Protected';

export type SafetyVerdict = 'auto_quarantine' | 'user_confirm' | 'never_delete';

export type ScanState = 'idle' | 'scanning' | 'paused' | 'completed' | 'cancelled';

export type AttributionConfidence = 'direct_key' | 'display_name' | 'publisher_directory' | 'heuristic' | 'unknown';

export type RuleConfidence = 'high' | 'medium' | 'low';

export interface RuleEvidenceDto {
  rule_id: string;
  confidence: RuleConfidence;
  category: string;
  reclaim_estimate_bytes: number;
}

export interface RiskFactorDto {
  name: string;
  weight: number;
  reason: string;
}

export interface CandidateExplainabilityDto {
  id: string;
  path: string;
  size_bytes: number;
  category: string;
  app_owner?: string;
  app_confidence?: AttributionConfidence;
  risk_score: number;
  risk_band: RiskBand;
  risk_factors: RiskFactorDto[];
  local_rules: RuleEvidenceDto[];
  safety_verdict: SafetyVerdict;
  can_quarantine: boolean;
  allowed_reasons: string[];
  blocked_reasons: string[];
  is_pe: boolean;
  is_signed: boolean;
  is_in_use: boolean;
  is_hidden_or_system: boolean;
  selected: boolean;
}

export interface QuarantineItemDto {
  item_id: string;
  original_path: string;
  category: string;
  quarantined_size_bytes: number;
  sha256_hash: string;
  quarantined_at: string;
  retention_days: number;
  days_remaining: number;
  is_expired: boolean;
}

export interface DriveStorageDto {
  mount_point: string;
  total_bytes: number;
  free_bytes: number;
  available_bytes: number;
}

export interface WinSxsProtectionDto {
  path: string;
  is_protected: boolean;
  reason: string;
}

export interface StorageSummaryDto {
  drives: DriveStorageDto[];
  winsxs_protection: WinSxsProtectionDto;
}

export interface CategorySummaryDto {
  category: string;
  count: number;
  total_bytes: number;
  eligible_quarantine_bytes: number;
}

export interface ScanSummaryDto {
  session_id: string;
  total_files_scanned: number;
  total_candidates_found: number;
  total_reclaimable_bytes: number;
  auto_eligible_bytes: number;
  user_confirm_bytes: number;
  blocked_bytes: number;
  categories: CategorySummaryDto[];
  elapsed_ms: number;
}

export interface SystemStatusDto {
  os_version: string;
  is_elevated: boolean;
  uac_level: string;
  quarantine_vault_path: string;
  quarantine_item_count: number;
  quarantine_total_bytes: number;
}

export interface ScanStatusDto {
  state: ScanState;
  session_id?: string;
  files_scanned: number;
  candidates_found: number;
  elapsed_ms: number;
  current_path?: string;
  progress_percent?: number; // Only when exact calculation is strictly available, never fabricated
}

export interface SettingsDto {
  quarantine_retention_days: number;
  excluded_paths: string[];
  enable_deep_scan: boolean;
  auto_rescan_on_startup: boolean;
}

export interface AuditEntryDto {
  id: number;
  timestamp: string;
  operation: string;
  target_path: string;
  success: boolean;
  details?: string;
}

export interface BlockedItemDto {
  path: string;
  reason: string;
}

export interface FailedItemDto {
  path: string;
  error: string;
}

export interface QuarantineOperationResultDto {
  quarantined: QuarantineItemDto[];
  blocked: BlockedItemDto[];
  failed: FailedItemDto[];
}

export interface SelectionSummaryDto {
  selected_count: number;
  selected_bytes: number;
  can_quarantine_all: boolean;
}

export * from './updater';
export * from './licensing';

// --- Streaming Events ---

export type IpcEvent =
  | { type: 'scan_started'; session_id: string; mode: string; roots: string[]; timestamp: string }
  | {
      type: 'scan_progress';
      session_id: string;
      elapsed_ms: number;
      files_scanned: number;
      current_path: string;
      current_category: string;
      candidates_found: number;
      estimated_reclaimable_bytes: number;
    }
  | { type: 'scan_candidate_discovered'; candidate: CandidateExplainabilityDto }
  | { type: 'scan_completed'; summary: ScanSummaryDto }
  | { type: 'scan_cancelled'; session_id: string; partial_summary: ScanSummaryDto }
  | { type: 'candidate_verdict_updated'; candidate: CandidateExplainabilityDto }
  | { type: 'quarantine_started'; total_items: number }
  | { type: 'quarantine_progress'; processed: number; total: number; current_path: string }
  | { type: 'quarantine_completed'; result: QuarantineOperationResultDto }
  | { type: 'restore_completed'; item_id: string; restored_to: string }
  | { type: 'elevation_required'; reason: string; action_attempted: string }
  | { type: 'diagnostic_message'; level: 'info' | 'warn' | 'error'; message: string }
  | { type: 'updater_status_changed'; status: import('./updater').UpdateStatusDto }
  | { type: 'updater_progress'; percent: number; bytes_transferred: number; total_bytes: number }
  | { type: 'updater_error'; code: string; message: string };

// --- Request Payloads ---

export interface CandidateFilter {
  category?: string;
  risk_band?: RiskBand;
  safety_verdict?: SafetyVerdict;
}

export interface QuarantineFilter {
  expired_only?: boolean;
}

export interface AuditFilter {
  action?: string;
  since_timestamp?: number;
  limit?: number;
  offset?: number;
}

export interface StartScanCommand {
  mode: 'quick' | 'smart' | 'deep';
  roots?: string[];
}

export interface CancelScanCommand {
  session_id: string;
}

export interface SelectCandidateCommand {
  path: string;
  selected: boolean;
}

export interface SelectAllCandidatesCommand {
  filter?: CandidateFilter;
  selected: boolean;
}

export interface QuarantineSelectedCommand {
  paths: string[];
}

export interface RestoreItemCommand {
  item_id: string;
  target_path_override?: string;
}

export interface PurgeItemCommand {
  item_id: string;
}

export interface SaveSettingsCommand {
  settings: SettingsDto;
}
