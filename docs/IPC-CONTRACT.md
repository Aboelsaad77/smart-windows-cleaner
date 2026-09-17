# Smart Cleaner — Desktop UI IPC / API Contract Specification (M3.1)

## 1. Architectural Principles & Boundaries

1. **The Desktop UI is a Presentation and Orchestration Layer Only.**
   - The UI displays state, graphs, lists, explanations, and emits user intent commands to the Rust core.
   - The UI **never** executes filesystem deletions, moves files directly into quarantine, edits registry entries, or invokes elevation APIs.
2. **Safety Authority is Absolute in the Core:**
   - Every destructive action flows through:
     $$\text{UI Command} \longrightarrow \text{IPC Protocol} \longrightarrow \text{Core Handler} \longrightarrow \text{Pre-flight Revalidation} \longrightarrow \text{Safety Engine Gate} \longrightarrow \text{Reversible Quarantine Vault}$$
   - Even if the UI attempts to request quarantine on a blocked item, the Safety Engine and Preflight gate will reject it.
3. **Structured Outcomes & No Silent Failures:**
   - Every mutating command returns structured per-item results: `{ quarantined: [...], blocked: [...], failed: [...] }`.
   - Error reasons are specific (e.g. `SOURCE_IN_USE`, `WINDOWS_PROTECTED_PATH`, `STATE_DRIFT_DETECTED`, `TAMPERED_CHECKSUM`).
4. **Offline and Local-First:**
   - No data, telemetry, hashes, or registry catalogs are transmitted to external services or cloud APIs.

---

## 2. Message Framing & Transport

Communication between the Desktop UI (Electron/React) and the Rust Core occurs over bidirectional IPC (stdio newline-delimited JSON or named pipe):

### Request Envelope (`IpcRequest`)
```json
{
  "id": "req-1001",
  "payload": {
    "action": "get_cleanup_candidates",
    "data": {
      "category": "browser_cache",
      "limit": 50
    }
  }
}
```

### Response Envelope (`IpcResponse`)
```json
{
  "id": "req-1001",
  "status": "ok",
  "data": { ... },
  "error": null
}
```
Or on error:
```json
{
  "id": "req-1001",
  "status": "error",
  "data": null,
  "error": {
    "code": "PREFLIGHT_LOCKED",
    "message": "File is currently locked by a running process.",
    "details": {
      "path": "C:\\Users\\User\\app.log"
    }
  }
}
```

### Event Envelope (`IpcEvent`)
Unilateral notifications pushed in real-time from Rust Core to UI:
```json
{
  "event": "scan_progress",
  "data": {
    "session_id": "scan-20260916-01",
    "elapsed_ms": 2500,
    "entries_scanned": 15400,
    "files_scanned": 14200,
    "dirs_scanned": 1200,
    "current_path": "C:\\Users\\User\\AppData\\Local\\Temp",
    "current_category": "USER_TEMP",
    "candidates_found": 84,
    "estimated_reclaimable_bytes": 452984832
  }
}
```

---

## 3. Query API Specifications

| Query Action | Input Parameters | Output Data Transfer Object | Description |
| :--- | :--- | :--- | :--- |
| `get_system_status` | None | `SystemStatusDto` | Elevation state, UAC capability, OS details, vault storage stats. |
| `get_scan_status` | None | `ScanStatusDto` | Current active scan state (Idle, Scanning, Completed, Cancelled). |
| `get_scan_summary` | None | `ScanSummaryDto` | High-level metrics of last completed scan, category breakdowns. |
| `get_storage_summary`| None | `StorageSummaryDto` | Physical drive usage and WinSxS component store protection info. |
| `get_cleanup_candidates` | `CandidateFilter` | `Vec<CandidateExplainabilityDto>` | Paginated candidates with full explainability, evidence, and risk. |
| `get_quarantine_contents`| `QuarantineFilter` | `Vec<QuarantineItemDto>` | Current contents of the reversible quarantine vault. |
| `get_audit_history` | `AuditFilter` | `Vec<AuditEntryDto>` | Immutable local audit history log. |
| `get_settings` | None | `SettingsDto` | Current configured scan modes, exclusions, and retention days. |
| `get_application_catalog`| None | `Vec<SoftwareRecord>` | Discovered installed applications from 32/64-bit registry. |

---

## 4. Command API Specifications

| Command Action | Input Payload | Output Data Transfer Object | Safety & Execution Rules |
| :--- | :--- | :--- | :--- |
| `start_scan` | `StartScanCommand` | `ScanStartedDto` | Starts asynchronous background scan engine with progress streaming. |
| `cancel_scan` | `{ session_id }` | `ScanCancelledDto` | Gracefully halts directory walking without discarding partial results. |
| `request_analysis` | `{ path }` | `CandidateExplainabilityDto` | On-demand live re-evaluation of a specific file (live locks, signatures). |
| `select_candidate` | `{ path, selected }` | `SelectionSummaryDto` | Updates user selection state; rejects selecting hard-blocked items. |
| `select_all_candidates` | `{ filter, selected }` | `SelectionSummaryDto` | Bulk selection; automatically skips blocked items. |
| `quarantine_selected` | `QuarantineSelectedCommand` | `QuarantineOperationResultDto` | **Mandatory Preflight Gate**. Re-evaluates every item, rejects locks/drifts, isolates files in vault. |
| `restore_quarantine_item`| `RestoreItemCommand` | `RestoreResultDto` | Verifies SHA256 integrity, ensures destination conflict-free, restores file. |
| `purge_quarantine_item` | `{ item_id }` | `PurgeResultDto` | Permanently deletes single vault item after explicit confirmation. |
| `rescan` | None | `ScanStartedDto` | Restarts scan using existing active scan configuration. |
| `save_settings` | `SaveSettingsCommand` | `SettingsDto` | Persists user exclusions and retention parameters locally. |

---

## 5. Streaming Event Specifications

| Event Name | Payload Schema | Frequency / Trigger |
| :--- | :--- | :--- |
| `scan_started` | `{ session_id, mode, roots, timestamp }` | Emitted once when scanner initializes. |
| `scan_progress` | `{ session_id, elapsed_ms, files_scanned, current_path, ... }` | Streamed throttled at ~50–100ms intervals during scan. |
| `scan_candidate_discovered` | `CandidateExplainabilityDto` | Emitted when high-value candidate matches local rules. |
| `scan_completed` | `{ summary: ScanSummaryDto }` | Emitted once all roots traversal finishes. |
| `scan_cancelled` | `{ session_id, elapsed_ms, files_scanned }` | Emitted immediately upon cancellation confirmation. |
| `candidate_verdict_updated` | `{ path, old_verdict, new_verdict, reasons }` | Emitted if preflight or lock detector changes file state. |
| `quarantine_started` | `{ total_items, total_bytes }` | Emitted when batch quarantine execution starts. |
| `quarantine_progress` | `{ current_index, total_items, current_path }` | Emitted per item during batch move into vault. |
| `quarantine_completed` | `QuarantineOperationResultDto` | Emitted with complete audit report of success/blocked/failed. |
| `restore_completed` | `{ item_id, restored_path, success, error }` | Emitted when a vault item is restored. |
| `elevation_required` | `{ target_path, reason, can_elevate_uac }` | Emitted when target location requires Administrator token. |
| `diagnostic_message` | `{ level, code, message, details }` | Core warnings, permission blocks, or diagnostic notifications. |

---

## 6. TypeScript Interface Definitions (for Desktop UI)

```typescript
// Shared Types
export type RuleCategory =
  | 'windows_temp'
  | 'user_temp'
  | 'browser_cache'
  | 'application_cache'
  | 'crash_dumps'
  | 'recycle_bin'
  | 'installer_artifacts'
  | 'app_specific_temp'
  | 'winsxs_component_store';

export type RuleConfidence = 'high' | 'medium' | 'low';
export type RiskBand = 'very_safe' | 'safe' | 'review' | 'dangerous' | 'protected';
export type SafetyVerdict = 'auto_quarantine' | 'user_confirm' | 'never_delete';

// Candidate Explainability DTO
export interface CandidateExplainabilityDto {
  name: string;
  path: string;
  size: number;
  file_class: 'regular_file' | 'directory' | 'symlink' | 'other';
  extension?: string;
  content_kind: string;
  owner_app?: string;
  attribution_confidence?: 'exact_install_location' | 'executable_match' | 'strong_path_match' | 'weak_heuristic';
  modified_at: number;
  age_days: number;
  is_hidden: boolean;
  is_system_attribute: boolean;
  is_pe: boolean;
  signature_status: 'unsigned' | 'signed_valid' | 'signed_invalid' | 'signed_unknown' | 'verification_error';
  signature_trust: string;
  signer_name?: string;
  risk_score: number;
  risk_band: RiskBand;
  risk_factors: Array<{ rule: string; delta: number; explanation: string }>;
  local_rules: Array<{
    rule_id: string;
    category: RuleCategory;
    matched_pattern: string;
    reason: string;
    confidence: RuleConfidence;
    reclaimable_size: number;
    safety_implications: string;
  }>;
  safety_verdict: SafetyVerdict;
  can_quarantine: boolean;
  requires_user_confirm: boolean;
  is_blocked: boolean;
  blocked_reasons: string[];
  allowed_reasons: string[];
}

// Quarantine DTO
export interface QuarantineItemDto {
  id: string;
  original_path: string;
  quarantined_at: number;
  size: number;
  reason: string;
  risk_score: number;
  risk_band: RiskBand;
  sha256: string;
  days_remaining?: number;
  is_intact: boolean;
}

// System Status DTO
export interface SystemStatusDto {
  is_elevated: boolean;
  elevation_type: 'default' | 'full' | 'limited' | 'unknown';
  can_elevate: boolean;
  is_admin_member: boolean;
  os_name: string;
  os_version: string;
  vault_path: string;
  vault_item_count: number;
  vault_total_bytes: number;
}

// Quarantine Operation Result DTO
export interface QuarantineOperationResultDto {
  total_attempted: number;
  successful_count: number;
  blocked_count: number;
  failed_count: number;
  total_reclaimed_bytes: number;
  successful_items: Array<{ item_id: string; original_path: string; size: number }>;
  blocked_items: Array<{ path: string; blocked_rules: string[]; reason: string }>;
  failed_items: Array<{ path: string; error_code: string; error_message: string }>;
}
```
