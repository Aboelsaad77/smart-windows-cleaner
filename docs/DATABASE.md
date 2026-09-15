# Local Database (spec §21)

SQLite, on-device, single-writer. **Nothing in this database is ever
transmitted** — the AI gateway only ever sends sanitized in-memory metadata
(spec §22).

Location (planned): `%LOCALAPPDATA%\SmartCleaner\smart-cleaner.db`
(kept separate from the program files — spec §24).

DDL lives in `core/crates/db/schema.sql` and is applied idempotently at open.

## Tables

| Table | Purpose |
|---|---|
| `meta` | Schema version and KV bookkeeping |
| `scan_sessions` | One row per scan (mode, timing, totals) |
| `files` | Per-scan file snapshot (`UNIQUE(session_id, path)`) |
| `risk_assessments` | Score + band + JSON factor list (explainability history) |
| `quarantine_items` | Mirror of the vault manifest |
| `cleanup_operations` | Each cleanup action with engine + result |
| `user_exclusions` | "Never touch" list (file / folder / app scope) |
| `software` | Installed software registry (owner attribution, spec §4) |
| `ai_analysis` | AI request/response audit (sanitized payloads only) |
| `audit_logs` | Full action log for the Logs page (spec §19) |
| `settings` | App settings KV (retention, AI mode, etc.) |

## Audit log entry shape (spec §19)

```text
2026-09-15 15:20
Action:  quarantine
File:    C:\...\cache.tmp
Size:    420 MB
Risk:    low
Reason:  Application cache
Engine:  local-rules        (or ai-second-opinion)
Result:  success
```
