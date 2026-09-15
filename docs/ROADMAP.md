# Roadmap

Per the spec's own advice (§27): **v1 has no AI cloud.** Build Scanner +
Risk Engine + Safety Engine + Quarantine + Rollback excellently first; AI is
a second-opinion layer for files the local engine cannot classify with
confidence.

## M0 — Core engine (this commit) ✅

- `sc-file-models`: shared types, path heuristics, content-kind inference
- `sc-scanner`: cross-platform Discovery Engine (quick/smart/deep modes,
  exclusions, depth budget, symlink-safe, progress callback)
- `sc-risk-engine`: 0–100 deletion-risk scoring, fully explainable factors
- `sc-safety-engine`: hard rules, verdicts, bounded AI second opinion,
  self-protection, user exclusions
- `sc-quarantine`: vault with hash-verified quarantine/restore, retention,
  force purge, self-ingestion guard
- `sc-db`: SQLite schema + audit log, exclusions, settings, software registry
- `sc-ai-gateway`: `Analyzer` trait, `LocalOnlyAnalyzer` (default),
  `CloudAnalyzer` skeleton, path sanitization
- `sc-cli`: `sc-cleaner` — reference CLI / future IPC sidecar
- Unit tests across all crates, CI on Linux + Windows

## M1 — Windows native depth

- Real drive enumeration; elevation only for protected locations (spec §1)
- `FILE_ATTRIBUTE_HIDDEN/SYSTEM`, process lock detection (in-use) (spec §3C)
- PE header + Authenticode parsing → `is_pe`, `is_signed`, `signed_by`
- Installed software registry from `Uninstall` keys → owner attribution (spec §4)
- WinSxS/DriverStore safe-walk optimization

## M2 — Desktop UI (Electron + React)

- Pages: Dashboard, Scan, Results (with *Why?*), Cleanup, Quarantine, Logs,
  Settings, Recovery (spec §15–§19, §25)
- IPC sidecar wrapping `sc-cli` operations; progress streaming
- Storage analyzer visualization + drill-down (spec §14)

## M3 — AI second opinion (optional, off by default)

- Cloud provider behind `Analyzer` trait; sanitized metadata only (spec §22)
- AI only for ambiguous (REVIEW-band) files; confidence-gated promotion

## M4 — Insights

- Duplicate detection: size → partial hash → full SHA-256,
  "Potential duplicates" only (spec §12)
- Large files intelligence, "untouched for 12 months" insights (spec §13)

## M5 — Packaging & distribution

- MSIX/NSIS installer, auto-update, optional telemetry (explicit opt-in)
