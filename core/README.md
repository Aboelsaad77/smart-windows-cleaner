# Smart Cleaner — Native Core (Rust)

The native core is the **trusted** part of Smart Cleaner. The desktop UI
(Electron/React, milestone M2) is only a shell: it renders, it never decides.

| Crate | Responsibility |
|---|---|
| `sc-file-models` | Shared data models: `FileRecord`, `RiskBand`, `AiSignal`, path heuristics |
| `sc-scanner` | Filesystem Discovery Engine — Discover → Analyze → Report. Never deletes. |
| `sc-risk-engine` | Scores the **risk of deleting** each file (0–100) with explainable factors |
| `sc-safety-engine` | The FINAL GATE: hard rules override everything, including AI |
| `sc-quarantine` | Reversible-delete vault: quarantine → restore → retention → purge |
| `sc-db` | Local SQLite persistence (schema in `crates/db/schema.sql`) |
| `sc-ai-gateway` | Optional AI second-opinion layer (v1: disabled by design) |
| `sc-cli` | Thin command-line frontend (also the future sidecar contract for the UI) |

## Commands

```bash
cargo test --workspace      # run everything
cargo clippy --all-targets  # lints
cargo fmt --all             # format

# demo: quick scan of a directory
cargo run -p sc-cli -- --quick /path/to/scan
```
