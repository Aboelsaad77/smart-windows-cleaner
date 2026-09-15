# Architecture

## Layers

```text
┌────────────────────────────────────────────────────────────┐
│                    Windows Desktop UI                      │
│                 Electron + React  (M2)                     │
│   Dashboard │ Scan │ Results │ Cleanup │ Quarantine │ Logs │
└───────────────────────────┬────────────────────────────────┘
                            │ IPC / local API (sidecar)
                            ▼
┌────────────────────────────────────────────────────────────┐
│                   Native Core (Rust)                       │
│                                                            │
│  sc-scanner ──▶ sc-risk-engine ──▶ sc-safety-engine        │
│  (discovery)    (score 0–100)       (FINAL GATE)           │
│        │                │                 │                │
│        │                │          ┌──────┴───────┐        │
│        │                │          ▼              ▼        │
│        │                │      BLOCKED       QUARANTINE    │
│        │                │                        │         │
│        │                ▼                        ▼         │
│        │           sc-ai-gateway            sc-quarantine  │
│        │          (optional signal,        (vault, restore,│
│        │           never a decision)        retention)     │
│        │                                                   │
│        └──────────────────▶ sc-db (SQLite, local only)     │
│                            sc-file-models (shared types)   │
└────────────────────────────────────────────────────────────┘
```

## Decision flow (per file)

1. **Discover** — `sc-scanner` walks configured roots and records metadata only.
   It has no delete capability, by construction.
2. **Understand** — the intelligence layer fills `FileRecord` signals
   (content kind now; PE header / signature / in-use / owner-app in M1).
3. **Score** — `sc-risk-engine` computes a 0–100 *deletion risk* and records
   every contributing rule (explainability, spec §17).
4. **Decide** — `sc-safety-engine` is the final gate. Hard rules override
   everything, including AI. Output: `NeverDelete | AutoQuarantine | UserConfirm`.
5. **Act** — the only destructive action is *quarantine* (move into the vault
   with hash + metadata). Restore at any time; purge only after retention.
6. **Audit** — every action is written to the local SQLite audit log (spec §19).

## Security boundary (spec §23)

```text
AI ──recommendation──▶ Risk Engine ──▶ SAFETY ENGINE ─▶ NO  → BLOCK
                                                  │
                                                  └──▶ YES → QUARANTINE (never direct delete)
```

Invariants enforced by code (and by tests):

- The AI receives sanitized metadata only, never file content (spec §22).
- An AI signal can only promote a *Review*-band item to auto-quarantine.
  It can never unblock a hard rule and can never trigger deletion.
- The program cannot touch its own files or its vault (`SELF_PROTECTION`).
- User exclusions are absolute (`USER_EXCLUSION`).
- Unsigned PE binaries are never auto-deleted (`UnknownExecutable` rule).

## Elevation (spec §1)

The app runs in **user mode** by default and only requests elevation for the
specific protected locations the user selects (`C:\Windows`, `C:\Program Files`,
`C:\ProgramData`). `platform::is_elevated()` is the hook (native check in M1).

## UI ↔ core contract

`sc-cli` (binary `sc-cleaner`) is the reference implementation of the
operations the UI will call over IPC in M2:

| Operation | CLI today | IPC in M2 |
|---|---|---|
| Scan (quick/smart/deep) | `sc-cleaner --quick <root>` | `scan.start(mode, roots, onProgress)` |
| Assess + decide | computed per file | included in scan result |
| Quarantine item | (core API) | `quarantine.run(itemId)` |
| Restore | (core API) | `quarantine.restore(id)` |
| Audit tail | (core API) | `logs.tail(since)` |
