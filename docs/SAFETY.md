# Safety Engine — the FINAL GATE (spec §6, §23)

The risk engine scores. The AI may second-guess. **Only the safety engine
decides.** Its output for each item is exactly one of:

| Verdict | Meaning |
|---|---|
| `NEVER_DELETE` | A hard rule fired. Nothing may be deleted, quarantined or touched. |
| `AUTO_QUARANTINE` | Low deletion risk. Eligible for one-click "clean all safe". The action is still quarantine, never direct deletion. |
| `USER_CONFIRM` | Quarantine allowed only after explicit user confirmation. |

## Hard rules (priority order)

```text
IF path under program's own root     => SELF_PROTECTION           => NEVER_DELETE
IF user-excluded root/file           => USER_EXCLUSION            => NEVER_DELETE
IF Windows-protected path            => WINDOWS_PROTECTED_PATH    => NEVER_DELETE
IF system file                       => SYSTEM_FILE               => NEVER_DELETE
IF kernel driver                     => DRIVER                    => NEVER_DELETE
IF currently in use                  => CURRENTLY_IN_USE          => NEVER_DELETE
IF signed PE binary                  => SIGNED_CRITICAL_BINARY    => NEVER_DELETE
IF risk band == PROTECTED            => PROTECTED_BAND            => NEVER_DELETE
IF unsigned PE and verdict would be  => UnknownExecutable         => demote AUTO_QUARANTINE -> USER_CONFIRM
   AUTO_QUARANTINE
```

Even if the AI said "delete it" — the safety engine says **NO** (spec §6).

## Decision after hard rules

| Risk band | Verdict |
|---|---|
| VERY_SAFE / SAFE (≤30) | `AUTO_QUARANTINE` |
| REVIEW (31–60) | `USER_CONFIRM` |
| DANGEROUS (61–85) | `USER_CONFIRM` (strong warning in UI) |
| PROTECTED (86–100) | `NEVER_DELETE` (via PROTECTED_BAND) |

## AI second opinion (bounded)

An `AiSignal` may only **promote** a `USER_CONFIRM` decision to
`AUTO_QUARANTINE` when **all** of these hold:

- `allow_ai_second_opinion` is enabled in settings (default: off in v1),
- `confidence ≥ 0.9`,
- recommendation is `QUARANTINE`,
- the band is REVIEW (never DANGEROUS or below),
- no hard rule fired.

A `KEEP` signal only adds an explanatory note. Nothing an AI says can unblock
a hard rule, promote a DANGEROUS item, or trigger any deletion (spec §23).

## Self-protection (spec §24)

`SafetyPolicy.self_root` points at the program's install directory. Any path
under it is `NEVER_DELETE`. The quarantine vault additionally refuses to
ingest anything located inside the vault itself.

## User exclusions (spec §18)

`SafetyPolicy.excluded_roots` / `excluded_files` (persisted in
`user_exclusions`, spec §21) are absolute — they beat the risk engine, the AI
and even "delete permanently now".
