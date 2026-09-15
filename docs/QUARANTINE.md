# Quarantine System (spec §9, §10, §11)

**Nothing is ever deleted directly.** Every removal is a *move* into the
Quarantine Vault. Deletion only happens later, by retention expiry or an
explicit force-purge.

```text
File ──▶ Quarantine ──▶ Wait (retention) ──▶ Permanent delete
                │
                └──▶ Restore (any time, until purged)
```

## Vault layout

```text
<vault root>/                 %LOCALAPPDATA%\SmartCleaner\quarantine (Windows)
  vault.json                  manifest: index of every item
  items/<uuid>/<name>         one directory per quarantined file
```

Each manifest entry (`QuarantineItem`):

```json
{
  "id": "8f2c…",
  "original_path": "C:\\Users\\U\\AppData\\Local\\SomeApp\\cache\\blob.tmp",
  "vault_path": "C:\\…\\SmartCleaner\\quarantine\\items\\8f2c…\\blob.tmp",
  "sha256": "…",
  "size": 123456,
  "quarantined_at": 1750000000,
  "reason": "Application cache",
  "risk_score": 8,
  "risk_band": "very_safe",
  "status": "quarantined"
}
```

`status` ∈ `quarantined | restored | purged`. Purged records stay in the
manifest for the audit trail.

## Quarantine checks

1. Source exists.
2. Source is not inside the vault (the vault cannot swallow itself).
3. Not already quarantined (per original path).
4. SHA-256 computed and stored **before** the move.

## Restore checks (spec §10), in order

1. Item exists and status = `quarantined`.
2. Vault file present.
3. **Integrity**: re-hashed file matches the stored SHA-256 (tamper ⇒ abort).
4. **Destination valid**: the original parent directory still exists.
5. **No conflict**: no file at the original path.
6. **Disk space**: free space ≥ item size.
7. Move back, then **verify the hash in place**.

Any failure aborts cleanly and leaves the item in the vault.

## Retention & permanent delete (spec §11)

Settings: `1 | 7 | 30` days or `never` (v1 default: 7).

- `purge_expired(retention_days)` runs after each cleanup and deletes items
  older than the retention window.
- "Delete permanently now" = `purge(id)` — UI must require a stronger
  confirmation (double confirm) before calling it.

## Recovery mode (spec §25)

`Settings → Recovery → Restore last cleanup` restores the items of the last
cleanup operation; `Restore All` restores everything whose status is still
`quarantined`. Items that were purged are gone by definition.
