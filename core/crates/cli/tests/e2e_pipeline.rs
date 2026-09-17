//! Deterministic End-to-End Pipeline Integration Test
//!
//! Covers the full lifecycle:
//! Scan
//!  ↓
//! Risk Assessment
//!  ↓
//! Safety Enforcement
//!  ↓
//! Pre-flight Revalidation Gate
//!  ↓
//! Guarded Quarantine
//!  ↓
//! SQLite Audit Log
//!  ↓
//! Restore / Rollback
//!
//! Verifies:
//! - Safe candidate successfully reaches quarantine.
//! - Protected candidate is blocked by safety engine.
//! - State drift before quarantine is detected and prevents automatic quarantine.
//! - In-use/locked file is blocked.
//! - Symlink/reparse-point input is rejected without touching the target.
//! - Successful quarantine creates the correct manifest entry.
//! - SHA-256/integrity remains correct through quarantine and restore.
//! - SQLite audit records are correctly written for successful and failed operations.
//! - Restore recreates the original file correctly.
//! - Failed operations leave the source untouched.
//! - Lower-level quarantine APIs cannot bypass the safety/preflight path.

use fs2::FileExt;
use sc_db::{AuditEntry, Db};
use sc_file_models::{now_secs, RiskBand};
#[cfg(unix)]
use sc_file_models::FileClass;
use sc_quarantine::{
    GuardedQuarantineError, ItemStatus, PreflightError, PreflightOptions, RequestedAction, Vault,
    VaultError,
};
use sc_risk_engine::{assess, AssessContext};
use sc_safety_engine::{enforce, SafetyPolicy, SafetyVerdict};
use sc_scanner::{ScanConfig, ScanMode, Scanner};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

/// Minimal valid PE binary bytes (AMD64)
fn minimal_pe() -> Vec<u8> {
    let mut v = vec![0u8; 0x80 + 26];
    v[0] = b'M';
    v[1] = b'Z';
    v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    v[0x80..0x84].copy_from_slice(b"PE\0\0");
    v[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    v[0x80 + 24..0x80 + 26].copy_from_slice(&0x20b_u16.to_le_bytes()); // PE32+
    v
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

struct TestEnv {
    root: PathBuf,
    scan_root: PathBuf,
    vault_root: PathBuf,
    db_path: PathBuf,
    safe_cache_file: PathBuf,
    protected_dll_file: PathBuf,
    drift_target_file: PathBuf,
    locked_file: PathBuf,
    #[allow(dead_code)]
    important_doc_file: PathBuf,
    #[allow(dead_code)]
    symlink_file: PathBuf,
    safe_content: Vec<u8>,
}

fn setup_env(tag: &str) -> TestEnv {
    let root = std::env::temp_dir().join(format!("sc-e2e-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    let scan_root = root.join("scanned_drive");
    let vault_root = root.join("quarantine_vault");
    let db_dir = root.join("db");
    fs::create_dir_all(&scan_root).unwrap();
    fs::create_dir_all(&vault_root).unwrap();
    fs::create_dir_all(&db_dir).unwrap();
    let db_path = db_dir.join("cleaner.db");

    // 1. Safe cache file in AppData\Local\Temp
    let temp_dir = scan_root.join("appdata/local/temp");
    fs::create_dir_all(&temp_dir).unwrap();
    let safe_cache_file = temp_dir.join("safe_cache.tmp");
    let safe_content = b"safe temporary application cache payload 2026".to_vec();
    fs::write(&safe_cache_file, &safe_content).unwrap();

    // 2. Protected OS binary in Windows\System32
    let sys32_dir = scan_root.join("windows/system32");
    fs::create_dir_all(&sys32_dir).unwrap();
    let protected_dll_file = sys32_dir.join("critical.dll");
    fs::write(&protected_dll_file, minimal_pe()).unwrap();

    // 3. Drift target in Downloads
    let dl_dir = scan_root.join("downloads");
    fs::create_dir_all(&dl_dir).unwrap();
    let drift_target_file = dl_dir.join("drift_target.tmp");
    fs::write(&drift_target_file, b"initial drift data").unwrap();

    // 4. Locked file in Work
    let work_dir = scan_root.join("work");
    fs::create_dir_all(&work_dir).unwrap();
    let locked_file = work_dir.join("locked_by_proc.tmp");
    fs::write(&locked_file, b"actively held by background task").unwrap();

    // 5. User document + symlink pointing to it
    let doc_dir = scan_root.join("documents");
    fs::create_dir_all(&doc_dir).unwrap();
    let important_doc_file = doc_dir.join("personal_tax_return.docx");
    fs::write(&important_doc_file, b"CONFIDENTIAL USER TAX DATA").unwrap();

    let symlink_file = scan_root.join("symlink_reparse_trap");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&important_doc_file, &symlink_file).unwrap();
    #[cfg(not(unix))]
    {
        // On non-unix test platforms where symlinks might require privs, create a placeholder
        fs::write(&symlink_file, b"symlink-placeholder").unwrap();
    }

    TestEnv {
        root,
        scan_root,
        vault_root,
        db_path,
        safe_cache_file,
        protected_dll_file,
        drift_target_file,
        locked_file,
        important_doc_file,
        symlink_file,
        safe_content,
    }
}

#[test]
fn test_end_to_end_pipeline() {
    let env = setup_env("full-pipeline");
    let db = Db::open(&env.db_path).expect("failed to open SQLite database");

    // =========================================================================
    // STEP 1: SCAN (Discovery Engine)
    // =========================================================================
    let session_id = db
        .start_scan_session("smart")
        .expect("failed to start scan session");
    assert!(session_id > 0);

    let scanner = Scanner::new(ScanConfig {
        mode: ScanMode::Smart,
        roots: vec![env.scan_root.clone()],
        ..Default::default()
    });

    let scan_result = scanner
        .scan(&mut |_| {})
        .expect("scanner discovery walk failed");
    assert!(scan_result.files >= 4, "all mock files must be found");

    // Persist discovered files in SQLite
    for r in &scan_result.records {
        db.upsert_file(session_id, r)
            .expect("failed to upsert file");
    }
    db.finish_scan_session(session_id, scan_result.files, scan_result.total_size)
        .expect("failed to finish scan session");

    // Verify symlink was recorded as a symlink and target was not duplicate-walked
    #[cfg(unix)]
    {
        let symlink_record = scan_result
            .records
            .iter()
            .find(|r| r.path == env.symlink_file)
            .expect("symlink entry must be recorded");
        assert_eq!(symlink_record.file_class, FileClass::Symlink);
    }

    // =========================================================================
    // STEP 2 & 3: RISK ASSESSMENT & SAFETY POLICY ENFORCEMENT
    // =========================================================================
    let now = now_secs();
    let ctx = AssessContext { now };
    let windir_norm = env.scan_root.join("windows").to_string_lossy().to_string();
    let policy = SafetyPolicy {
        windir: windir_norm,
        ..Default::default()
    };

    // 2.1 Safe candidate evaluation
    let safe_rec = scan_result
        .records
        .iter()
        .find(|r| r.path == env.safe_cache_file)
        .expect("safe cache file must be in scan records");
    let safe_assessment = assess(safe_rec, &ctx);
    assert!(
        safe_assessment.band <= RiskBand::Safe,
        "temp cache file deletion risk must be Safe or VerySafe (got score {})",
        safe_assessment.score
    );
    let safe_decision = enforce(safe_rec, &safe_assessment, &policy, None);
    assert_eq!(
        safe_decision.verdict,
        SafetyVerdict::AutoQuarantine,
        "clean temp file must get AutoQuarantine verdict"
    );

    // 2.2 Protected DLL candidate evaluation
    let prot_rec = scan_result
        .records
        .iter()
        .find(|r| r.path == env.protected_dll_file)
        .expect("protected DLL must be in scan records");
    let prot_assessment = assess(prot_rec, &ctx);
    let prot_decision = enforce(prot_rec, &prot_assessment, &policy, None);
    assert_eq!(
        prot_decision.verdict,
        SafetyVerdict::NeverDelete,
        "Windows critical DLL must be blocked"
    );
    assert!(
        prot_decision
            .blocked_rules
            .contains(&"WINDOWS_PROTECTED_PATH")
            || prot_decision.blocked_rules.contains(&"PROTECTED_BAND")
    );

    // Record safety block in audit log
    db.log_audit(&AuditEntry {
        action: "safety_check".into(),
        path: Some(env.protected_dll_file.to_string_lossy().to_string()),
        size: Some(prot_rec.size),
        risk: Some(prot_assessment.band.label().into()),
        reason: Some(prot_decision.blocked_rules.join(", ")),
        engine: "safety-engine".into(),
        result: "blocked".into(),
        detail: Some("Blocked by safety hard rules".into()),
    })
    .unwrap();

    // =========================================================================
    // STEP 4: PRE-FLIGHT REVALIDATION GATE & GUARDED QUARANTINE
    // =========================================================================
    let mut vault = Vault::open(env.vault_root.clone()).expect("failed to open vault");
    let expected_sha = sha256_bytes(&env.safe_content);

    // -------------------------------------------------------------------------
    // 4.1 Safe candidate: Passes Pre-flight & Enters Vault
    // -------------------------------------------------------------------------
    let safe_preflight_opts =
        PreflightOptions::new(&policy, RequestedAction::AutoQuarantine).with_expected(safe_rec);

    let (quarantined_item, preflight_outcome) = vault
        .quarantine_guarded(&env.safe_cache_file, &safe_preflight_opts)
        .expect("safe file must pass pre-flight and enter vault");

    // Verification of safe quarantine
    assert!(
        !env.safe_cache_file.exists(),
        "original file must be moved into vault"
    );
    assert!(
        quarantined_item.vault_path.is_file(),
        "file must exist inside vault"
    );
    assert_eq!(quarantined_item.status, ItemStatus::Quarantined);
    assert_eq!(
        quarantined_item.sha256, expected_sha,
        "manifest SHA-256 must match"
    );
    assert_eq!(quarantined_item.size, env.safe_content.len() as u64);
    assert_eq!(
        preflight_outcome.decision.verdict,
        SafetyVerdict::AutoQuarantine
    );
    assert_eq!(
        vault.items().len(),
        1,
        "vault manifest must contain exactly 1 item"
    );

    // Record audit and DB mirror for successful quarantine
    db.log_audit(&AuditEntry {
        action: "quarantine".into(),
        path: Some(env.safe_cache_file.to_string_lossy().to_string()),
        size: Some(quarantined_item.size),
        risk: Some(quarantined_item.risk_band.label().into()),
        reason: Some(quarantined_item.reason.clone()),
        engine: "safety-engine".into(),
        result: "success".into(),
        detail: Some(format!("Vault item id: {}", quarantined_item.id)),
    })
    .unwrap();

    db.record_quarantine(
        &quarantined_item.id,
        &quarantined_item.original_path.to_string_lossy(),
        &quarantined_item.vault_path.to_string_lossy(),
        &quarantined_item.sha256,
        quarantined_item.size,
        quarantined_item.quarantined_at,
        &quarantined_item.reason,
        quarantined_item.risk_score,
        "quarantined",
    )
    .unwrap();

    // -------------------------------------------------------------------------
    // 4.2 Protected candidate: Blocked at Pre-flight
    // -------------------------------------------------------------------------
    let prot_preflight_opts =
        PreflightOptions::new(&policy, RequestedAction::AutoQuarantine).with_expected(prot_rec);
    let prot_err = vault
        .quarantine_guarded(&env.protected_dll_file, &prot_preflight_opts)
        .expect_err("protected file must be rejected by pre-flight gate");

    match prot_err {
        GuardedQuarantineError::Preflight(PreflightError::Blocked { decision }) => {
            assert!(decision.is_blocked());
        }
        other => panic!("expected PreflightError::Blocked, got {:?}", other),
    }

    // Invariant: protected file remains completely untouched
    assert!(
        env.protected_dll_file.is_file(),
        "protected file must remain on disk"
    );
    assert_eq!(
        vault.items().len(),
        1,
        "vault must NOT ingest protected file"
    );

    db.log_audit(&AuditEntry {
        action: "quarantine".into(),
        path: Some(env.protected_dll_file.to_string_lossy().to_string()),
        size: Some(prot_rec.size),
        risk: Some(prot_assessment.band.label().into()),
        reason: Some("Blocked by safety rule WINDOWS_PROTECTED_PATH".into()),
        engine: "safety-engine".into(),
        result: "blocked".into(),
        detail: Some("Pre-flight gate prevented quarantine".into()),
    })
    .unwrap();

    // -------------------------------------------------------------------------
    // 4.3 State Drift candidate: Mutated before quarantine → Aborts
    // -------------------------------------------------------------------------
    let drift_rec = scan_result
        .records
        .iter()
        .find(|r| r.path == env.drift_target_file)
        .expect("drift target file must be in scan records");

    // Simulate time passing: another process mutates the file on disk
    fs::write(
        &env.drift_target_file,
        b"heavily modified content that changed between scan and quarantine execution",
    )
    .unwrap();

    let drift_preflight_opts =
        PreflightOptions::new(&policy, RequestedAction::AutoQuarantine).with_expected(drift_rec);
    let drift_err = vault
        .quarantine_guarded(&env.drift_target_file, &drift_preflight_opts)
        .expect_err("mutated file must be rejected by state drift check");

    match drift_err {
        GuardedQuarantineError::Preflight(PreflightError::StateDrift { path, reason }) => {
            assert_eq!(path, env.drift_target_file);
            assert!(reason.contains("size changed"), "reason was: {reason}");
        }
        other => panic!("expected PreflightError::StateDrift, got {:?}", other),
    }

    // Invariant: mutated file remains on disk untouched
    assert!(env.drift_target_file.is_file());
    assert_eq!(vault.items().len(), 1, "vault must NOT ingest drifted file");

    db.log_audit(&AuditEntry {
        action: "quarantine".into(),
        path: Some(env.drift_target_file.to_string_lossy().to_string()),
        size: Some(drift_rec.size),
        risk: Some("review".into()),
        reason: Some("State drift detected".into()),
        engine: "safety-engine".into(),
        result: "aborted_drift".into(),
        detail: Some("Size/mtime changed after scan".into()),
    })
    .unwrap();

    // -------------------------------------------------------------------------
    // 4.4 In-Use / Locked candidate: Open process lock → Blocked
    // -------------------------------------------------------------------------
    let lock_handle = fs::OpenOptions::new()
        .write(true)
        .open(&env.locked_file)
        .unwrap();
    lock_handle.lock_exclusive().unwrap();

    let lock_preflight_opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine);
    let lock_err = vault
        .quarantine_guarded(&env.locked_file, &lock_preflight_opts)
        .expect_err("locked file must be blocked by in-use probe");

    match lock_err {
        GuardedQuarantineError::Preflight(PreflightError::FileInUse(p)) => {
            assert_eq!(p, env.locked_file);
        }
        other => panic!("expected PreflightError::FileInUse, got {:?}", other),
    }

    // Invariant: locked file remains intact
    assert!(env.locked_file.is_file());
    assert_eq!(vault.items().len(), 1);

    db.log_audit(&AuditEntry {
        action: "quarantine".into(),
        path: Some(env.locked_file.to_string_lossy().to_string()),
        size: Some(17),
        risk: Some("protected".into()),
        reason: Some("File is locked/in-use".into()),
        engine: "safety-engine".into(),
        result: "blocked_in_use".into(),
        detail: Some("Active process lock detected".into()),
    })
    .unwrap();
    lock_handle.unlock().unwrap();

    // -------------------------------------------------------------------------
    // 4.5 Symlink candidate: Reparse-point input → Rejected without touching target
    // -------------------------------------------------------------------------
    #[cfg(unix)]
    {
        let symlink_opts = PreflightOptions::new(&policy, RequestedAction::AutoQuarantine);
        let symlink_err = vault
            .quarantine_guarded(&env.symlink_file, &symlink_opts)
            .expect_err("symlink must be rejected by preflight");

        match symlink_err {
            GuardedQuarantineError::Preflight(PreflightError::SymlinkBlocked(p)) => {
                assert_eq!(p, env.symlink_file);
            }
            other => panic!("expected PreflightError::SymlinkBlocked, got {:?}", other),
        }

        // Invariant: target file is 100% untouched
        assert!(
            env.important_doc_file.is_file(),
            "target document must remain untouched"
        );
        assert_eq!(
            fs::read(&env.important_doc_file).unwrap(),
            b"CONFIDENTIAL USER TAX DATA",
            "target content must be unmodified"
        );
        assert!(env.symlink_file.is_symlink());
        assert_eq!(vault.items().len(), 1);

        db.log_audit(&AuditEntry {
            action: "quarantine".into(),
            path: Some(env.symlink_file.to_string_lossy().to_string()),
            size: None,
            risk: Some("protected".into()),
            reason: Some("Symlink / reparse point traversal blocked".into()),
            engine: "safety-engine".into(),
            result: "blocked_symlink".into(),
            detail: Some("Target was preserved untouched".into()),
        })
        .unwrap();
    }

    // -------------------------------------------------------------------------
    // 4.6 Lower-level quarantine API bypass prevention
    // -------------------------------------------------------------------------
    // Attempting to call vault.quarantine(locked_file, meta) directly must still fail!
    let lock_handle2 = fs::OpenOptions::new()
        .write(true)
        .open(&env.locked_file)
        .unwrap();
    lock_handle2.lock_exclusive().unwrap();

    let meta = sc_quarantine::QuarantineMeta {
        original_path: env.locked_file.clone(),
        reason: "attempted bypass".into(),
        risk_score: 5,
        risk_band: RiskBand::VerySafe,
    };
    let bypass_err = vault
        .quarantine(&env.locked_file, meta)
        .expect_err("lower level API must enforce pre-flight revalidation");

    assert!(
        matches!(bypass_err, VaultError::PreflightBlocked(_)),
        "lower-level API must return PreflightBlocked, got {:?}",
        bypass_err
    );
    assert!(env.locked_file.is_file());
    assert_eq!(
        vault.items().len(),
        1,
        "vault manifest must not accept bypassed items"
    );
    lock_handle2.unlock().unwrap();

    db.log_audit(&AuditEntry {
        action: "quarantine".into(),
        path: Some(env.locked_file.to_string_lossy().to_string()),
        size: Some(17),
        risk: Some("very_safe".into()),
        reason: Some("Lower-level bypass blocked by pre-flight gate".into()),
        engine: "safety-engine".into(),
        result: "blocked_lower_level_bypass".into(),
        detail: Some("Direct vault.quarantine call was checked and blocked".into()),
    })
    .unwrap();

    // =========================================================================
    // STEP 5: RESTORE / ROLLBACK
    // =========================================================================
    let restored_item = vault
        .restore(&quarantined_item.id)
        .expect("restore must succeed");

    assert_eq!(restored_item.status, ItemStatus::Restored);
    assert!(
        env.safe_cache_file.is_file(),
        "file must be restored to original path"
    );

    // Verify SHA-256 and content byte-for-byte
    let restored_content = fs::read(&env.safe_cache_file).unwrap();
    assert_eq!(restored_content, env.safe_content);
    assert_eq!(sha256_bytes(&restored_content), expected_sha);

    // Record restore in SQLite audit and DB mirror
    db.log_audit(&AuditEntry {
        action: "restore".into(),
        path: Some(env.safe_cache_file.to_string_lossy().to_string()),
        size: Some(restored_item.size),
        risk: Some(restored_item.risk_band.label().into()),
        reason: Some("User requested rollback".into()),
        engine: "vault".into(),
        result: "success".into(),
        detail: Some(format!("Restored from item id {}", restored_item.id)),
    })
    .unwrap();

    db.record_quarantine(
        &restored_item.id,
        &restored_item.original_path.to_string_lossy(),
        &restored_item.vault_path.to_string_lossy(),
        &restored_item.sha256,
        restored_item.size,
        restored_item.quarantined_at,
        &restored_item.reason,
        restored_item.risk_score,
        "restored",
    )
    .unwrap();

    // =========================================================================
    // STEP 6: SQLITE AUDIT TRAIL VERIFICATION
    // =========================================================================
    let audit_rows = db.audit_since(0).expect("failed to query audit log");
    assert!(
        audit_rows.len() >= 6,
        "all lifecycle events must be logged in SQLite"
    );

    let results: Vec<String> = audit_rows.iter().map(|r| r.result.clone()).collect();
    assert!(results.contains(&"success".to_string()));
    assert!(results.contains(&"blocked".to_string()));
    assert!(results.contains(&"aborted_drift".to_string()));
    assert!(results.contains(&"blocked_in_use".to_string()));
    #[cfg(unix)]
    assert!(results.contains(&"blocked_symlink".to_string()));
    assert!(results.contains(&"blocked_lower_level_bypass".to_string()));

    // Verify scan session files in DB
    let count: i64 = db
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM files WHERE session_id = ?1",
            rusqlite::params![session_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(count >= 4);

    // Cleanup isolated temp test root
    let _ = fs::remove_dir_all(&env.root);
}
