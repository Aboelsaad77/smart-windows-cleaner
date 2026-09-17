use sc_file_models::{now_secs, FileClass};
use sc_risk_engine::{assess, AssessContext};
use sc_safety_engine::{enforce, SafetyPolicy, SafetyVerdict};
use sc_scanner::{ScanConfig, ScanMode, Scanner};
use std::path::PathBuf;

pub fn run() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = if args.iter().any(|a| a == "--quick") {
        ScanMode::Quick
    } else if args.iter().any(|a| a == "--deep") {
        ScanMode::Deep
    } else {
        ScanMode::Smart
    };
    let roots: Vec<PathBuf> = args
        .iter()
        .filter(|a| !a.starts_with("--"))
        .map(PathBuf::from)
        .collect();

    let cfg = ScanConfig {
        mode,
        roots,
        ..Default::default()
    };
    let scanner = Scanner::new(cfg);
    let result = scanner
        .scan(&mut |p| {
            eprint!(
                "\r scanning… {} entries, {} files, {:.1} MiB   ",
                p.entries,
                p.files,
                p.total_size as f64 / 1024.0 / 1024.0
            );
        })
        .expect("scan failed");
    eprintln!();

    let ctx = AssessContext { now: now_secs() };
    let policy = SafetyPolicy::default();

    let (mut safe, mut review, mut blocked) = (0u64, 0u64, 0u64);
    let mut rows: Vec<(u64, String, &str, u16, &str)> = Vec::new();
    for r in &result.records {
        if r.file_class != FileClass::RegularFile {
            continue;
        }
        let a = assess(r, &ctx);
        let d = enforce(r, &a, &policy, None);
        let verdict = match d.verdict {
            SafetyVerdict::AutoQuarantine => "auto-quarantine",
            SafetyVerdict::UserConfirm => "user-confirm",
            SafetyVerdict::NeverDelete => "never-delete",
        };
        match d.verdict {
            SafetyVerdict::AutoQuarantine => safe = safe.saturating_add(r.size),
            SafetyVerdict::UserConfirm => review = review.saturating_add(r.size),
            SafetyVerdict::NeverDelete => blocked = blocked.saturating_add(r.size),
        }
        rows.push((
            r.size,
            r.path.to_string_lossy().to_string(),
            a.band.label(),
            a.score,
            verdict,
        ));
    }
    rows.sort_by_key(|r| std::cmp::Reverse(r.0));

    println!(
        "files: {}   total: {:.1} MiB   ({} errors)",
        result.files,
        result.total_size as f64 / 1024.0 / 1024.0,
        result.errors.len()
    );
    println!(
        "auto-quarantine eligible:  {:>8.1} MiB",
        safe as f64 / 1024.0 / 1024.0
    );
    println!(
        "needs user confirmation:   {:>8.1} MiB",
        review as f64 / 1024.0 / 1024.0
    );
    println!(
        "blocked (never delete):    {:>8.1} MiB",
        blocked as f64 / 1024.0 / 1024.0
    );
    println!("\ntop 20 by size:");
    println!(
        "{:>9}  {:>10} {:>4}  {:<15}  path",
        "MiB", "band", "score", "verdict"
    );
    for (size, path, band, score, verdict) in rows.iter().take(20) {
        println!(
            "{:>9.1}  {:>10} {:>4}  {:<15}  {path}",
            *size as f64 / 1024.0 / 1024.0,
            band,
            score,
            verdict
        );
    }
}
