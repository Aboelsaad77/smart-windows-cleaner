//! `sc-scanner` — the Filesystem Discovery Engine (spec §2).
//!
//! The scanner only *discovers* and *reports*: Discover → Analyze → Report.
//! It never deletes anything, directly or indirectly.
//!
//! Cross-platform by design: on Windows the same walk runs against real
//! drives. Windows-specific concerns (drive enumeration, elevation, process
//! locks, attribute flags) are isolated in [`platform`] and are filled in
//! with native calls in milestone M1 (see docs/ROADMAP.md).

use sc_file_models::{infer_content_kind, known_paths, FileClass, FileRecord};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    /// Known safe junk only (temp folders, browser caches).
    Quick,
    /// Full walk of the configured roots.
    Smart,
    /// Smart + SHA-256 for files below `hash_max_size`.
    Deep,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub mode: ScanMode,
    /// Roots to walk. Empty ⇒ [`platform::default_roots`].
    pub roots: Vec<PathBuf>,
    /// Directory depth budget below each root. `0` disables the limit.
    pub max_depth: usize,
    /// Extra "never touch" prefixes, applied on top of the defaults.
    pub extra_exclusions: Vec<PathBuf>,
    /// Deep mode: hash files up to this size (bytes).
    pub hash_max_size: Option<u64>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            mode: ScanMode::Smart,
            roots: vec![],
            max_depth: 12,
            extra_exclusions: vec![],
            hash_max_size: Some(512 * 1024 * 1024),
        }
    }
}

/// Default "never touch" entries, matched by exact (case-insensitive) name
/// so they apply at any depth: recycle bins, system volume info, the
/// paging/hibernation files (spec §7, §24).
pub fn default_exclusions() -> Vec<PathBuf> {
    vec![
        PathBuf::from("$RECYCLE.BIN"),
        PathBuf::from("$Recycle.Bin"),
        PathBuf::from("System Volume Information"),
        PathBuf::from("RECYCLER"),
        PathBuf::from("pagefile.sys"),
        PathBuf::from("swapfile.sys"),
        PathBuf::from("hiberfil.sys"),
    ]
}

#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub entries: u64,
    pub files: u64,
    pub dirs: u64,
    pub skipped: u64,
    pub total_size: u64,
    pub current: PathBuf,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanError {
    pub path: PathBuf,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    pub records: Vec<FileRecord>,
    pub entries: u64,
    pub files: u64,
    pub dirs: u64,
    pub skipped: u64,
    pub total_size: u64,
    pub errors: Vec<ScanError>,
    pub elapsed_ms: u64,
}

pub struct Scanner {
    cfg: ScanConfig,
    name_excl: Vec<String>,
    prefix_excl: Vec<String>,
}

impl Scanner {
    pub fn new(cfg: ScanConfig) -> Self {
        let name_excl = default_exclusions()
            .into_iter()
            .map(|p| p.to_string_lossy().to_lowercase())
            .collect();
        let mut prefix_excl: Vec<String> = cfg
            .extra_exclusions
            .iter()
            .map(|p| known_paths::norm(p))
            .collect();
        if let Some(v) = platform::vault_root_hint() {
            let n = known_paths::norm(&v);
            if !prefix_excl.contains(&n) {
                prefix_excl.push(n);
            }
        }
        Self {
            cfg,
            name_excl,
            prefix_excl,
        }
    }

    /// Walk the configured roots and report metadata.
    ///
    /// `on_progress` is called periodically and once at the end.
    pub fn scan(&self, on_progress: &mut dyn FnMut(&ScanProgress)) -> io::Result<ScanResult> {
        let started = Instant::now();
        let roots = if self.cfg.roots.is_empty() {
            platform::default_roots()
        } else {
            self.cfg.roots.clone()
        };
        let mut result = ScanResult::default();
        let mut stack: Vec<(PathBuf, usize)> = roots.into_iter().map(|r| (r, 0)).collect();

        while let Some((dir, depth)) = stack.pop() {
            let rd = match fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(err) => {
                    // A root that cannot be read is worth reporting.
                    if depth == 0 {
                        result.errors.push(ScanError {
                            path: dir.clone(),
                            message: err.to_string(),
                        });
                    }
                    continue;
                }
            };
            for entry in rd {
                let entry = match entry {
                    Ok(e) => e,
                    Err(err) => {
                        result.errors.push(ScanError {
                            path: dir.clone(),
                            message: err.to_string(),
                        });
                        continue;
                    }
                };
                let path = entry.path();
                result.entries += 1;
                let name_s = entry.file_name().to_string_lossy().to_lowercase();
                if self.name_excluded(&name_s) || self.prefix_excluded(&path) {
                    result.skipped += 1;
                    continue;
                }
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => {
                        result.skipped += 1;
                        continue;
                    }
                };
                let ft = meta.file_type();

                if ft.is_symlink() {
                    // Record, never follow.
                    result.records.push(FileRecord {
                        path,
                        file_class: FileClass::Symlink,
                        modified: to_epoch(meta.modified()),
                        ..Default::default()
                    });
                    continue;
                }
                if ft.is_dir() {
                    result.dirs += 1;
                    result.records.push(FileRecord {
                        path: path.clone(),
                        file_class: FileClass::Directory,
                        modified: to_epoch(meta.modified()),
                        ..Default::default()
                    });
                    if self.cfg.max_depth == 0 || depth < self.cfg.max_depth {
                        stack.push((path, depth + 1));
                    }
                    continue;
                }
                // Regular file.
                let ext = path
                    .extension()
                    .map(|e| e.to_string_lossy().to_lowercase())
                    .filter(|e| !e.is_empty());
                let mut rec = FileRecord {
                    path: path.clone(),
                    size: meta.len(),
                    file_class: FileClass::RegularFile,
                    modified: to_epoch(meta.modified()),
                    created: to_opt_epoch(meta.created()),
                    accessed: to_opt_epoch(meta.accessed()),
                    extension: ext.clone(),
                    content_kind: infer_content_kind(&path),
                    is_hidden: platform::is_hidden(&path),
                    is_system: false, // M1: FILE_ATTRIBUTE_SYSTEM on Windows
                    // Conservative M0 assumption (audit F8): until M1 parses PE
                    // headers + Authenticode, PE-extension files are treated as
                    // unsigned PEs — this fails closed, so an unanalyzed binary
                    // can never score below "review".
                    is_pe: matches!(
                        ext.as_deref(),
                        Some("exe") | Some("dll") | Some("sys") | Some("drv")
                    ),
                    ..Default::default()
                };
                // Quick mode: known junk only.
                if self.cfg.mode == ScanMode::Quick
                    && !(known_paths::is_temp_path(&path)
                        || known_paths::is_browser_cache_path(&path))
                {
                    result.skipped += 1;
                    continue;
                }
                if self.cfg.mode == ScanMode::Deep {
                    if let Some(max) = self.cfg.hash_max_size {
                        if meta.len() <= max {
                            if let Ok(h) = hash_file(&path) {
                                rec.sha256 = Some(h);
                            }
                        }
                    }
                }
                result.files += 1;
                result.total_size = result.total_size.saturating_add(rec.size);
                result.records.push(rec);
            }
            if result.entries % 2048 == 0 {
                on_progress(&progress_snapshot(&result, &PathBuf::new(), started));
            }
        }

        result.elapsed_ms = started.elapsed().as_millis() as u64;
        on_progress(&progress_snapshot(&result, &PathBuf::new(), started));
        Ok(result)
    }

    fn name_excluded(&self, name_s: &str) -> bool {
        self.name_excl.iter().any(|e| e == name_s)
    }

    fn prefix_excluded(&self, path: &Path) -> bool {
        let n = known_paths::norm(path);
        self.prefix_excl.iter().any(|p| {
            let r = p.trim_end_matches('\\');
            n == r || n.starts_with(&format!("{r}\\"))
        })
    }
}

fn progress_snapshot(r: &ScanResult, current: &Path, started: Instant) -> ScanProgress {
    ScanProgress {
        entries: r.entries,
        files: r.files,
        dirs: r.dirs,
        skipped: r.skipped,
        total_size: r.total_size,
        current: current.to_path_buf(),
        elapsed_ms: started.elapsed().as_millis() as u64,
    }
}

fn to_epoch(t: io::Result<SystemTime>) -> i64 {
    t.ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn to_opt_epoch(t: io::Result<SystemTime>) -> Option<i64> {
    t.ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

fn hash_file(path: &Path) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Platform-specific bits. Everything here is a clean stub on non-Windows
/// dev machines and becomes a native call in milestone M1.
pub mod platform {
    use std::path::PathBuf;

    /// Roots used when `ScanConfig::roots` is empty.
    pub fn default_roots() -> Vec<PathBuf> {
        #[cfg(windows)]
        {
            let mut v = Vec::new();
            if let Some(home) = std::env::var_os("USERPROFILE") {
                v.push(PathBuf::from(home));
            }
            if let Some(w) = std::env::var_os("WINDIR") {
                v.push(PathBuf::from(w).join("Temp"));
            }
            v
        }
        #[cfg(not(windows))]
        {
            std::env::var_os("HOME")
                .map(|h| vec![PathBuf::from(h)])
                .unwrap_or_default()
        }
    }

    /// Where this program keeps its own vault (must never be scanned).
    pub fn vault_root_hint() -> Option<PathBuf> {
        #[cfg(windows)]
        {
            std::env::var_os("LOCALAPPDATA")
                .map(|d| PathBuf::from(d).join("SmartCleaner").join("quarantine"))
        }
        #[cfg(not(windows))]
        {
            std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join(".smart-cleaner").join("quarantine"))
        }
    }

    /// Hidden-file detection (dot-prefix here; M1: FILE_ATTRIBUTE_HIDDEN).
    pub fn is_hidden(path: &std::path::Path) -> bool {
        path.file_name()
            .map(|n| n.to_string_lossy().starts_with('.'))
            .unwrap_or(false)
    }

    /// Whether the current process runs elevated.
    /// M1: Windows token check. The app must only request elevation when a
    /// protected location is actually selected (spec §1).
    pub fn is_elevated() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_file_models::ContentKind;

    fn build_tree(tag: &str) -> PathBuf {
        // Deliberately NOT the OS temp area: the temp area itself matches the
        // temp-path heuristic on both Windows and Linux, which would pollute
        // the Quick-mode assertions. `target/` is gitignored.
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("sc-scan-tests-{tag}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("downloads")).unwrap();
        fs::create_dir_all(root.join("appdata/local/temp")).unwrap();
        fs::create_dir_all(root.join("appdata/local/microsoft/edge/user data/default/cache"))
            .unwrap();
        fs::create_dir_all(root.join("System Volume Information")).unwrap();
        fs::create_dir_all(root.join("keep-out")).unwrap();
        fs::create_dir_all(root.join("deep/a/b/c")).unwrap();
        fs::write(root.join("downloads/old-installer.exe"), b"EXE").unwrap();
        fs::write(root.join("appdata/local/temp/junk.tmp"), b"JUNK").unwrap();
        fs::write(
            root.join("appdata/local/microsoft/edge/user data/default/cache/blob"),
            b"CBLOB",
        )
        .unwrap();
        fs::write(root.join(".hiddenfile"), b"H").unwrap();
        fs::write(root.join("big.txt"), vec![b'X'; 1024]).unwrap();
        fs::write(root.join("System Volume Information/svinfo.dat"), b"S").unwrap();
        fs::write(root.join("keep-out/secret.txt"), b"K").unwrap();
        fs::write(root.join("deep/a/b/c/deep.txt"), b"D").unwrap();
        root
    }

    fn file_names(result: &ScanResult) -> Vec<String> {
        result
            .records
            .iter()
            .filter(|r| r.file_class == FileClass::RegularFile)
            .map(|r| r.path.to_string_lossy().to_string())
            .collect()
    }

    #[test]
    fn smart_scan_walks_and_reports() {
        let root = build_tree("smart");
        let scanner = Scanner::new(ScanConfig {
            roots: vec![root.clone()],
            extra_exclusions: vec![root.join("keep-out")],
            ..Default::default()
        });
        let mut progress_calls = 0;
        let result = scanner
            .scan(&mut |_p| {
                progress_calls += 1;
            })
            .unwrap();
        let names = file_names(&result);

        assert!(names.iter().any(|n| n.ends_with("old-installer.exe")));
        assert!(names.iter().any(|n| n.ends_with("junk.tmp")));
        assert!(names.iter().any(|n| n.ends_with(".hiddenfile")));
        assert!(names.iter().any(|n| n.ends_with("big.txt")));
        assert!(names.iter().any(|n| n.ends_with("deep.txt")));
        assert!(!names
            .iter()
            .any(|n| n.contains("System Volume Information")));
        assert!(!names.iter().any(|n| n.contains("keep-out")));

        let hidden = result
            .records
            .iter()
            .find(|r| {
                r.path
                    .file_name()
                    .map(|f| f == ".hiddenfile")
                    .unwrap_or(false)
            })
            .unwrap();
        assert!(hidden.is_hidden);

        let inst = result
            .records
            .iter()
            .find(|r| r.path.ends_with("old-installer.exe"))
            .unwrap();
        assert_eq!(inst.content_kind, ContentKind::Installer);
        // Audit F8: until M1 parses PE headers, PE-extension files are
        // assumed (unsigned) PEs — fails closed.
        assert!(inst.is_pe);

        assert!(progress_calls >= 1);
        assert!(result.total_size > 0);
    }

    #[test]
    fn quick_mode_only_reports_known_junk() {
        let root = build_tree("quick");
        let scanner = Scanner::new(ScanConfig {
            mode: ScanMode::Quick,
            roots: vec![root],
            ..Default::default()
        });
        let result = scanner.scan(&mut |_| {}).unwrap();
        let names = file_names(&result);
        assert!(names.iter().any(|n| n.ends_with("junk.tmp")));
        assert!(names.iter().any(|n| n.ends_with("cache/blob")));
        assert!(!names.iter().any(|n| n.ends_with("big.txt")));
        assert!(!names.iter().any(|n| n.ends_with("old-installer.exe")));
    }

    #[test]
    fn depth_budget_limits_traversal() {
        let root = build_tree("depth");
        let scanner = Scanner::new(ScanConfig {
            roots: vec![root],
            max_depth: 1,
            ..Default::default()
        });
        let result = scanner.scan(&mut |_| {}).unwrap();
        let names = file_names(&result);
        assert!(names.iter().any(|n| n.ends_with("old-installer.exe")));
        assert!(!names.iter().any(|n| n.ends_with("junk.tmp")));
        assert!(!names.iter().any(|n| n.ends_with("deep.txt")));
    }

    #[test]
    fn deep_mode_hashes_small_files() {
        let root = build_tree("deep");
        let scanner = Scanner::new(ScanConfig {
            mode: ScanMode::Deep,
            roots: vec![root],
            hash_max_size: Some(10_000),
            ..Default::default()
        });
        let result = scanner.scan(&mut |_| {}).unwrap();
        let hashed = result
            .records
            .iter()
            .filter(|r| r.file_class == FileClass::RegularFile)
            .filter(|r| r.sha256.is_some())
            .count();
        assert!(hashed > 0);
        // Known hash of b"H"
        let h = result
            .records
            .iter()
            .find(|r| {
                r.path
                    .file_name()
                    .map(|f| f == ".hiddenfile")
                    .unwrap_or(false)
            })
            .unwrap();
        assert_eq!(
            h.sha256.as_deref(),
            Some("44bd7ae60f478fae1061e11a7739f4b94d1daf917982d33b6fc8a01a63f89c21")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_recorded_not_followed() {
        let root = build_tree("symlink");
        let target = root.join("big.txt");
        std::os::unix::fs::symlink(&target, root.join("link-to-big")).unwrap();
        let scanner = Scanner::new(ScanConfig {
            roots: vec![root],
            ..Default::default()
        });
        let result = scanner.scan(&mut |_| {}).unwrap();
        let links: Vec<&FileRecord> = result
            .records
            .iter()
            .filter(|r| r.file_class == FileClass::Symlink)
            .collect();
        assert_eq!(links.len(), 1);
        let big_count = result
            .records
            .iter()
            .filter(|r| r.path.ends_with("big.txt") && r.file_class == FileClass::RegularFile)
            .count();
        assert_eq!(big_count, 1);
    }
}
