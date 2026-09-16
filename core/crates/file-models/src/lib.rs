//! `sc-file-models` — core data models shared across Smart Cleaner.
//!
//! These types are the contract between the scanner, the file-intelligence
//! layer, the risk engine, the safety engine, quarantine and the database.
//! They are deliberately free of platform-specific logic so every crate
//! (and its tests) can run on any OS.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Coarse class of a scanned item.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileClass {
    #[default]
    RegularFile,
    Directory,
    Symlink,
    Other,
}

/// What a file *looks like* based on extension / filename / path heuristics.
///
/// This is a working hypothesis produced by the intelligence layer — it is
/// NOT the OS's notion of file type and never overrides signature checks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    #[default]
    Unknown,
    Temp,
    Log,
    Cache,
    Backup,
    Installer,
    Media,
    Document,
    Executable,
    Library,
    Database,
    Archive,
}

/// Deletion-risk band derived from a 0..=100 score.
///
/// IMPORTANT: the score measures the risk *of deleting* the item, not how
/// "junk" it is. A ten-year-old installer and a system DLL are both judged
/// by "what happens if we remove this", never by "is this interesting".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskBand {
    VerySafe,
    Safe,
    #[default]
    Review,
    Dangerous,
    Protected,
}

impl RiskBand {
    /// Band boundaries (risk of *deletion*):
    /// 0–10 VerySafe | 11–30 Safe | 31–60 Review | 61–85 Dangerous | 86–100 Protected
    pub fn from_score(score: u16) -> Self {
        match score {
            0..=10 => RiskBand::VerySafe,
            11..=30 => RiskBand::Safe,
            31..=60 => RiskBand::Review,
            61..=85 => RiskBand::Dangerous,
            _ => RiskBand::Protected,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            RiskBand::VerySafe => "VERY_SAFE",
            RiskBand::Safe => "SAFE",
            RiskBand::Review => "REVIEW",
            RiskBand::Dangerous => "DANGEROUS",
            RiskBand::Protected => "PROTECTED",
        }
    }
}

/// One scanned item plus the signals the file-intelligence layer fills in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: PathBuf,
    pub size: u64,
    pub file_class: FileClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
    /// Unix epoch seconds (`None` when the filesystem does not expose it).
    pub created: Option<i64>,
    pub modified: i64,
    pub accessed: Option<i64>,
    pub is_hidden: bool,
    pub is_system: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,

    // ---- intelligence-layer signals (filled after discovery) ----
    /// PE header detected (.exe / .dll / .sys / .drv).
    pub is_pe: bool,
    /// Kernel driver.
    pub is_driver: bool,
    /// Valid code signature (Authenticode on Windows).
    pub is_signed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    /// Located in a protected Windows component path (System32, WinSxS, ...).
    pub is_windows_component: bool,
    /// Locked / currently used by a running process.
    pub in_use: bool,
    /// Installed application this file belongs to (software awareness).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_app: Option<String>,
    pub content_kind: ContentKind,
}

impl FileRecord {
    pub fn new(path: impl Into<PathBuf>, size: u64, modified: i64) -> Self {
        Self {
            path: path.into(),
            size,
            modified,
            ..Default::default()
        }
    }

    /// Days since the file was last touched (created or modified, whichever is newer).
    pub fn age_days(&self, now: i64) -> i64 {
        let touched = self.modified.max(self.created.unwrap_or(i64::MIN));
        (now.saturating_sub(touched) / 86_400).max(0)
    }
}

/// Output of an (optional) AI analyzer.
///
/// The AI can only *recommend*. The safety engine is the final gate and may
/// always veto; an AI signal can never grant a delete permission.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AiSignal {
    /// Where the signal came from, e.g. `"local-stub"` or `"cloud/<provider>"`.
    pub source: String,
    /// Free-form classification, e.g. `"LIKELY_JUNK"`.
    pub classification: Option<String>,
    /// 0.0 ..= 1.0
    pub confidence: f32,
    /// `"QUARANTINE"` | `"KEEP"` | `"REVIEW"` — anything else is ignored.
    pub recommendation: Option<String>,
    pub reason: Option<String>,
}

/// Current unix time in seconds (0 if the clock is broken).
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Path heuristics shared by the risk engine, the scanner and the UI.
///
/// Matching runs on a normalized, case-insensitive form of the path so it
/// behaves identically on Windows (production) and any other OS (dev/tests).
pub mod known_paths {
    use std::path::Path;

    /// Lowercase, backslash-normalized path for substring matching.
    pub fn norm(p: &Path) -> String {
        p.to_string_lossy().replace('/', "\\").to_ascii_lowercase()
    }

    fn has(p: &Path, needles: &[&str]) -> bool {
        let n = norm(p);
        needles.iter().any(|x| n.contains(x))
    }

    /// Known temporary locations.
    ///
    /// NOTE: a bare folder named `tmp` anywhere is intentionally NOT treated
    /// as a temp location — project folders use that name all the time, and
    /// misclassifying them would make their contents auto-clean candidates.
    pub fn is_temp_path(p: &Path) -> bool {
        has(
            p,
            &[
                "\\appdata\\local\\temp\\",
                "\\windows\\temp\\",
                "\\appdata\\local\\microsoft\\windows\\tmp\\",
            ],
        )
    }

    /// Cache folders of major browsers.
    ///
    /// NOTE: this intentionally matches *cache subdirectories only* — a
    /// browser profile contains cookies, passwords and history and must
    /// never be treated as cache.
    pub fn is_browser_cache_path(p: &Path) -> bool {
        const BROWSERS: &[&str] = &[
            "google\\chrome\\user data\\",
            "microsoft\\edge\\user data\\",
            "brave software\\brave-browser\\user data\\",
            "mozilla\\firefox\\profiles\\",
            "opera software\\opera",
        ];
        const CACHE_MARKERS: &[&str] = &[
            "\\cache\\",
            "cachedata",
            "code cache",
            "gpucache",
            "service worker\\",
            "storage\\",
        ];
        let n = norm(p);
        let in_browser = BROWSERS.iter().any(|b| n.contains(b));
        in_browser && CACHE_MARKERS.iter().any(|c| n.contains(c))
    }

    /// Personal user areas — deleting here means deleting the *user's* data.
    /// (`Downloads` is intentionally excluded: it is a mixed zone and is
    /// handled by content-specific rules instead.)
    pub fn is_personal_path(p: &Path) -> bool {
        has(
            p,
            &[
                "\\desktop\\",
                "\\documents\\",
                "\\pictures\\",
                "\\videos\\",
                "\\music\\",
                "\\photos\\",
            ],
        )
    }

    /// Paths that belong to the Windows OS itself and must never be touched.
    pub fn is_windows_protected_path(p: &Path) -> bool {
        let n = norm(p);
        n.starts_with("c:\\windows\\")
            || n.contains("\\winsxs\\")
            || n.contains("\\driverstore\\")
            || n.contains("\\windows\\installer\\")
            || n.contains("\\windows\\servicing\\")
            || n.contains("\\windows\\system32\\")
            || n.contains("\\windows\\syswow64\\")
            || n.contains("\\windows\\boot\\")
    }
}

/// Best-effort content-kind inference from extension + filename.
/// The intelligence layer refines this with PE/signature checks in M1.
pub fn infer_content_kind(path: &Path) -> ContentKind {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let lower = name.to_ascii_lowercase();
    let looks_like_installer = lower.contains("setup") || lower.contains("install");
    match ext.as_str() {
        "tmp" | "temp" | "dmp" | "chk" | "swp" | "old" => ContentKind::Temp,
        "log" => ContentKind::Log,
        "msi" | "msp" => ContentKind::Installer,
        "exe" => {
            if looks_like_installer {
                ContentKind::Installer
            } else {
                ContentKind::Executable
            }
        }
        "dll" | "ocx" | "cpl" | "sys" | "drv" => ContentKind::Library,
        "mp4" | "mkv" | "avi" | "mov" | "wmv" | "flv" | "webm" | "mp3" | "flac" | "wav" | "m4a"
        | "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "heic" | "tiff" | "psd" => {
            ContentKind::Media
        }
        "doc" | "docx" | "pdf" | "xls" | "xlsx" | "ppt" | "pptx" | "txt" | "md" | "odt" | "csv"
        | "rtf" => ContentKind::Document,
        "db" | "sqlite" | "sqlite3" => ContentKind::Database,
        "iso" | "zip" | "rar" | "7z" | "gz" | "tar" | "cab" => ContentKind::Archive,
        "bak" | "backup" => ContentKind::Backup,
        // Audit F2: ".dat" is deliberately NOT mapped to Cache — many .dat
        // files are app data (game saves, settings), and classifying them as
        // cache by extension alone made them auto-quarantine candidates.
        // Cache classification needs a cache-path context, not an extension.
        "cache" | "ldat" => ContentKind::Cache,
        _ => ContentKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn band_boundaries() {
        assert_eq!(RiskBand::from_score(0), RiskBand::VerySafe);
        assert_eq!(RiskBand::from_score(10), RiskBand::VerySafe);
        assert_eq!(RiskBand::from_score(11), RiskBand::Safe);
        assert_eq!(RiskBand::from_score(30), RiskBand::Safe);
        assert_eq!(RiskBand::from_score(31), RiskBand::Review);
        assert_eq!(RiskBand::from_score(60), RiskBand::Review);
        assert_eq!(RiskBand::from_score(61), RiskBand::Dangerous);
        assert_eq!(RiskBand::from_score(85), RiskBand::Dangerous);
        assert_eq!(RiskBand::from_score(86), RiskBand::Protected);
        assert_eq!(RiskBand::from_score(100), RiskBand::Protected);
    }

    #[test]
    fn known_paths_match_windows_style_paths_cross_platform() {
        assert!(known_paths::is_temp_path(Path::new(
            "C:\\Users\\Bob\\AppData\\Local\\Temp\\a.tmp"
        )));
        assert!(!known_paths::is_temp_path(Path::new(
            "C:\\Users\\Bob\\Documents\\report.txt"
        )));

        let cache = Path::new(
            "C:\\Users\\Bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\f_000001",
        );
        assert!(known_paths::is_browser_cache_path(cache));
        // A browser *profile* is not its cache — cookies/passwords live there.
        assert!(!known_paths::is_browser_cache_path(Path::new(
            "C:\\Users\\Bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"
        )));
        assert!(!known_paths::is_browser_cache_path(Path::new(
            "C:\\Users\\Bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
        )));

        assert!(known_paths::is_personal_path(Path::new(
            "C:\\Users\\Bob\\Documents\\x.docx"
        )));
        assert!(known_paths::is_personal_path(Path::new(
            "C:\\Users\\Bob\\Desktop\\shot.png"
        )));
        assert!(!known_paths::is_personal_path(Path::new(
            "C:\\Users\\Bob\\Downloads\\vs-setup.exe"
        )));

        assert!(known_paths::is_windows_protected_path(Path::new(
            "C:\\Windows\\System32\\drivers\\x.sys"
        )));
        assert!(known_paths::is_windows_protected_path(Path::new(
            "C:\\Windows\\WinSxS\\manifests\\x"
        )));
        assert!(!known_paths::is_windows_protected_path(Path::new(
            "C:\\Program Files\\App\\x.dll"
        )));
    }

    #[test]
    fn content_kind_inference() {
        assert_eq!(
            infer_content_kind(Path::new("C:\\x\\vs-setup.exe")),
            ContentKind::Installer
        );
        assert_eq!(
            infer_content_kind(Path::new("C:\\x\\chrome.dll")),
            ContentKind::Library
        );
        assert_eq!(
            infer_content_kind(Path::new("C:\\x\\video.mp4")),
            ContentKind::Media
        );
        assert_eq!(
            infer_content_kind(Path::new("C:\\x\\resume.docx")),
            ContentKind::Document
        );
        assert_eq!(
            infer_content_kind(Path::new("C:\\x\\game.iso")),
            ContentKind::Archive
        );
        assert_eq!(
            infer_content_kind(Path::new("C:\\x\\random.bin")),
            ContentKind::Unknown
        );
        // Audit F2: .dat must NOT be classified as cache by extension alone
        // (game saves, settings, ...). Cache needs a path context.
        assert_eq!(
            infer_content_kind(Path::new("D:\\Games\\GTA\\saves.dat")),
            ContentKind::Unknown
        );
    }

    #[test]
    fn age_days() {
        let r = FileRecord::new("a.txt", 10, 1_000_000);
        assert_eq!(r.age_days(1_000_000 + 3 * 86_400), 3);
        assert_eq!(r.age_days(999_000), 0);
    }
}
