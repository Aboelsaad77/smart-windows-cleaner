//! `sc-file-models` — core data models shared across Smart Cleaner.
//!
//! These types are the contract between the scanner, the file-intelligence
//! layer, the risk engine, the safety engine, quarantine and the database.
//! They are deliberately free of platform-specific logic so every crate
//! (and its tests) can run on any OS.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub mod ipc;
pub mod rules;
pub mod signature;
pub mod software;

pub use ipc::*;
pub use rules::*;
pub use signature::*;
pub use software::*;

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
    pub windows_attributes: Option<WindowsAttributes>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureInfo>,
    /// Located in a protected Windows component path (System32, WinSxS, ...).
    pub is_windows_component: bool,
    /// Locked / currently used by a running process.
    pub in_use: bool,
    /// Installed application this file belongs to (software awareness).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_app: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_attribution: Option<SoftwareAttribution>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_evidences: Vec<RuleEvidence>,
    pub content_kind: ContentKind,
}

/// Windows filesystem attributes (spec §2; Milestone M1 Component #2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WindowsAttributes {
    pub raw: u32,
    pub is_readonly: bool,
    pub is_hidden: bool,
    pub is_system: bool,
    pub is_directory: bool,
    pub is_archive: bool,
    pub is_normal: bool,
    pub is_temporary: bool,
    pub is_sparse: bool,
    pub is_reparse_point: bool,
    pub is_compressed: bool,
    pub is_offline: bool,
    pub is_not_content_indexed: bool,
    pub is_encrypted: bool,
}

impl WindowsAttributes {
    pub const READONLY: u32 = 0x00000001;
    pub const HIDDEN: u32 = 0x00000002;
    pub const SYSTEM: u32 = 0x00000004;
    pub const DIRECTORY: u32 = 0x00000010;
    pub const ARCHIVE: u32 = 0x00000020;
    pub const DEVICE: u32 = 0x00000040;
    pub const NORMAL: u32 = 0x00000080;
    pub const TEMPORARY: u32 = 0x00000100;
    pub const SPARSE_FILE: u32 = 0x00000200;
    pub const REPARSE_POINT: u32 = 0x00000400;
    pub const COMPRESSED: u32 = 0x00000800;
    pub const OFFLINE: u32 = 0x00001000;
    pub const NOT_CONTENT_INDEXED: u32 = 0x00002000;
    pub const ENCRYPTED: u32 = 0x00004000;

    pub fn from_raw(raw: u32) -> Self {
        Self {
            raw,
            is_readonly: (raw & Self::READONLY) != 0,
            is_hidden: (raw & Self::HIDDEN) != 0,
            is_system: (raw & Self::SYSTEM) != 0,
            is_directory: (raw & Self::DIRECTORY) != 0,
            is_archive: (raw & Self::ARCHIVE) != 0,
            is_normal: (raw & Self::NORMAL) != 0,
            is_temporary: (raw & Self::TEMPORARY) != 0,
            is_sparse: (raw & Self::SPARSE_FILE) != 0,
            is_reparse_point: (raw & Self::REPARSE_POINT) != 0,
            is_compressed: (raw & Self::COMPRESSED) != 0,
            is_offline: (raw & Self::OFFLINE) != 0,
            is_not_content_indexed: (raw & Self::NOT_CONTENT_INDEXED) != 0,
            is_encrypted: (raw & Self::ENCRYPTED) != 0,
        }
    }
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
    ///
    /// `windir` is the normalized OS directory (e.g. `"c:\\windows"`).
    /// Windows is not guaranteed to live on C: — audit F5.
    pub fn is_windows_protected_path(p: &Path, windir: &str) -> bool {
        let n = norm(p);
        let wd_full = norm(std::path::Path::new(windir));
        let wd = wd_full.trim_end_matches('\\');
        n.starts_with(&format!("{wd}\\"))
            || n.contains("\\winsxs\\")
            || n.contains("\\driverstore\\")
            || n.contains("\\windows\\installer\\")
            || n.contains("\\windows\\servicing\\")
            || n.contains("\\windows\\system32\\")
            || n.contains("\\windows\\syswow64\\")
            || n.contains("\\windows\\boot\\")
    }
}

/// Minimal PE (Portable Executable) structure inspection (M1, spec §3A).
///
/// Cross-platform: works on raw bytes, so dev and tests run anywhere.
/// Authenticode *signature verification* needs the Windows API
/// (WinVerifyTrust) and lives in the scanner's platform layer — this module
/// only establishes "is this really a PE, and for which machine".
pub mod pe {
    /// Result of inspecting the head of a file.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct PeInfo {
        /// DOS (MZ) + `PE\0\0` headers are present: structurally a PE.
        pub is_pe: bool,
        /// COFF machine type (e.g. [`AMD64`], [`X86`]) when PE.
        pub machine: Option<u16>,
        /// Optional-header magic: PE32 (true) vs PE32+ (false) when PE.
        pub is_pe32: Option<bool>,
    }

    pub const X86: u16 = 0x014c;
    pub const AMD64: u16 = 0x8664;
    pub const ARM64: u16 = 0xaa64;

    const PE32_MAGIC: u16 = 0x010b;

    /// Inspect the first KiB(s) of a file. A short `data` slice simply
    /// reports "not (yet) verifiable" rather than erroring.
    pub fn inspect(data: &[u8]) -> PeInfo {
        let mut info = PeInfo::default();
        // DOS header: "MZ" at offset 0, e_lfanew (PE offset) at 0x3C.
        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            return info;
        }
        let pe_off = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        // The PE signature + COFF machine + optional-header magic must be
        // inside the window we were given, and at a sane offset.
        if pe_off >= 0x1000 || data.len() < pe_off + 26 {
            return info;
        }
        if &data[pe_off..pe_off + 4] != b"PE\0\0" {
            return info;
        }
        info.is_pe = true;
        info.machine = Some(u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]));
        info.is_pe32 =
            Some(u16::from_le_bytes([data[pe_off + 24], data[pe_off + 25]]) == PE32_MAGIC);
        info
    }
}

/// Best-effort content-kind inference from extension + filename.
/// The scanner refines this with PE signature checks (see [`pe`]).
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

        assert!(known_paths::is_windows_protected_path(
            Path::new("C:\\Windows\\System32\\drivers\\x.sys"),
            "c:\\windows"
        ));
        assert!(known_paths::is_windows_protected_path(
            Path::new("C:\\Windows\\WinSxS\\manifests\\x"),
            "c:\\windows"
        ));
        assert!(!known_paths::is_windows_protected_path(
            Path::new("C:\\Program Files\\App\\x.dll"),
            "c:\\windows"
        ));
        // Audit F5: the OS-drive prefix is not hardcoded to C:. A file that
        // sits directly under the windir root matches only via the prefix, so
        // it isolates the windir behavior from the drive-agnostic substrings.
        assert!(known_paths::is_windows_protected_path(
            Path::new("D:\\Windows\\bootmgr"),
            "d:\\windows"
        ));
        assert!(!known_paths::is_windows_protected_path(
            Path::new("D:\\Windows\\bootmgr"),
            "c:\\windows"
        ));
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

    // ---- M1: PE structure inspection ----

    /// Build a minimal but structurally valid PE: MZ header at 0, e_lfanew
    /// = 0x80, `PE\0\0` at 0x80, COFF machine, optional-header magic.
    fn build_pe(machine: u16, optional_magic: u16) -> Vec<u8> {
        let mut v = vec![0u8; 0x80 + 26];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        v[0x80..0x84].copy_from_slice(b"PE\0\0");
        v[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        v[0x80 + 24..0x80 + 26].copy_from_slice(&optional_magic.to_le_bytes());
        v
    }

    #[test]
    fn pe_inspect_valid_amd64() {
        let v = build_pe(pe::AMD64, 0x20b);
        let i = pe::inspect(&v);
        assert!(i.is_pe);
        assert_eq!(i.machine, Some(pe::AMD64));
        assert_eq!(i.is_pe32, Some(false));
    }

    #[test]
    fn pe_inspect_valid_x86_pe32() {
        let v = build_pe(pe::X86, 0x010b);
        let i = pe::inspect(&v);
        assert!(i.is_pe);
        assert_eq!(i.machine, Some(pe::X86));
        assert_eq!(i.is_pe32, Some(true));
    }

    #[test]
    fn pe_inspect_rejects_non_pe() {
        assert!(!pe::inspect(b"just some text, no magic at all").is_pe);
        assert!(!pe::inspect(b"").is_pe);
        assert!(!pe::inspect(b"MZ").is_pe); // too short for a DOS header
    }

    #[test]
    fn pe_inspect_rejects_mz_without_pe_signature() {
        let mut v = vec![0u8; 0x80 + 4];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // No "PE\0\0" at 0x80.
        assert!(!pe::inspect(&v).is_pe);
    }

    #[test]
    fn pe_inspect_rejects_bogus_lfanew() {
        let mut v = build_pe(pe::AMD64, 0x20b);
        // Point e_lfanew outside the window.
        v[0x3c..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(!pe::inspect(&v).is_pe);
        // And truncated right at the DOS header boundary.
        let mut short = build_pe(pe::AMD64, 0x20b);
        short.truncate(0x40);
        assert!(!pe::inspect(&short).is_pe);
    }

    #[test]
    fn windows_attributes_normal_file() {
        let attr = WindowsAttributes::from_raw(WindowsAttributes::NORMAL);
        assert!(attr.is_normal);
        assert!(!attr.is_hidden);
        assert!(!attr.is_system);
        assert_eq!(attr.raw, WindowsAttributes::NORMAL);
    }

    #[test]
    fn windows_attributes_hidden_file() {
        let attr = WindowsAttributes::from_raw(WindowsAttributes::HIDDEN);
        assert!(attr.is_hidden);
        assert!(!attr.is_system);
    }

    #[test]
    fn windows_attributes_system_flagged_file() {
        let attr = WindowsAttributes::from_raw(WindowsAttributes::SYSTEM);
        assert!(attr.is_system);
        assert!(!attr.is_hidden);
    }

    #[test]
    fn windows_attributes_both_flags() {
        let raw = WindowsAttributes::HIDDEN | WindowsAttributes::SYSTEM;
        let attr = WindowsAttributes::from_raw(raw);
        assert!(attr.is_hidden);
        assert!(attr.is_system);
    }

    #[test]
    fn windows_attributes_extensible_flags() {
        let raw = WindowsAttributes::READONLY
            | WindowsAttributes::ARCHIVE
            | WindowsAttributes::TEMPORARY
            | WindowsAttributes::REPARSE_POINT;
        let attr = WindowsAttributes::from_raw(raw);
        assert!(attr.is_readonly);
        assert!(attr.is_archive);
        assert!(attr.is_temporary);
        assert!(attr.is_reparse_point);
    }

    #[test]
    fn windows_attributes_display_formatting() {
        let attr = WindowsAttributes::from_raw(WindowsAttributes::NORMAL);
        let serialized = serde_json::to_string(&attr).unwrap();
        let deserialized: WindowsAttributes = serde_json::from_str(&serialized).unwrap();
        assert_eq!(attr, deserialized);
    }

    #[test]
    fn signature_model_unsigned_pe() {
        let s = SignatureInfo::unsigned(true);
        assert!(s.is_pe);
        assert!(s.is_unsigned());
        assert!(!s.has_signature());
    }

    #[test]
    fn signature_model_signed_valid() {
        let s = SignatureInfo::signed_valid(Some("Microsoft Corporation".into()));
        assert!(s.is_pe);
        assert!(s.is_signed_valid());
        assert!(s.has_signature());
        assert_eq!(s.signer_name.as_deref(), Some("Microsoft Corporation"));
    }

    #[test]
    fn signature_model_signed_invalid_baddigest() {
        let s = SignatureInfo::signed_invalid(
            TrustStatus::BadDigest,
            Some(0x80096010),
            "Bad digest",
            Some("Untrusted".into()),
        );
        assert!(s.is_pe);
        assert!(!s.is_signed_valid());
        assert!(s.has_signature());
        assert_eq!(s.trust_status, TrustStatus::BadDigest);
    }

    #[test]
    fn signature_model_not_pe() {
        let s = SignatureInfo::not_pe();
        assert!(!s.is_pe);
        assert_eq!(s.trust_status, TrustStatus::NotApplicable);
    }

    #[test]
    fn signature_model_unsupported_platform() {
        let s = SignatureInfo::unsupported_platform(true);
        assert_eq!(s.status, SignatureStatus::UnsupportedPlatform);
    }

    #[test]
    fn signature_model_verification_error() {
        let s = SignatureInfo::verification_error(true, Some(5), "Access denied");
        assert_eq!(s.status, SignatureStatus::VerificationError);
    }

    #[test]
    fn software_model_merge_preserves_stronger_fields() {
        let mut app1 = SoftwareRecord {
            display_name: "App".into(),
            publisher: None,
            display_version: None,
            install_location: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            install_date: None,
            estimated_size_kb: None,
            architecture: RegistryView::View32Bit,
            registry_source: "HKLM".into(),
            scope: SoftwareScope::MachineWide,
        };
        let app2 = SoftwareRecord {
            display_name: "App".into(),
            publisher: Some("Vendor".into()),
            display_version: Some("1.0.0".into()),
            install_location: Some(PathBuf::from("C:\\App")),
            uninstall_string: None,
            quiet_uninstall_string: None,
            install_date: None,
            estimated_size_kb: Some(1024),
            architecture: RegistryView::View64Bit,
            registry_source: "HKLM".into(),
            scope: SoftwareScope::MachineWide,
        };
        app1.merge(app2);
        assert_eq!(app1.publisher.as_deref(), Some("Vendor"));
        assert_eq!(app1.display_version.as_deref(), Some("1.0.0"));
        assert_eq!(app1.architecture, RegistryView::View64Bit);
    }

    #[test]
    fn attribution_confidence_ordering_and_authoritativeness() {
        assert!(
            AttributionConfidence::ExactInstallLocation > AttributionConfidence::ExecutableMatch
        );
        assert!(AttributionConfidence::ExecutableMatch > AttributionConfidence::StrongPathMatch);
        assert!(AttributionConfidence::StrongPathMatch > AttributionConfidence::WeakHeuristic);
        assert!(AttributionConfidence::WeakHeuristic > AttributionConfidence::Unknown);
    }

    #[test]
    fn ipc_request_roundtrip_command() {
        let req = IpcRequest {
            id: "cmd-1".into(),
            payload: IpcPayload::StartScan(StartScanCommand {
                mode: "smart".into(),
                roots: vec![PathBuf::from("C:\\Test")],
                extra_exclusions: vec![],
            }),
        };
        let s = serde_json::to_string(&req).unwrap();
        let parsed: IpcRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(req.id, parsed.id);
    }

    #[test]
    fn ipc_request_roundtrip_query() {
        let req = IpcRequest {
            id: "q-1".into(),
            payload: IpcPayload::GetSystemStatus,
        };
        let s = serde_json::to_string(&req).unwrap();
        let parsed: IpcRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(req.id, parsed.id);
    }

    #[test]
    fn ipc_response_error_structure() {
        let resp = IpcResponse {
            id: "cmd-1".into(),
            status: ResponseStatus::Error,
            data: None,
            error: Some(IpcError {
                code: "PERMISSION_DENIED".into(),
                message: "Elevation required".into(),
                details: None,
            }),
        };
        assert_eq!(resp.status, ResponseStatus::Error);
        assert_eq!(resp.error.unwrap().code, "PERMISSION_DENIED");
    }

    #[test]
    fn ipc_event_streaming_serialization() {
        let evt = IpcEvent::ScanProgress {
            session_id: "sess-1".into(),
            elapsed_ms: 50,
            entries_scanned: 100,
            files_scanned: 90,
            dirs_scanned: 10,
            current_path: PathBuf::from("C:\\Temp"),
            current_category: None,
            candidates_found: 5,
            estimated_reclaimable_bytes: 10240,
        };
        let s = serde_json::to_string(&evt).unwrap();
        assert!(s.contains("scan_progress"));
    }

    #[test]
    fn candidate_explainability_dto_serialization() {
        let dto = CandidateExplainabilityDto {
            name: "junk.tmp".into(),
            path: PathBuf::from("C:\\Temp\\junk.tmp"),
            size: 512,
            file_class: FileClass::RegularFile,
            extension: Some("tmp".into()),
            content_kind: ContentKind::Temp,
            owner_app: None,
            attribution_confidence: None,
            modified_at: 100,
            age_days: 1,
            is_hidden: false,
            is_system_attribute: false,
            is_pe: false,
            signature_status: SignatureStatus::Unsigned,
            signature_trust: TrustStatus::NoSignature,
            signer_name: None,
            risk_score: 5,
            risk_band: RiskBand::VerySafe,
            risk_factors: vec![],
            local_rules: vec![],
            safety_verdict: "auto_quarantine".into(),
            can_quarantine: true,
            requires_user_confirm: false,
            is_blocked: false,
            blocked_reasons: vec![],
            allowed_reasons: vec!["safe".into()],
        };
        let s = serde_json::to_string(&dto).unwrap();
        let parsed: CandidateExplainabilityDto = serde_json::from_str(&s).unwrap();
        assert_eq!(dto.path, parsed.path);
    }

    #[test]
    fn rule_category_labels_and_winsxs_evidence() {
        assert_eq!(RuleCategory::WindowsTemp.label(), "WINDOWS_TEMP");
        assert_eq!(
            RuleCategory::WinSxSComponentStore.label(),
            "WINSXS_COMPONENT_STORE"
        );
        let evidence = RuleEvidence {
            rule_id: "WINSXS_STORE".into(),
            category: RuleCategory::WinSxSComponentStore,
            matched_pattern: "*\\winsxs\\*".into(),
            reason: "Component store".into(),
            confidence: RuleConfidence::High,
            reclaimable_size: 0,
            safety_implications: "Servicing store".into(),
        };
        assert!(evidence.is_winsxs());
    }

    #[test]
    fn signature_info_has_signature_matrix() {
        assert!(SignatureInfo::signed_valid(None).has_signature());
        assert!(
            SignatureInfo::signed_invalid(TrustStatus::Expired, Some(1), "Expired", None)
                .has_signature()
        );
        let unknown = SignatureInfo {
            status: SignatureStatus::SignedUnknown,
            is_pe: true,
            trust_status: TrustStatus::UnknownTrust,
            ..Default::default()
        };
        assert!(unknown.has_signature());
        assert!(!SignatureInfo::unsigned(true).has_signature());
        assert!(!SignatureInfo::not_pe().has_signature());
    }
}
