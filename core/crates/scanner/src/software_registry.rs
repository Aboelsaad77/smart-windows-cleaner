//! Windows Installed Software Registry Discovery & Attribution (spec §4; Milestone M1 Component #4).
//!
//! Enumerates installed software from Windows Uninstall registry keys:
//! - 64-bit native view (`KEY_WOW64_64KEY`)
//! - 32-bit / WOW6432Node view (`KEY_WOW64_32KEY`)
//! - Machine-wide (`HKEY_LOCAL_MACHINE`)
//! - Per-user (`HKEY_CURRENT_USER`)
//!
//! Features:
//! - RAII resource safety for registry handles (`RegCloseKey`)
//! - Graceful handling of missing, malformed, stale, and duplicate entries
//! - Deterministic application attribution with confidence levels
//! - Strict safety boundary: software attribution is strictly informational and
//!   NEVER bypasses the Safety Engine, preflight checks, or protected paths.
//! - Non-Windows platforms cleanly compile and provide cross-platform attribution models.

use sc_file_models::{
    AttributionConfidence, RegistryView, SoftwareAttribution, SoftwareRecord, SoftwareScope,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Common uninstall registry subkey path.
pub const UNINSTALL_REG_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

/// An error or failure encountered while querying or parsing registry data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// Key does not exist.
    KeyNotFound(String),
    /// Access denied / insufficient permissions.
    AccessDenied(String),
    /// Malformed or unparseable registry data.
    MalformedData { key: String, reason: String },
    /// System or I/O error code.
    OsError { code: u32, message: String },
    /// Unsupported platform (non-Windows).
    UnsupportedPlatform,
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::KeyNotFound(k) => write!(f, "Registry key not found: {k}"),
            RegistryError::AccessDenied(k) => write!(f, "Access denied to registry key: {k}"),
            RegistryError::MalformedData { key, reason } => {
                write!(f, "Malformed registry data at {key}: {reason}")
            }
            RegistryError::OsError { code, message } => {
                write!(f, "Registry OS error 0x{code:08X}: {message}")
            }
            RegistryError::UnsupportedPlatform => {
                write!(f, "Windows registry operations unsupported on this platform")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

/// Abstract representation of a registry value for testability and cross-platform parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryValue {
    String(String),
    Dword(u32),
    Binary(Vec<u8>),
}

/// Parse raw key-value pairs from an uninstall subkey into a structured `SoftwareRecord`.
///
/// Returns:
/// - `Ok(Some(record))` if a valid application with a `DisplayName` was parsed.
/// - `Ok(None)` if the entry is an update, component, or lacks a display name.
/// - `Err(RegistryError)` if data is corrupted or violates required formats.
pub fn parse_uninstall_entry(
    values: &HashMap<String, RegistryValue>,
    source_key: &str,
    architecture: RegistryView,
    scope: SoftwareScope,
) -> Result<Option<SoftwareRecord>, RegistryError> {
    // Entries marked as SystemComponent=1 are Windows internal components, not user applications.
    if let Some(RegistryValue::Dword(1)) = values.get("SystemComponent") {
        return Ok(None);
    }

    // Windows update packages (KB numbers / parent keys) should not be treated as standalone apps.
    if let Some(RegistryValue::Dword(1)) = values.get("WindowsInstaller") {
        // MSI apps are valid, but check if it's purely a hotfix
        if let Some(RegistryValue::String(parent)) = values.get("ParentKeyName") {
            if !parent.is_empty() {
                return Ok(None);
            }
        }
    }

    // Mandatory: DisplayName
    let display_name = match values.get("DisplayName") {
        Some(RegistryValue::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            trimmed.to_string()
        }
        Some(_) => {
            return Err(RegistryError::MalformedData {
                key: source_key.to_string(),
                reason: "DisplayName value is not a string".into(),
            });
        }
        None => return Ok(None),
    };

    let publisher = match values.get("Publisher") {
        Some(RegistryValue::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    };

    let display_version = match values.get("DisplayVersion") {
        Some(RegistryValue::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    };

    let install_location = match values.get("InstallLocation") {
        Some(RegistryValue::String(s)) => {
            let cleaned = s.trim().trim_matches('"').trim();
            if !cleaned.is_empty() {
                let p = PathBuf::from(cleaned);
                // Filter out bogus root paths like "C:\" or "C:\Program Files" directly
                if p.parent().is_some() && p.file_name().is_some() {
                    Some(p)
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    };

    let uninstall_string = match values.get("UninstallString") {
        Some(RegistryValue::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    };

    let quiet_uninstall_string = match values.get("QuietUninstallString") {
        Some(RegistryValue::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    };

    let install_date = match values.get("InstallDate") {
        Some(RegistryValue::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    };

    let estimated_size_kb = match values.get("EstimatedSize") {
        Some(RegistryValue::Dword(size)) => Some(*size as u64),
        _ => None,
    };

    Ok(Some(SoftwareRecord {
        display_name,
        publisher,
        display_version,
        install_location,
        uninstall_string,
        quiet_uninstall_string,
        install_date,
        estimated_size_kb,
        architecture,
        registry_source: source_key.to_string(),
        scope,
    }))
}

/// Deduplicate a list of software records, merging duplicate entries across registry views.
pub fn deduplicate_software(records: Vec<SoftwareRecord>) -> Vec<SoftwareRecord> {
    let mut catalog: HashMap<String, SoftwareRecord> = HashMap::new();

    for rec in records {
        let key = rec.normalized_name();
        if let Some(existing) = catalog.get_mut(&key) {
            existing.merge(rec);
        } else {
            catalog.insert(key, rec);
        }
    }

    let mut result: Vec<SoftwareRecord> = catalog.into_values().collect();
    result.sort_by_key(|a| a.display_name.to_lowercase());
    result
}

/// Catalog of installed software with fast path attribution index.
#[derive(Debug, Clone, Default)]
pub struct SoftwareCatalog {
    pub records: Vec<SoftwareRecord>,
}

impl SoftwareCatalog {
    /// Creates a new catalog from a list of records (automatically deduplicating).
    pub fn new(records: Vec<SoftwareRecord>) -> Self {
        Self {
            records: deduplicate_software(records),
        }
    }

    /// Load installed software catalog from the Windows registry.
    ///
    /// On Windows: queries HKLM and HKCU in both 64-bit and 32-bit views.
    /// On non-Windows: returns an empty catalog.
    pub fn load_system() -> Self {
        #[cfg(windows)]
        {
            let records = enumerate_windows_installed_software();
            Self::new(records)
        }
        #[cfg(not(windows))]
        {
            Self::default()
        }
    }

    /// Attribute a file path to an installed application in this catalog.
    ///
    /// Evaluates multiple signals in strict confidence priority:
    /// 1. `ExactInstallLocation`: path is inside `install_location`
    /// 2. `ExecutableMatch`: matches executable derived from uninstall string or location
    /// 3. `StrongPathMatch`: path hierarchy matches `{Publisher}/{AppName}` under standard program roots
    /// 4. `WeakHeuristic`: loose folder name substring match (never authoritative)
    pub fn attribute(&self, path: &Path) -> Option<SoftwareAttribution> {
        let norm_path_str = path.to_string_lossy().to_lowercase().replace('/', "\\");

        // Tier 1: ExactInstallLocation
        for app in &self.records {
            if let Some(install_loc) = &app.install_location {
                let loc_str = install_loc.to_string_lossy().to_lowercase().replace('/', "\\");
                let clean_loc = loc_str.trim_end_matches('\\');

                // Must be longer than a drive root or naked Program Files
                if clean_loc.len() > 10 && norm_path_str.starts_with(clean_loc) {
                    return Some(SoftwareAttribution {
                        app_name: app.display_name.clone(),
                        publisher: app.publisher.clone(),
                        confidence: AttributionConfidence::ExactInstallLocation,
                        matched_location: Some(install_loc.clone()),
                    });
                }
            }
        }

        // Tier 2: ExecutableMatch from uninstall string
        for app in &self.records {
            if let Some(cmd) = &app.uninstall_string {
                if let Some(exe_dir) = extract_executable_parent(cmd) {
                    let dir_str = exe_dir.to_string_lossy().to_lowercase().replace('/', "\\");
                    let clean_dir = dir_str.trim_end_matches('\\');
                    if clean_dir.len() > 10 && norm_path_str.starts_with(clean_dir) {
                        return Some(SoftwareAttribution {
                            app_name: app.display_name.clone(),
                            publisher: app.publisher.clone(),
                            confidence: AttributionConfidence::ExecutableMatch,
                            matched_location: Some(exe_dir),
                        });
                    }
                }
            }
        }

        // Tier 3: StrongPathMatch (structural vendor + app containment)
        for app in &self.records {
            if let Some(pub_name) = &app.publisher {
                let pub_norm = pub_name.trim().to_lowercase();
                let app_norm = app.normalized_name();
                if pub_norm.len() >= 3 && app_norm.len() >= 3 {
                    let vendor_app_segment = format!("\\{}\\{}", pub_norm, app_norm);
                    if norm_path_str.contains(&vendor_app_segment) {
                        return Some(SoftwareAttribution {
                            app_name: app.display_name.clone(),
                            publisher: Some(pub_name.clone()),
                            confidence: AttributionConfidence::StrongPathMatch,
                            matched_location: None,
                        });
                    }
                }
            }
        }

        // Tier 4: WeakHeuristic (folder name substring match)
        for app in &self.records {
            let app_norm = app.normalized_name();
            if app_norm.len() >= 4 {
                let app_dir_pattern = format!("\\{}\\", app_norm);
                if norm_path_str.contains(&app_dir_pattern) {
                    return Some(SoftwareAttribution {
                        app_name: app.display_name.clone(),
                        publisher: app.publisher.clone(),
                        confidence: AttributionConfidence::WeakHeuristic,
                        matched_location: None,
                    });
                }
            }
        }

        None
    }
}

/// Helper to parse the directory of an executable path inside a command line string.
fn extract_executable_parent(cmd: &str) -> Option<PathBuf> {
    let trimmed = cmd.trim();
    let raw_path = if let Some(after_first) = trimmed.strip_prefix('"') {
        after_first.split('"').next()?
    } else {
        trimmed.split_whitespace().next()?
    };

    let norm = raw_path.replace('/', "\\");
    let norm_lower = norm.to_lowercase();

    // System utility launchers (msiexec, rundll32, cmd, powershell) reside in
    // System32 and must NEVER be attributed as an application's install directory.
    if norm_lower.ends_with("msiexec.exe")
        || norm_lower.ends_with("rundll32.exe")
        || norm_lower.ends_with("cmd.exe")
        || norm_lower.ends_with("powershell.exe")
    {
        return None;
    }

    if norm_lower.ends_with(".exe") {
        if let Some(idx) = norm.rfind('\\') {
            let parent = &norm[..idx];
            let parent_lower = parent.to_lowercase();
            // Never attribute Windows system root directories via uninstall strings
            if !parent_lower.ends_with("\\windows\\system32")
                && !parent_lower.ends_with("\\windows\\syswow64")
                && !parent_lower.ends_with("\\windows")
            {
                return Some(PathBuf::from(parent));
            }
        }
    }
    None
}

#[cfg(windows)]
fn enumerate_windows_installed_software() -> Vec<SoftwareRecord> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::System::Registry::*;

    let mut records = Vec::new();

    // Registry search matrix:
    // (Root HKEY, Subkey, Architecture View, Scope, View Name)
    let sources = [
        // 1. HKLM 64-bit
        (
            HKEY_LOCAL_MACHINE,
            UNINSTALL_REG_KEY,
            KEY_WOW64_64KEY,
            RegistryView::View64Bit,
            SoftwareScope::MachineWide,
            "HKLM_64",
        ),
        // 2. HKLM 32-bit (WOW6432Node)
        (
            HKEY_LOCAL_MACHINE,
            UNINSTALL_REG_KEY,
            KEY_WOW64_32KEY,
            RegistryView::View32Bit,
            SoftwareScope::MachineWide,
            "HKLM_32",
        ),
        // 3. HKCU 64-bit
        (
            HKEY_CURRENT_USER,
            UNINSTALL_REG_KEY,
            KEY_WOW64_64KEY,
            RegistryView::View64Bit,
            SoftwareScope::PerUser,
            "HKCU_64",
        ),
        // 4. HKCU 32-bit (WOW6432Node)
        (
            HKEY_CURRENT_USER,
            UNINSTALL_REG_KEY,
            KEY_WOW64_32KEY,
            RegistryView::View32Bit,
            SoftwareScope::PerUser,
            "HKCU_32",
        ),
    ];

    struct RegKeyGuard(HKEY);
    impl Drop for RegKeyGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    RegCloseKey(self.0);
                }
            }
        }
    }

    for (root, subkey, wow_flag, view, scope, source_tag) in sources {
        let subkey_wide: Vec<u16> = std::ffi::OsStr::new(subkey)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut hkey: HKEY = std::ptr::null_mut();
        let status = unsafe {
            RegOpenKeyExW(
                root,
                subkey_wide.as_ptr(),
                0,
                KEY_READ | wow_flag,
                &mut hkey,
            )
        };

        if status != ERROR_SUCCESS {
            continue;
        }

        let _root_guard = RegKeyGuard(hkey);

        let mut subkey_index = 0u32;
        let mut subkey_name_buf = [0u16; 256];

        loop {
            let mut subkey_name_len = subkey_name_buf.len() as u32;
            let enum_status = unsafe {
                RegEnumKeyExW(
                    hkey,
                    subkey_index,
                    subkey_name_buf.as_mut_ptr(),
                    &mut subkey_name_len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };

            if enum_status == ERROR_NO_MORE_ITEMS {
                break;
            }

            if enum_status == ERROR_SUCCESS {
                let subkey_name = String::from_utf16_lossy(&subkey_name_buf[..subkey_name_len as usize]);
                let full_source = format!("{source_tag}\\{subkey_name}");

                // Open the specific application subkey
                let mut app_hkey: HKEY = std::ptr::null_mut();
                let app_subkey_wide: Vec<u16> = std::ffi::OsStr::new(&subkey_name)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                let open_status = unsafe {
                    RegOpenKeyExW(
                        hkey,
                        app_subkey_wide.as_ptr(),
                        0,
                        KEY_READ | wow_flag,
                        &mut app_hkey,
                    )
                };

                if open_status == ERROR_SUCCESS {
                    let _app_guard = RegKeyGuard(app_hkey);
                    let values = read_all_values(app_hkey);
                    if let Ok(Some(rec)) = parse_uninstall_entry(&values, &full_source, view, scope) {
                        records.push(rec);
                    }
                }
            }

            subkey_index = subkey_index.saturating_add(1);
        }
    }

    records
}

#[cfg(windows)]
fn read_all_values(hkey: windows_sys::Win32::System::Registry::HKEY) -> HashMap<String, RegistryValue> {
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::System::Registry::*;

    let mut map = HashMap::new();
    let mut val_index = 0u32;
    let mut val_name_buf = [0u16; 256];
    let mut data_buf = [0u8; 8192];

    loop {
        let mut val_name_len = val_name_buf.len() as u32;
        let mut val_type = 0u32;
        let mut data_len = data_buf.len() as u32;

        let status = unsafe {
            RegEnumValueW(
                hkey,
                val_index,
                val_name_buf.as_mut_ptr(),
                &mut val_name_len,
                std::ptr::null_mut(),
                &mut val_type,
                data_buf.as_mut_ptr(),
                &mut data_len,
            )
        };

        if status == ERROR_NO_MORE_ITEMS {
            break;
        }

        if status == ERROR_SUCCESS {
            let name = String::from_utf16_lossy(&val_name_buf[..val_name_len as usize]);
            let parsed_val = match val_type {
                REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ => {
                    let u16_slice = unsafe {
                        std::slice::from_raw_parts(
                            data_buf.as_ptr() as *const u16,
                            (data_len as usize) / 2,
                        )
                    };
                    // Strip null terminators
                    let trimmed = match u16_slice.iter().position(|&c| c == 0) {
                        Some(pos) => &u16_slice[..pos],
                        None => u16_slice,
                    };
                    Some(RegistryValue::String(String::from_utf16_lossy(trimmed)))
                }
                REG_DWORD => {
                    if data_len >= 4 {
                        let dword = u32::from_le_bytes(data_buf[..4].try_into().unwrap_or_default());
                        Some(RegistryValue::Dword(dword))
                    } else {
                        None
                    }
                }
                _ => None,
            };

            if let Some(val) = parsed_val {
                map.insert(name, val);
            }
        }

        val_index = val_index.saturating_add(1);
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_complete_uninstall_entry() {
        let mut values = HashMap::new();
        values.insert("DisplayName".into(), RegistryValue::String("Git".into()));
        values.insert("Publisher".into(), RegistryValue::String("The Git Development Community".into()));
        values.insert("DisplayVersion".into(), RegistryValue::String("2.44.0".into()));
        values.insert("InstallLocation".into(), RegistryValue::String("C:\\Program Files\\Git".into()));
        values.insert("UninstallString".into(), RegistryValue::String("\"C:\\Program Files\\Git\\unins000.exe\"".into()));
        values.insert("QuietUninstallString".into(), RegistryValue::String("\"C:\\Program Files\\Git\\unins000.exe\" /SILENT".into()));
        values.insert("InstallDate".into(), RegistryValue::String("20260315".into()));
        values.insert("EstimatedSize".into(), RegistryValue::Dword(350000));

        let res = parse_uninstall_entry(&values, "HKLM\\Git", RegistryView::View64Bit, SoftwareScope::MachineWide).unwrap();
        assert!(res.is_some());
        let rec = res.unwrap();
        assert_eq!(rec.display_name, "Git");
        assert_eq!(rec.publisher.as_deref(), Some("The Git Development Community"));
        assert_eq!(rec.display_version.as_deref(), Some("2.44.0"));
        assert_eq!(rec.install_location, Some(PathBuf::from("C:\\Program Files\\Git")));
        assert_eq!(rec.estimated_size_kb, Some(350000));
        assert_eq!(rec.architecture, RegistryView::View64Bit);
        assert_eq!(rec.scope, SoftwareScope::MachineWide);
    }

    #[test]
    fn parse_missing_optional_values_still_succeeds() {
        let mut values = HashMap::new();
        values.insert("DisplayName".into(), RegistryValue::String("Notepad++".into()));

        let res = parse_uninstall_entry(&values, "HKLM\\Notepad++", RegistryView::View32Bit, SoftwareScope::PerUser).unwrap();
        assert!(res.is_some());
        let rec = res.unwrap();
        assert_eq!(rec.display_name, "Notepad++");
        assert!(rec.publisher.is_none());
        assert!(rec.install_location.is_none());
        assert_eq!(rec.architecture, RegistryView::View32Bit);
        assert_eq!(rec.scope, SoftwareScope::PerUser);
    }

    #[test]
    fn parse_missing_display_name_returns_none() {
        let mut values = HashMap::new();
        values.insert("Publisher".into(), RegistryValue::String("Someone".into()));

        let res = parse_uninstall_entry(&values, "HKLM\\Unknown", RegistryView::View64Bit, SoftwareScope::MachineWide).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn parse_system_component_returns_none() {
        let mut values = HashMap::new();
        values.insert("DisplayName".into(), RegistryValue::String("Windows System Package".into()));
        values.insert("SystemComponent".into(), RegistryValue::Dword(1));

        let res = parse_uninstall_entry(&values, "HKLM\\SysPkg", RegistryView::View64Bit, SoftwareScope::MachineWide).unwrap();
        assert!(res.is_none(), "SystemComponent=1 must be skipped");
    }

    #[test]
    fn parse_malformed_display_name_fails() {
        let mut values = HashMap::new();
        values.insert("DisplayName".into(), RegistryValue::Dword(1234));

        let res = parse_uninstall_entry(&values, "HKLM\\Bad", RegistryView::View64Bit, SoftwareScope::MachineWide);
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), RegistryError::MalformedData { .. }));
    }

    #[test]
    fn deduplication_merges_32_and_64_bit_entries() {
        let rec1 = SoftwareRecord {
            display_name: "Visual Studio Code".into(),
            publisher: Some("Microsoft Corporation".into()),
            display_version: Some("1.88.0".into()),
            install_location: Some(PathBuf::from("C:\\Users\\User\\AppData\\Local\\Programs\\Microsoft VS Code")),
            architecture: RegistryView::View64Bit,
            registry_source: "HKCU_64\\VSCode".into(),
            scope: SoftwareScope::PerUser,
            ..Default::default()
        };
        let rec2 = SoftwareRecord {
            display_name: "Visual Studio Code".into(),
            publisher: None,
            display_version: Some("1.88.0".into()),
            install_location: None,
            architecture: RegistryView::View32Bit,
            registry_source: "HKCU_32\\VSCode".into(),
            scope: SoftwareScope::PerUser,
            ..Default::default()
        };

        let deduped = deduplicate_software(vec![rec1, rec2]);
        assert_eq!(deduped.len(), 1);
        let merged = &deduped[0];
        assert_eq!(merged.display_name, "Visual Studio Code");
        assert_eq!(merged.publisher.as_deref(), Some("Microsoft Corporation"));
        assert_eq!(merged.architecture, RegistryView::View64Bit);
        assert!(merged.install_location.is_some());
    }

    #[test]
    fn attribution_exact_install_location() {
        let catalog = SoftwareCatalog::new(vec![SoftwareRecord {
            display_name: "Blender".into(),
            publisher: Some("Blender Foundation".into()),
            install_location: Some(PathBuf::from("C:\\Program Files\\Blender Foundation\\Blender 4.0")),
            architecture: RegistryView::View64Bit,
            scope: SoftwareScope::MachineWide,
            ..Default::default()
        }]);

        let file = Path::new("C:\\Program Files\\Blender Foundation\\Blender 4.0\\blender.exe");
        let attr = catalog.attribute(file).expect("should attribute");
        assert_eq!(attr.app_name, "Blender");
        assert_eq!(attr.confidence, AttributionConfidence::ExactInstallLocation);
        assert!(attr.confidence.is_authoritative());
    }

    #[test]
    fn attribution_executable_match() {
        let catalog = SoftwareCatalog::new(vec![SoftwareRecord {
            display_name: "GIMP".into(),
            publisher: Some("GIMP Team".into()),
            install_location: None, // No install location registered!
            uninstall_string: Some("\"C:\\Program Files\\GIMP 2\\uninst\\unins000.exe\"".into()),
            architecture: RegistryView::View64Bit,
            scope: SoftwareScope::MachineWide,
            ..Default::default()
        }]);

        let file = Path::new("C:\\Program Files\\GIMP 2\\uninst\\unins000.dat");
        let attr = catalog.attribute(file).expect("should attribute from uninstall executable dir");
        assert_eq!(attr.app_name, "GIMP");
        assert_eq!(attr.confidence, AttributionConfidence::ExecutableMatch);
    }

    #[test]
    fn attribution_strong_path_match() {
        let catalog = SoftwareCatalog::new(vec![SoftwareRecord {
            display_name: "Slack".into(),
            publisher: Some("Slack Technologies".into()),
            install_location: None,
            architecture: RegistryView::View64Bit,
            scope: SoftwareScope::PerUser,
            ..Default::default()
        }]);

        let file = Path::new("C:\\Users\\User\\AppData\\Local\\Slack Technologies\\Slack\\app.asar");
        let attr = catalog.attribute(file).expect("should attribute via vendor + app hierarchy");
        assert_eq!(attr.app_name, "Slack");
        assert_eq!(attr.confidence, AttributionConfidence::StrongPathMatch);
    }

    #[test]
    fn attribution_weak_heuristic() {
        let catalog = SoftwareCatalog::new(vec![SoftwareRecord {
            display_name: "Audacity".into(),
            publisher: None,
            install_location: None,
            architecture: RegistryView::View64Bit,
            scope: SoftwareScope::MachineWide,
            ..Default::default()
        }]);

        let file = Path::new("D:\\Backups\\Audio\\audacity\\temp.raw");
        let attr = catalog.attribute(file).expect("should attribute weakly");
        assert_eq!(attr.app_name, "Audacity");
        assert_eq!(attr.confidence, AttributionConfidence::WeakHeuristic);
        assert!(!attr.confidence.is_authoritative());
    }

    #[test]
    fn attribution_unknown_for_unrelated_path() {
        let catalog = SoftwareCatalog::new(vec![SoftwareRecord {
            display_name: "VLC media player".into(),
            publisher: Some("VideoLAN".into()),
            install_location: Some(PathBuf::from("C:\\Program Files\\VideoLAN\\VLC")),
            architecture: RegistryView::View64Bit,
            scope: SoftwareScope::MachineWide,
            ..Default::default()
        }]);

        let file = Path::new("C:\\Users\\User\\AppData\\Local\\Temp\\random_junk.tmp");
        let attr = catalog.attribute(file);
        assert!(attr.is_none());
    }

    #[test]
    fn extract_executable_parent_filters_system_launchers() {
        assert_eq!(extract_executable_parent("MsiExec.exe /X{12345678}"), None);
        assert_eq!(
            extract_executable_parent("C:\\Windows\\System32\\msiexec.exe /I{12345678}"),
            None
        );
        assert_eq!(
            extract_executable_parent("rundll32.exe \"C:\\Program Files\\App\\app.dll\",Uninstall"),
            None
        );
        assert_eq!(
            extract_executable_parent("C:\\Windows\\System32\\cmd.exe /c del"),
            None
        );

        let valid = extract_executable_parent(
            "\"C:\\Program Files\\Vendor\\Product\\unins000.exe\" /SILENT",
        );
        assert_eq!(
            valid,
            Some(PathBuf::from("C:\\Program Files\\Vendor\\Product"))
        );
    }
}
