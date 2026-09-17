//! Windows File Attributes (spec §2; Milestone M1 Component #2).
//!
//! Provides native querying of Windows filesystem attributes:
//! - `FILE_ATTRIBUTE_HIDDEN` (0x00000002)
//! - `FILE_ATTRIBUTE_SYSTEM` (0x00000004)
//! - plus all standard Win32 file attribute flags (readonly, archive, temporary,
//!   sparse, reparse point, compressed, offline, encrypted).
//!
//! Important safety semantics:
//! - `HIDDEN` alone does NOT mean NEVER_DELETE.
//! - `SYSTEM` alone does NOT automatically mean NEVER_DELETE.
//! - They are safety/risk signals for the intelligence and risk engines.
//! - On non-Windows platforms, returns `UnsupportedPlatform` with a safe fallback.

use sc_file_models::WindowsAttributes;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Outcome of querying Windows filesystem attributes for a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AttributeQueryResult {
    /// Native attributes were successfully retrieved from the filesystem.
    Available(WindowsAttributes),
    /// Platform is not Windows (native Windows attributes unsupported).
    UnsupportedPlatform,
    /// Query was attempted on Windows but failed (e.g. Access Denied, File Not Found, Sharing Violation).
    Failed {
        path: PathBuf,
        os_error_code: u32,
        message: String,
    },
}

impl AttributeQueryResult {
    /// Returns the underlying `WindowsAttributes` if available.
    pub fn attributes(&self) -> Option<WindowsAttributes> {
        match self {
            AttributeQueryResult::Available(a) => Some(*a),
            _ => None,
        }
    }

    /// Whether the file has `FILE_ATTRIBUTE_HIDDEN`.
    pub fn is_hidden(&self) -> bool {
        self.attributes().map(|a| a.is_hidden).unwrap_or(false)
    }

    /// Whether the file has `FILE_ATTRIBUTE_SYSTEM`.
    pub fn is_system(&self) -> bool {
        self.attributes().map(|a| a.is_system).unwrap_or(false)
    }

    /// Whether native attributes were retrieved successfully.
    pub fn is_available(&self) -> bool {
        matches!(self, AttributeQueryResult::Available(_))
    }

    /// Whether the query explicitly failed on Windows.
    pub fn is_failed(&self) -> bool {
        matches!(self, AttributeQueryResult::Failed { .. })
    }
}

/// Query native Windows attributes for `path`.
///
/// On Windows: calls `GetFileAttributesW` via `windows-sys`.
/// On non-Windows: returns `AttributeQueryResult::UnsupportedPlatform`.
pub fn query_file_attributes(path: &Path) -> AttributeQueryResult {
    #[cfg(windows)]
    {
        query_windows_file_attributes(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        AttributeQueryResult::UnsupportedPlatform
    }
}

#[cfg(windows)]
fn query_windows_file_attributes(path: &Path) -> AttributeQueryResult {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{GetFileAttributesW, INVALID_FILE_ATTRIBUTES};

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let raw = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if raw == INVALID_FILE_ATTRIBUTES {
        let err = std::io::Error::last_os_error();
        AttributeQueryResult::Failed {
            path: path.to_path_buf(),
            os_error_code: err.raw_os_error().unwrap_or(0) as u32,
            message: err.to_string(),
        }
    } else {
        AttributeQueryResult::Available(WindowsAttributes::from_raw(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_query_result_methods_normal() {
        let res =
            AttributeQueryResult::Available(WindowsAttributes::from_raw(WindowsAttributes::NORMAL));
        assert!(res.is_available());
        assert!(!res.is_failed());
        assert!(!res.is_hidden());
        assert!(!res.is_system());
        assert_eq!(res.attributes().unwrap().raw, WindowsAttributes::NORMAL);
    }

    #[test]
    fn attribute_query_result_methods_hidden() {
        let res =
            AttributeQueryResult::Available(WindowsAttributes::from_raw(WindowsAttributes::HIDDEN));
        assert!(res.is_available());
        assert!(res.is_hidden());
        assert!(!res.is_system());
    }

    #[test]
    fn attribute_query_result_methods_system() {
        let res =
            AttributeQueryResult::Available(WindowsAttributes::from_raw(WindowsAttributes::SYSTEM));
        assert!(res.is_available());
        assert!(!res.is_hidden());
        assert!(res.is_system());
    }

    #[test]
    fn attribute_query_result_methods_both_flags() {
        let raw =
            WindowsAttributes::HIDDEN | WindowsAttributes::SYSTEM | WindowsAttributes::ARCHIVE;
        let res = AttributeQueryResult::Available(WindowsAttributes::from_raw(raw));
        assert!(res.is_available());
        assert!(res.is_hidden());
        assert!(res.is_system());
        assert!(res.attributes().unwrap().is_archive);
    }

    #[test]
    fn attribute_query_result_failed_explicit_error() {
        let res = AttributeQueryResult::Failed {
            path: PathBuf::from("C:\\NonExistent\\file.tmp"),
            os_error_code: 2,
            message: "The system cannot find the file specified.".into(),
        };
        assert!(!res.is_available());
        assert!(res.is_failed());
        assert!(!res.is_hidden());
        assert!(!res.is_system());
        assert!(res.attributes().is_none());
    }

    #[test]
    fn non_windows_fallback_behavior() {
        #[cfg(not(windows))]
        {
            let res = query_file_attributes(Path::new("/tmp/some_file.txt"));
            assert_eq!(res, AttributeQueryResult::UnsupportedPlatform);
            assert!(!res.is_available());
            assert!(!res.is_failed());
            assert!(!res.is_hidden());
            assert!(!res.is_system());
        }
    }
}
