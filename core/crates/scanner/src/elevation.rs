//! Windows Elevation and Token Detection (spec §1; Milestone M1).
//!
//! Windows permissions model:
//! - **User mode**: inspects and cleans user profile areas (`C:\Users\<user>\`:
//!   Downloads, AppData, Temp, Desktop, Documents, caches). No elevation needed.
//! - **Elevated mode**: only requested when protected system areas are selected
//!   (`C:\Windows`, `C:\ProgramData`, `C:\Program Files`, `C:\Program Files (x86)`).
//!
//! Rule: The application MUST NEVER request Administrator automatically or run
//! elevated by default. Elevation is requested on-demand only when a specific
//! operation targets a location that requires it.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{
        CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, TokenElevation,
        TokenElevationType, TokenElevationTypeDefault, TokenElevationTypeFull,
        TokenElevationTypeLimited, WinBuiltinAdministratorsSid, TOKEN_ELEVATION,
        TOKEN_ELEVATION_TYPE, TOKEN_QUERY,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

/// Classification of process token elevation under Windows UAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElevationType {
    /// Token does not have a split token (standard user account without admin rights, or UAC disabled).
    Default,
    /// Process is running with full elevated administrator privileges (elevated UAC token).
    Full,
    /// Process is running with a filtered/limited token (standard user context of an Administrator, can elevate).
    Limited,
    /// Non-Windows platform or unknown token state.
    Unknown,
}

/// Structured elevation status of the running process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElevationStatus {
    /// True if the current process is running with full elevated privileges (Administrator / root).
    pub is_elevated: bool,
    /// Detailed token elevation type (Default, Full, Limited, Unknown).
    pub elevation_type: ElevationType,
    /// True if the user account is a member of the local Administrators group
    /// (even if the current token is filtered/unelevated).
    pub is_admin_member: bool,
}

impl ElevationStatus {
    /// Inspect the current process token.
    pub fn current() -> Self {
        #[cfg(windows)]
        {
            inspect_windows_token()
        }
        #[cfg(not(windows))]
        {
            inspect_unix_credentials()
        }
    }

    /// Whether this unelevated process has the capability to elevate via UAC prompt.
    ///
    /// Returns true when running under a limited split-token or when the user is an
    /// administrator group member running unelevated.
    pub fn can_elevate(&self) -> bool {
        self.elevation_type == ElevationType::Limited || (!self.is_elevated && self.is_admin_member)
    }

    /// Evaluates whether accessing or cleaning `path` requires elevated Administrator privileges.
    ///
    /// Per spec §1:
    /// - **User mode**: paths under `C:\Users\<user>\` do not require elevation.
    /// - **Elevated mode**: `C:\Windows`, `C:\ProgramData`, `C:\Program Files`,
    ///   `C:\Program Files (x86)`, and `System Volume Information` require elevation.
    pub fn requires_elevation(path: &Path, windir: Option<&str>) -> bool {
        let p = sc_file_models::known_paths::norm(path);

        // If path is under the user profile, user mode suffices.
        if let Some(user_home) = user_profile_dir() {
            let user_norm = sc_file_models::known_paths::norm(&user_home);
            if p.starts_with(&user_norm) {
                return false;
            }
        }

        // Windows OS directory (System32, servicing, etc.)
        let win = windir.unwrap_or("c:\\windows");
        let win_norm = sc_file_models::known_paths::norm(Path::new(win));
        if p.starts_with(&win_norm) {
            return true;
        }

        // System-wide application and system directories
        if p.starts_with("c:\\program files\\")
            || p.starts_with("c:\\program files (x86)\\")
            || p.starts_with("c:\\programdata\\")
            || p.starts_with("c:\\system volume information\\")
            || p.contains("\\system volume information\\")
            || p.contains("\\$recycle.bin\\")
        {
            return true;
        }

        false
    }
}

/// Determines the elevation requirement for a specific target location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationRequirement {
    /// Operation can proceed under standard user context.
    NotRequired,
    /// Operation targets protected locations and the process is already elevated.
    AlreadyElevated,
    /// Operation targets protected locations, process is unelevated, but user CAN elevate via UAC.
    ElevationRequiredCanElevate,
    /// Operation targets protected locations, process is unelevated, and user is a standard user
    /// (cannot elevate without administrator credentials).
    ElevationRequiredNeedsCredentials,
}

/// Check the elevation requirement for an operation against `path`.
pub fn check_elevation_requirement(path: &Path, windir: Option<&str>) -> ElevationRequirement {
    let status = ElevationStatus::current();
    if !ElevationStatus::requires_elevation(path, windir) {
        ElevationRequirement::NotRequired
    } else if status.is_elevated {
        ElevationRequirement::AlreadyElevated
    } else if status.can_elevate() {
        ElevationRequirement::ElevationRequiredCanElevate
    } else {
        ElevationRequirement::ElevationRequiredNeedsCredentials
    }
}

fn user_profile_dir() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(std::path::PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(std::path::PathBuf::from)
    }
}

#[cfg(windows)]
fn inspect_windows_token() -> ElevationStatus {
    use std::mem::size_of;

    let mut token: HANDLE = std::ptr::null_mut();
    let mut is_elevated = false;
    let mut elevation_type = ElevationType::Unknown;
    let mut is_admin_member = false;

    struct TokenGuard(HANDLE);
    impl Drop for TokenGuard {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != -1_isize as HANDLE {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0 {
            let _token_guard = TokenGuard(token);
            // 1. Query TokenElevation
            let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut ret_len = 0u32;
            if GetTokenInformation(
                token,
                TokenElevation,
                &mut elev as *mut _ as *mut _,
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            ) != 0
            {
                is_elevated = elev.TokenIsElevated != 0;
            }

            // 2. Query TokenElevationType (Default, Full, Limited)
            let mut elev_type: TOKEN_ELEVATION_TYPE = 0;
            if GetTokenInformation(
                token,
                TokenElevationType,
                &mut elev_type as *mut _ as *mut _,
                size_of::<TOKEN_ELEVATION_TYPE>() as u32,
                &mut ret_len,
            ) != 0
            {
                #[allow(non_upper_case_globals)]
                let parsed = match elev_type {
                    TokenElevationTypeDefault => ElevationType::Default,
                    TokenElevationTypeFull => ElevationType::Full,
                    TokenElevationTypeLimited => ElevationType::Limited,
                    _ => ElevationType::Unknown,
                };
                elevation_type = parsed;
            }
        }

        // 3. Check if user is member of local Administrators group
        let mut admin_sid = [0u8; 68]; // SECURITY_MAX_SID_SIZE
        let mut sid_size = admin_sid.len() as u32;
        if CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            admin_sid.as_mut_ptr() as *mut _,
            &mut sid_size,
        ) != 0
        {
            let mut is_member = 0;
            if CheckTokenMembership(
                std::ptr::null_mut(),
                admin_sid.as_mut_ptr() as *mut _,
                &mut is_member,
            ) != 0
            {
                is_admin_member = is_member != 0;
            }
        }
    }

    if is_elevated {
        is_admin_member = true;
    }

    ElevationStatus {
        is_elevated,
        elevation_type,
        is_admin_member,
    }
}

#[cfg(not(windows))]
fn inspect_unix_credentials() -> ElevationStatus {
    // Non-Windows stub: root is euid 0
    let euid = unsafe { libc::geteuid() };
    let is_elevated = euid == 0;
    let elevation_type = if is_elevated {
        ElevationType::Full
    } else {
        ElevationType::Default
    };

    ElevationStatus {
        is_elevated,
        elevation_type,
        is_admin_member: is_elevated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn elevation_status_current_returns_valid_state() {
        let status = ElevationStatus::current();
        if status.is_elevated {
            assert!(status.is_admin_member);
            assert!(matches!(
                status.elevation_type,
                ElevationType::Full | ElevationType::Default
            ));
        } else {
            // Unelevated process
            assert!(!status.is_elevated);
        }
    }

    #[test]
    fn requires_elevation_distinguishes_user_from_system() {
        // User paths do NOT require elevation
        assert!(!ElevationStatus::requires_elevation(
            Path::new("C:\\Users\\Alice\\AppData\\Local\\Temp\\junk.tmp"),
            None
        ));
        assert!(!ElevationStatus::requires_elevation(
            Path::new("C:\\Users\\Alice\\Downloads\\installer.exe"),
            None
        ));
        assert!(!ElevationStatus::requires_elevation(
            Path::new("C:\\Users\\Alice\\Documents\\file.txt"),
            None
        ));

        // System paths DO require elevation
        assert!(ElevationStatus::requires_elevation(
            Path::new("C:\\Windows\\System32\\critical.dll"),
            None
        ));
        assert!(ElevationStatus::requires_elevation(
            Path::new("C:\\Program Files\\SomeApp\\app.exe"),
            None
        ));
        assert!(ElevationStatus::requires_elevation(
            Path::new("C:\\Program Files (x86)\\Legacy\\tool.dll"),
            None
        ));
        assert!(ElevationStatus::requires_elevation(
            Path::new("C:\\ProgramData\\Package Cache\\setup.exe"),
            None
        ));
        assert!(ElevationStatus::requires_elevation(
            Path::new("D:\\System Volume Information\\wpsettings.dat"),
            None
        ));
    }

    #[test]
    fn requires_elevation_respects_custom_windir() {
        let custom_win = "D:\\CustomWindows";
        assert!(ElevationStatus::requires_elevation(
            Path::new("D:\\CustomWindows\\System32\\ntoskrnl.exe"),
            Some(custom_win)
        ));
    }

    #[test]
    fn can_elevate_logic() {
        // Limited token (UAC split token unelevated) can elevate
        let limited = ElevationStatus {
            is_elevated: false,
            elevation_type: ElevationType::Limited,
            is_admin_member: true,
        };
        assert!(limited.can_elevate());

        // Already elevated doesn't need to elevate
        let full = ElevationStatus {
            is_elevated: true,
            elevation_type: ElevationType::Full,
            is_admin_member: true,
        };
        assert!(!full.can_elevate());

        // Standard user without admin rights cannot elevate without credentials
        let standard = ElevationStatus {
            is_elevated: false,
            elevation_type: ElevationType::Default,
            is_admin_member: false,
        };
        assert!(!standard.can_elevate());
    }

    #[test]
    fn check_elevation_requirement_workflow() {
        let user_path = PathBuf::from("C:\\Users\\Alice\\AppData\\Local\\Temp\\test.tmp");
        assert_eq!(
            check_elevation_requirement(&user_path, None),
            ElevationRequirement::NotRequired
        );
    }
}
