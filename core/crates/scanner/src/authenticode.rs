//! Windows Authenticode Verification (spec §3A; Milestone M1 Component #3).
//!
//! Provides native verification of PE digital signatures:
//! - Uses `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2`
//! - Extracts publisher/signer display name via `CryptQueryObject` & `CertGetNameStringW`
//! - Strictly local/offline trust verification: `WTD_REVOKE_NONE` & `WTD_CACHE_ONLY_URL_RETRIEVAL`
//!   (verifies signature integrity and local certificate store trust chains; does
//!   not query network revocation servers or CRL endpoints)
//! - RAII cleanup for all native handles and state allocations (`WTD_STATEACTION_CLOSE`)
//! - Strict error distinguishing: `Unsigned` vs `SignedInvalid` vs `VerificationError`
//! - Non-Windows platforms cleanly return `UnsupportedPlatform`.

#[allow(unused_imports)]
use sc_file_models::{SignatureInfo, SignatureStatus, TrustStatus};
use std::path::Path;

/// Query Authenticode signature for a file path.
///
/// If `is_pe` is false, returns `SignatureInfo::not_pe()` without attempting
/// any PE signature parsing or Win32 CryptoAPI calls.
pub fn verify_authenticode(path: &Path, is_pe: bool) -> SignatureInfo {
    if !is_pe {
        return SignatureInfo::not_pe();
    }

    // Verify file accessibility before invoking Windows crypto stack.
    // If the file is inaccessible or missing, this is an explicit verification error,
    // NEVER to be confused with "unsigned".
    if let Err(e) = std::fs::metadata(path) {
        return SignatureInfo::verification_error(
            true,
            e.raw_os_error().map(|code| code as u32),
            format!("Cannot access file for signature verification: {e}"),
        );
    }

    #[cfg(windows)]
    {
        verify_authenticode_windows(path)
    }

    #[cfg(not(windows))]
    {
        let _ = path;
        SignatureInfo::unsupported_platform(true)
    }
}

#[cfg(windows)]
fn verify_authenticode_windows(path: &Path) -> SignatureInfo {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::WinTrust::*;

    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide_path.as_ptr(),
        hFile: 0 as _,
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut wtd = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: 0 as _,
        pwszURLReference: std::ptr::null_mut(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: 0,
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    struct WinTrustGuard<'a> {
        data: &'a mut WINTRUST_DATA,
        action: &'a mut windows_sys::core::GUID,
    }

    impl<'a> Drop for WinTrustGuard<'a> {
        fn drop(&mut self) {
            if !self.data.hWVTStateData.is_null() {
                self.data.dwStateAction = WTD_STATEACTION_CLOSE;
                unsafe {
                    WinVerifyTrust(
                        0 as _,
                        self.action,
                        self.data as *mut _ as *mut std::ffi::c_void,
                    );
                }
            }
        }
    }

    let status = unsafe {
        WinVerifyTrust(
            0 as _,
            &mut action_guid,
            &mut wtd as *mut _ as *mut std::ffi::c_void,
        )
    };

    let _guard = WinTrustGuard {
        data: &mut wtd,
        action: &mut action_guid,
    };

    let status_u32 = status as u32;

    match status_u32 {
        0 => {
            let signer = extract_signer_name(path);
            SignatureInfo::signed_valid(signer)
        }
        // TRUST_E_NOSIGNATURE (0x800B0100) or CRYPT_E_NO_MATCH (0x80092009)
        0x800B0100 | 0x80092009 => SignatureInfo::unsigned(true),
        // TRUST_E_BAD_DIGEST (0x80096010)
        0x80096010 => {
            let signer = extract_signer_name(path);
            SignatureInfo::signed_invalid(
                TrustStatus::BadDigest,
                Some(status_u32),
                "Digital signature hash mismatch: file content has been altered or tampered with",
                signer,
            )
        }
        // CERT_E_UNTRUSTEDROOT (0x800B0109)
        0x800B0109 => {
            let signer = extract_signer_name(path);
            SignatureInfo::signed_invalid(
                TrustStatus::UntrustedRoot,
                Some(status_u32),
                "Certificate chain processed correctly but terminated in an untrusted root certificate",
                signer,
            )
        }
        // CERT_E_CHAINING (0x800B010A)
        0x800B010A => {
            let signer = extract_signer_name(path);
            SignatureInfo::signed_invalid(
                TrustStatus::UntrustedRoot,
                Some(status_u32),
                "Certificate chain could not be built to a trusted root authority",
                signer,
            )
        }
        // CERT_E_EXPIRED (0x800B0101)
        0x800B0101 => {
            let signer = extract_signer_name(path);
            SignatureInfo::signed_invalid(
                TrustStatus::Expired,
                Some(status_u32),
                "Certificate is expired or not yet valid",
                signer,
            )
        }
        // CERT_E_REVOKED (0x800B010C)
        0x800B010C => {
            let signer = extract_signer_name(path);
            SignatureInfo::signed_invalid(
                TrustStatus::Revoked,
                Some(status_u32),
                "Certificate has been revoked by the issuer",
                signer,
            )
        }
        // TRUST_E_EXPLICIT_DISTRUST (0x800B0111)
        0x800B0111 => {
            let signer = extract_signer_name(path);
            SignatureInfo::signed_invalid(
                TrustStatus::ExplicitDistrust,
                Some(status_u32),
                "Certificate is explicitly marked as distrusted",
                signer,
            )
        }
        // TRUST_E_PROVIDER_UNKNOWN (0x800B0001) or TRUST_E_ACTION_UNKNOWN (0x800B0002)
        0x800B0001 | 0x800B0002 => {
            SignatureInfo {
                status: SignatureStatus::SignedUnknown,
                is_pe: true,
                trust_status: TrustStatus::UnknownTrust,
                signer_name: extract_signer_name(path),
                error_code: Some(status_u32),
                error_message: Some(format!("Trust provider or action unrecognized (0x{status_u32:08X})")),
            }
        }
        // General or OS errors (e.g. sharing violation, access denied, etc.)
        other => {
            SignatureInfo::verification_error(
                true,
                Some(other),
                format!("WinVerifyTrust returned error code 0x{other:08X}"),
            )
        }
    }
}

#[cfg(windows)]
fn extract_signer_name(path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Cryptography::*;

    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut encoding: u32 = 0;
    let mut content_type: u32 = 0;
    let mut format_type: u32 = 0;
    let mut cert_store: HCERTSTORE = std::ptr::null_mut();
    let mut crypt_msg: *mut std::ffi::c_void = std::ptr::null_mut();

    let ok = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const _,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            &mut encoding,
            &mut content_type,
            &mut format_type,
            &mut cert_store,
            &mut crypt_msg,
            std::ptr::null_mut(),
        )
    };

    if ok == 0 {
        return None;
    }

    struct CryptQueryCleanup {
        store: HCERTSTORE,
        msg: *mut std::ffi::c_void,
    }
    impl Drop for CryptQueryCleanup {
        fn drop(&mut self) {
            unsafe {
                if !self.msg.is_null() {
                    CryptMsgClose(self.msg);
                }
                if !self.store.is_null() {
                    CertCloseStore(self.store, 0);
                }
            }
        }
    }
    let _guard = CryptQueryCleanup {
        store: cert_store,
        msg: crypt_msg,
    };

    if crypt_msg.is_null() || cert_store.is_null() {
        return None;
    }

    let mut signer_info_size: u32 = 0;
    let ok = unsafe {
        CryptMsgGetParam(
            crypt_msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            std::ptr::null_mut(),
            &mut signer_info_size,
        )
    };
    if ok == 0 || signer_info_size == 0 {
        return None;
    }

    let mut signer_info_buf = vec![0u8; signer_info_size as usize];
    let ok = unsafe {
        CryptMsgGetParam(
            crypt_msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            signer_info_buf.as_mut_ptr() as *mut _,
            &mut signer_info_size,
        )
    };
    if ok == 0 {
        return None;
    }

    let signer_info = signer_info_buf.as_ptr() as *const CMSG_SIGNER_INFO;
    let cert_info = CERT_INFO {
        Issuer: unsafe { (*signer_info).Issuer },
        SerialNumber: unsafe { (*signer_info).SerialNumber },
        ..unsafe { std::mem::zeroed() }
    };

    let cert_context = unsafe {
        CertFindCertificateInStore(
            cert_store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            &cert_info as *const _ as *const _,
            std::ptr::null(),
        )
    };

    if cert_context.is_null() {
        return None;
    }

    struct CertContextGuard(*const CERT_CONTEXT);
    impl Drop for CertContextGuard {
        fn drop(&mut self) {
            unsafe {
                CertFreeCertificateContext(self.0);
            }
        }
    }
    let _cert_guard = CertContextGuard(cert_context);

    let len = unsafe {
        CertGetNameStringW(
            cert_context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
        )
    };
    if len <= 1 {
        return None;
    }

    let mut name_buf = vec![0u16; len as usize];
    let written = unsafe {
        CertGetNameStringW(
            cert_context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            std::ptr::null(),
            name_buf.as_mut_ptr(),
            len,
        )
    };
    if written <= 1 {
        return None;
    }

    let name_slice = &name_buf[..(written as usize).saturating_sub(1)];
    Some(String::from_utf16_lossy(name_slice))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn verify_authenticode_non_pe_returns_not_pe() {
        let temp_dir = std::env::temp_dir().join("sc_auth_non_pe_test");
        let _ = fs::create_dir_all(&temp_dir);
        let path = temp_dir.join("sample.txt");
        fs::write(&path, b"hello world not a pe").unwrap();

        let sig = verify_authenticode(&path, false);
        assert!(!sig.is_pe);
        assert_eq!(sig.status, SignatureStatus::Unsigned);
        assert_eq!(sig.trust_status, TrustStatus::NotApplicable);
        assert!(!sig.is_signed_valid());
    }

    #[test]
    fn verify_authenticode_inaccessible_file_returns_verification_error() {
        let missing = Path::new("C:\\Definitely\\Does\\Not\\Exist_xyz987.dll");
        let sig = verify_authenticode(missing, true);
        assert!(sig.is_pe);
        assert_eq!(sig.status, SignatureStatus::VerificationError);
        assert_eq!(sig.trust_status, TrustStatus::VerificationFailed);
        assert!(sig.error_code.is_some());
        assert!(!sig.is_unsigned(), "Inaccessible file must NEVER be reported as unsigned");
    }

    #[test]
    fn verify_authenticode_unsigned_pe_fixture() {
        let temp_dir = std::env::temp_dir().join("sc_auth_unsigned_pe_test");
        let _ = fs::create_dir_all(&temp_dir);
        let path = temp_dir.join("unsigned.exe");
        // Construct minimal valid PE header bytes
        let mut pe_bytes = vec![0u8; 0x200];
        pe_bytes[0] = b'M';
        pe_bytes[1] = b'Z';
        pe_bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe_bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe_bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        fs::write(&path, &pe_bytes).unwrap();

        let sig = verify_authenticode(&path, true);
        assert!(sig.is_pe);

        #[cfg(windows)]
        {
            assert_eq!(sig.status, SignatureStatus::Unsigned);
            assert_eq!(sig.trust_status, TrustStatus::NoSignature);
        }

        #[cfg(not(windows))]
        {
            assert_eq!(sig.status, SignatureStatus::UnsupportedPlatform);
        }
    }

    #[test]
    fn verify_authenticode_distinguishes_error_from_unsigned() {
        let unsigned = SignatureInfo::unsigned(true);
        let err = SignatureInfo::verification_error(true, Some(5), "Access denied");

        assert!(unsigned.is_unsigned());
        assert!(!err.is_unsigned());
        assert_ne!(unsigned.status, err.status);
    }

    #[test]
    fn verify_authenticode_signed_valid_fixture() {
        let sig = SignatureInfo::signed_valid(Some("Microsoft Windows".into()));
        assert!(sig.is_signed_valid());
        assert_eq!(sig.signer_name.as_deref(), Some("Microsoft Windows"));
        assert_eq!(sig.trust_status, TrustStatus::Trusted);
        assert_eq!(sig.error_code, Some(0));
    }

    #[test]
    fn verify_authenticode_invalid_tampered_fixture() {
        let sig = SignatureInfo::signed_invalid(
            TrustStatus::BadDigest,
            Some(0x80096010),
            "Digital signature hash mismatch: file content has been altered or tampered with",
            Some("Contoso Ltd".into()),
        );
        assert!(!sig.is_signed_valid());
        assert_eq!(sig.status, SignatureStatus::SignedInvalid);
        assert_eq!(sig.trust_status, TrustStatus::BadDigest);
        assert_eq!(sig.error_code, Some(0x80096010));
        assert!(sig.has_signature());
    }
}
