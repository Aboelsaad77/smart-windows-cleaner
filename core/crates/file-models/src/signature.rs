//! Structured Authenticode signature intelligence (spec §3A; Milestone M1 Component #3).
//!
//! Separates:
//! - Whether a file is a PE binary.
//! - Whether a digital signature is present.
//! - Whether the signature is cryptographically valid and trusted.
//! - Publisher / signer identity.
//! - OS or CryptoAPI error codes on failure.

use serde::{Deserialize, Serialize};

/// High-level digital signature verification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// File has no digital signature (e.g. TRUST_E_NOSIGNATURE or un-embedded).
    #[default]
    Unsigned,
    /// Signature is present, cryptographically valid, and chains to a trusted root.
    SignedValid,
    /// Signature is present but invalid (expired, revoked, tampered digest, or untrusted root).
    SignedInvalid,
    /// Signature is present but provider/action unknown or trust cannot be determined.
    SignedUnknown,
    /// Verification could not be performed (e.g. I/O error, sharing violation, out of memory).
    VerificationError,
    /// Platform is not Windows (Authenticode verification unsupported).
    UnsupportedPlatform,
}

/// Detailed reason for trust or verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustStatus {
    /// Cryptographically valid and trusted root.
    Trusted,
    /// Certificate chain terminated in an untrusted root (e.g. self-signed or private CA).
    UntrustedRoot,
    /// Specifically detected self-signed certificate.
    SelfSigned,
    /// Certificate expired at verification time.
    Expired,
    /// Certificate has been revoked.
    Revoked,
    /// File contents modified after signing (digest mismatch / corrupted PE).
    BadDigest,
    /// Certificate is explicitly marked as distrusted/disallowed in system store.
    ExplicitDistrust,
    /// No signature present.
    #[default]
    NoSignature,
    /// Provider or action unknown.
    UnknownTrust,
    /// Verification failed to complete (I/O or system error).
    VerificationFailed,
    /// Not applicable (e.g. non-PE file or unsupported platform).
    NotApplicable,
}

/// Rich, structured signature intelligence associated with a scanned file.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// High-level status.
    pub status: SignatureStatus,
    /// Whether the file was confirmed to be a Portable Executable (PE) binary.
    pub is_pe: bool,
    /// Detailed trust status.
    pub trust_status: TrustStatus,
    /// Publisher/signer name extracted from leaf certificate subject (e.g. "Microsoft Corporation").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_name: Option<String>,
    /// Win32 / WinVerifyTrust HRESULT or OS error code (e.g. 0x800B0100 for TRUST_E_NOSIGNATURE).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<u32>,
    /// Diagnostic explanation of verification result or failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl SignatureInfo {
    /// Returns true if the file has a cryptographically valid and trusted signature.
    pub fn is_signed_valid(&self) -> bool {
        self.status == SignatureStatus::SignedValid
    }

    /// Returns true if the file has no digital signature.
    pub fn is_unsigned(&self) -> bool {
        self.status == SignatureStatus::Unsigned
    }

    /// Returns true if any signature was detected (valid, invalid, or unknown).
    pub fn has_signature(&self) -> bool {
        matches!(
            self.status,
            SignatureStatus::SignedValid
                | SignatureStatus::SignedInvalid
                | SignatureStatus::SignedUnknown
        )
    }

    /// Creates an `Unsigned` record for a PE file.
    pub fn unsigned(is_pe: bool) -> Self {
        Self {
            status: SignatureStatus::Unsigned,
            is_pe,
            trust_status: TrustStatus::NoSignature,
            signer_name: None,
            error_code: None,
            error_message: None,
        }
    }

    /// Creates a `SignedValid` record with optional publisher name.
    pub fn signed_valid(signer: Option<String>) -> Self {
        Self {
            status: SignatureStatus::SignedValid,
            is_pe: true,
            trust_status: TrustStatus::Trusted,
            signer_name: signer,
            error_code: Some(0),
            error_message: None,
        }
    }

    /// Creates a `SignedInvalid` record with specific trust failure reason and error code.
    pub fn signed_invalid(
        trust_status: TrustStatus,
        error_code: Option<u32>,
        message: impl Into<String>,
        signer: Option<String>,
    ) -> Self {
        Self {
            status: SignatureStatus::SignedInvalid,
            is_pe: true,
            trust_status,
            signer_name: signer,
            error_code,
            error_message: Some(message.into()),
        }
    }

    /// Creates a result indicating the file is not a PE binary.
    pub fn not_pe() -> Self {
        Self {
            status: SignatureStatus::Unsigned,
            is_pe: false,
            trust_status: TrustStatus::NotApplicable,
            signer_name: None,
            error_code: None,
            error_message: Some("File is not a PE executable".into()),
        }
    }

    /// Creates a result indicating the platform does not support Authenticode.
    pub fn unsupported_platform(is_pe: bool) -> Self {
        Self {
            status: SignatureStatus::UnsupportedPlatform,
            is_pe,
            trust_status: TrustStatus::NotApplicable,
            signer_name: None,
            error_code: None,
            error_message: Some("Authenticode verification requires Windows".into()),
        }
    }

    /// Creates an explicit verification error result (I/O, sharing violation, OOM, etc.).
    pub fn verification_error(is_pe: bool, error_code: Option<u32>, message: impl Into<String>) -> Self {
        Self {
            status: SignatureStatus::VerificationError,
            is_pe,
            trust_status: TrustStatus::VerificationFailed,
            signer_name: None,
            error_code,
            error_message: Some(message.into()),
        }
    }
}
