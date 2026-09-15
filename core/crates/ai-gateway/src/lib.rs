//! `sc-ai-gateway` — optional AI second-opinion layer (spec §7, §22).
//!
//! Contract:
//! - The AI receives **sanitized metadata only** — never file content.
//! - Its output is an [`sc_file_models::AiSignal`]: a *recommendation* that
//!   the safety engine may or may not use. The AI has no delete permission,
//!   ever (spec §23, Security Boundary).
//! - v1 ships with AI **off by default**: the local engine is the sole
//!   source of truth. Cloud providers are milestone M3.

use sc_file_models::{now_secs, AiSignal, ContentKind};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

/// Sanitized metadata sent (in the future) to a remote analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRequest {
    /// Path with the username masked, e.g. `C:\Users\<USER>\AppData\...`.
    pub path_hint: String,
    pub size: u64,
    pub content_kind: ContentKind,
    pub age_days: i64,
    pub owner_app: Option<String>,
    pub signed: bool,
    pub in_use: bool,
    pub application_installed: bool,
    /// What the local engine already concluded.
    pub local_risk_score: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AiError {
    Unavailable(String),
    Timeout,
    BadResponse(String),
}

impl fmt::Display for AiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AiError::Unavailable(w) => write!(f, "AI unavailable: {w}"),
            AiError::Timeout => write!(f, "AI request timed out"),
            AiError::BadResponse(w) => write!(f, "bad AI response: {w}"),
        }
    }
}

impl std::error::Error for AiError {}

/// Anything that can produce an [`AiSignal`].
pub trait Analyzer: Send + Sync {
    fn name(&self) -> &str;
    fn available(&self) -> bool;
    fn analyze(&self, req: &AiRequest) -> Result<AiSignal, AiError>;
}

/// v1 default: no AI at all — the local engine is the sole source of truth.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalOnlyAnalyzer;

impl Analyzer for LocalOnlyAnalyzer {
    fn name(&self) -> &str {
        "local-only"
    }
    fn available(&self) -> bool {
        false
    }
    fn analyze(&self, _req: &AiRequest) -> Result<AiSignal, AiError> {
        Err(AiError::Unavailable(
            "v1 ships without AI; the local engine is the sole source of truth".into(),
        ))
    }
}

/// Skeleton for a future cloud provider (milestone M3). Not wired to any
/// network in v1 — enabling it without a provider is a misconfiguration.
#[derive(Debug, Clone, Default)]
pub struct CloudAnalyzer {
    pub enabled: bool,
    pub endpoint: Option<String>,
}

impl Analyzer for CloudAnalyzer {
    fn name(&self) -> &str {
        "cloud"
    }
    fn available(&self) -> bool {
        self.enabled && self.endpoint.is_some()
    }
    fn analyze(&self, _req: &AiRequest) -> Result<AiSignal, AiError> {
        if !self.enabled {
            return Err(AiError::Unavailable(
                "cloud AI is disabled in settings".into(),
            ));
        }
        Err(AiError::BadResponse(
            "cloud provider integration lands in milestone M3".into(),
        ))
    }
}

/// Mask the user's identity before anything leaves the machine.
///
/// `C:\Users\Bob\AppData\...`  →  `C:/Users/<USER>/AppData/...`
/// `/home/alice/project`        →  `/home/<USER>/project`
pub fn sanitize_path(p: &Path) -> String {
    let normalized = p.to_string_lossy().replace('\\', "/");
    let comps: Vec<String> = normalized
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let mut out = String::new();
    let mut skip_next = false;
    for c in comps {
        if skip_next {
            skip_next = false;
            continue;
        }
        if matches!(c.to_ascii_lowercase().as_str(), "users" | "home") {
            if !out.is_empty() {
                out.push('/');
            }
            out.push_str(&c);
            out.push_str("/<USER>");
            skip_next = true;
            continue;
        }
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(&c);
    }
    out
}

/// When this sanitized request would have been sent (audit trail).
pub fn audit_stamp() -> i64 {
    now_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_masks_windows_user() {
        let s = sanitize_path(Path::new(
            "C:\\Users\\Bob\\AppData\\Local\\SomeApp\\cache\\x.bin",
        ));
        assert!(s.contains("Users/<USER>"), "got: {s}");
        assert!(!s.contains("Bob"));
    }

    #[test]
    fn sanitize_masks_unix_user() {
        let s = sanitize_path(Path::new("/home/alice/project/build.log"));
        assert!(s.contains("home/<USER>"), "got: {s}");
        assert!(!s.contains("alice"));
    }

    #[test]
    fn local_only_is_unavailable() {
        let a = LocalOnlyAnalyzer;
        assert!(!a.available());
        let err = a
            .analyze(&AiRequest {
                path_hint: "x".into(),
                size: 1,
                content_kind: ContentKind::Unknown,
                age_days: 1,
                owner_app: None,
                signed: false,
                in_use: false,
                application_installed: false,
                local_risk_score: 50,
            })
            .unwrap_err();
        assert!(matches!(err, AiError::Unavailable(_)));
    }

    #[test]
    fn cloud_disabled_is_unavailable() {
        let a = CloudAnalyzer::default();
        assert!(!a.available());
        let err = a
            .analyze(&AiRequest {
                path_hint: "x".into(),
                size: 1,
                content_kind: ContentKind::Unknown,
                age_days: 1,
                owner_app: None,
                signed: false,
                in_use: false,
                application_installed: false,
                local_risk_score: 50,
            })
            .unwrap_err();
        assert!(matches!(err, AiError::Unavailable(_)));
    }

    #[test]
    fn cloud_enabled_without_provider_is_misconfigured() {
        let a = CloudAnalyzer {
            enabled: true,
            endpoint: Some("https://example.invalid".into()),
        };
        assert!(a.available());
        let err = a
            .analyze(&AiRequest {
                path_hint: "x".into(),
                size: 1,
                content_kind: ContentKind::Unknown,
                age_days: 1,
                owner_app: None,
                signed: false,
                in_use: false,
                application_installed: false,
                local_risk_score: 50,
            })
            .unwrap_err();
        assert!(matches!(err, AiError::BadResponse(_)));
    }
}
