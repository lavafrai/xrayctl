use crate::ports::Capability;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, ManagerError>;

#[derive(Debug, Error)]
pub enum ManagerError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid node URI: {0}")]
    InvalidNode(String),
    #[error("invalid subscription: {0}")]
    InvalidSubscription(String),
    #[error("I/O operation failed: {0}")]
    Io(String),
    #[error("download failed: {0}")]
    Download(String),
    #[error("Xray validation failed: {0}")]
    Validation(String),
    #[error("operation is already in progress")]
    LockContention,
    #[error("{capability} is unsupported on {platform}: {reason}")]
    PlatformUnsupported {
        capability: Capability,
        platform: String,
        backend: Option<String>,
        reason: String,
        recommendation: Option<String>,
    },
    #[error("Manager release source is not configured.")]
    ManagerReleaseSourceNotConfigured,
    #[error("operation requires administrator privileges")]
    PrivilegeRequired,
    #[error("{0}")]
    Other(String),
}

impl ManagerError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig(_) => "invalid_config",
            Self::InvalidNode(_) => "invalid_node",
            Self::InvalidSubscription(_) => "invalid_subscription",
            Self::Io(_) => "io_error",
            Self::Download(_) => "download_error",
            Self::Validation(_) => "validation_error",
            Self::LockContention => "lock_contention",
            Self::PlatformUnsupported { .. } => "platform_unsupported",
            Self::ManagerReleaseSourceNotConfigured => "manager_release_source_not_configured",
            Self::PrivilegeRequired => "privilege_required",
            Self::Other(_) => "operation_failed",
        }
    }

    pub fn details(&self) -> serde_json::Value {
        match self {
            Self::PlatformUnsupported {
                capability,
                platform,
                backend,
                reason,
                recommendation,
            } => serde_json::json!({
                "capability": capability,
                "platform": platform,
                "backend": backend,
                "reason": reason,
                "recommendation": recommendation
            }),
            _ => serde_json::json!({}),
        }
    }
}
