use std::{io, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum AppError {
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error("command was not found or is not executable: {0:?}")]
    CommandNotFound(PathBuf),
    #[error("path does not exist: {0}")]
    MissingPath(PathBuf),
    #[error("path cannot be represented safely in a Seatbelt profile: {0}")]
    NonUtf8Path(PathBuf),
    #[error("refusing to sandbox the filesystem root or home directory")]
    UnsafeWorkingDirectory,
    #[error("write-protected path must be absolute and must not be the filesystem root: {0}")]
    InvalidWriteProtection(PathBuf),
    #[error("requested path overlaps protected data: {0}")]
    ProtectedPath(PathBuf),
    #[error("launch manifest is invalid: {0}")]
    Core(#[from] sandy_core::ValidationError),
    #[error("launch protocol failed: {0}")]
    Wire(#[from] sandy_core::WireError),
    #[cfg(target_os = "macos")]
    #[error("macOS sandbox enforcement failed: {0}")]
    Seatbelt(#[from] sandy_seatbelt::SeatbeltError),
    #[error("Sandy enforcement is currently supported only on macOS")]
    UnsupportedPlatform,
    #[error("{service} runtime control failed: {message}")]
    RuntimeControl {
        service: &'static str,
        message: String,
    },
    #[error("{provider} integration setup failed: {message}")]
    IntegrationSetup {
        provider: &'static str,
        message: String,
    },
    #[error("sandbox support probe failed: {0}")]
    Probe(String),
    #[error("launch preparation failed: {0}")]
    Launch(String),
    #[error("agent profile failed: {0}")]
    Profile(String),
    #[error("unknown agent profile {name:?}; available profiles: {}", available.join(", "))]
    UnknownProfile {
        name: String,
        available: Vec<String>,
    },
    #[error("target command could not be executed: {0}")]
    Exec(io::Error),
}

impl AppError {
    pub(crate) fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    pub(crate) fn runtime_control(service: &'static str, message: impl Into<String>) -> Self {
        Self::RuntimeControl {
            service,
            message: message.into(),
        }
    }

    pub(crate) fn integration_setup(provider: &'static str, message: impl Into<String>) -> Self {
        Self::IntegrationSetup {
            provider,
            message: message.into(),
        }
    }

    #[must_use]
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::Seatbelt(_)
            | Self::UnsupportedPlatform
            | Self::Wire(_)
            | Self::Core(_)
            | Self::Launch(_) => 126,
            _ => 1,
        }
    }
}
