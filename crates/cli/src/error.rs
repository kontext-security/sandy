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
    #[error("path cannot be represented safely in a native policy: {0}")]
    NonUtf8Path(PathBuf),
    #[error("refusing to sandbox the filesystem root or home directory")]
    UnsafeWorkingDirectory,
    #[error("write-protected path must be absolute and must not be the filesystem root: {0}")]
    InvalidWriteProtection(PathBuf),
    #[error("requested path overlaps protected data: {0}")]
    ProtectedPath(PathBuf),
    #[error("policy path must be absolute and must not be the filesystem root: {0}")]
    InvalidPolicyPath(PathBuf),
    #[error("policy intent is invalid: {0}")]
    PolicyIntent(#[from] sandy_core::PolicyIntentError),
    #[error("{0}")]
    PolicyDocument(#[from] sandy_core::PolicyDocumentError),
    #[error("sandbox policy file: {0}")]
    PolicyFile(String),
    #[error("launch manifest is invalid: {0}")]
    Core(#[from] sandy_core::ValidationError),
    #[error("launch protocol failed: {0}")]
    Wire(#[from] sandy_core::WireError),
    #[cfg(target_os = "macos")]
    #[error("macOS sandbox enforcement failed: {0}")]
    Seatbelt(#[from] sandy_seatbelt::SeatbeltError),
    #[cfg(target_os = "linux")]
    #[error("Linux sandbox enforcement failed: {0}")]
    Linux(#[from] sandy_linux::LinuxError),
    #[error("Sandy enforcement is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("integration setup is currently supported only on macOS")]
    UnsupportedIntegrationSetup,
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
    #[error("agent preset failed: {0}")]
    AgentPreset(String),
    #[error("unknown agent {name:?}; available agents: {}", available.join(", "))]
    UnknownAgent {
        name: String,
        available: Vec<&'static str>,
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
            #[cfg(target_os = "macos")]
            Self::Seatbelt(_) => 126,
            #[cfg(target_os = "linux")]
            Self::Linux(_) => 126,
            Self::UnsupportedPlatform
            | Self::Wire(_)
            | Self::Core(_)
            | Self::PolicyIntent(_)
            | Self::PolicyDocument(_)
            | Self::PolicyFile(_)
            | Self::Launch(_) => 126,
            _ => 1,
        }
    }
}
