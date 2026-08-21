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
    #[error("Kontext integration failed: {0}")]
    Kontext(String),
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

    #[must_use]
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::Seatbelt(_) | Self::UnsupportedPlatform | Self::Wire(_) | Self::Core(_) => 126,
            _ => 1,
        }
    }
}
