use std::{error::Error, fmt};

/// Stable high-level classification for a Linux backend failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxErrorKind {
    /// The host or requested policy cannot provide the required semantics.
    Unsupported,
    /// Ambient resources could not be pinned before enforcement.
    PreparationFailed,
    /// An irreversible native enforcement step failed.
    EnforcementFailed,
}

/// Redacted Linux backend failure.
///
/// Paths and native error strings are intentionally not retained because this
/// error crosses the supported facade and CLI boundaries.
pub struct LinuxError {
    kind: LinuxErrorKind,
    phase: &'static str,
}

impl LinuxError {
    pub(crate) const fn new(kind: LinuxErrorKind, phase: &'static str) -> Self {
        Self { kind, phase }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(&self) -> LinuxErrorKind {
        self.kind
    }
}

impl fmt::Debug for LinuxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxError")
            .field("kind", &self.kind)
            .field("phase", &self.phase)
            .finish()
    }
}

impl fmt::Display for LinuxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Linux sandbox {} failed", self.phase)
    }
}

impl Error for LinuxError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_format_is_redacted() {
        let error = LinuxError::new(LinuxErrorKind::PreparationFailed, "path pinning");
        let display = error.to_string();
        let debug = format!("{error:?}");
        for rendered in [display, debug] {
            assert!(!rendered.contains("/home/"));
            assert!(!rendered.contains("native error"));
        }
        assert!(error.source().is_none());
    }
}
