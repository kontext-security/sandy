use std::{error::Error, fmt};

/// Stable classification for failures returned by [`crate::apply`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// No backend can establish Sandy's contract on this platform.
    Unsupported,
    /// The caller supplied policy intent that cannot be enforced safely.
    InvalidPolicy,
    /// Sandy could not finish trusted preparation before enforcement began.
    PreparationFailed,
    /// Native enforcement failed and the requested boundary is unproven.
    EnforcementFailed,
}

/// Failure to prepare or apply a current-process sandbox.
///
/// Display and debug output deliberately omit paths and native policy contents.
/// Use [`SandboxError::kind`] for programmatic handling.
pub struct SandboxError {
    kind: ErrorKind,
}

impl SandboxError {
    pub(crate) const fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable phase classification for this failure.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for SandboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            ErrorKind::Unsupported => "sandbox enforcement is unsupported on this platform",
            ErrorKind::InvalidPolicy => "sandbox policy is invalid",
            ErrorKind::PreparationFailed => "sandbox preparation failed",
            ErrorKind::EnforcementFailed => {
                "sandbox enforcement failed; terminate before running untrusted work"
            }
        };
        formatter.write_str(message)
    }
}

impl fmt::Debug for SandboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for SandboxError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_do_not_store_or_expose_sensitive_context() {
        let error = SandboxError::new(ErrorKind::InvalidPolicy);
        assert_eq!(error.to_string(), "sandbox policy is invalid");
        assert_eq!(format!("{error:?}"), "SandboxError { kind: InvalidPolicy }");
        assert!(error.source().is_none());
    }
}
