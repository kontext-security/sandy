//! Errors produced while rendering, probing, or applying Seatbelt policy.

use thiserror::Error;

/// Failure at the Sandy-to-Seatbelt enforcement boundary.
#[derive(Debug, Error)]
pub enum SeatbeltError {
    /// A value cannot be embedded safely in one SBPL string literal.
    #[error("Seatbelt policy contains an unsupported control character")]
    ControlCharacter,
    /// A native C string or policy value contains an embedded NUL.
    #[error("Seatbelt policy contains a NUL byte")]
    Nul,
    /// The validated policy contains a capability this backend cannot lower.
    #[error("Seatbelt cannot enforce one requested typed capability")]
    UnsupportedPolicy,
    /// The host rejected the generated profile before target execution.
    #[error("Seatbelt rejected the generated profile: {0}")]
    Apply(String),
    /// The native Seatbelt boundary is unavailable on this target platform.
    #[error("Seatbelt is supported only on macOS")]
    UnsupportedPlatform,
}
