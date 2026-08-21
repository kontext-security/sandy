use thiserror::Error;

#[derive(Debug, Error)]
pub enum SeatbeltError {
    #[error("Seatbelt policy contains an unsupported control character")]
    ControlCharacter,
    #[error("Seatbelt policy contains a NUL byte")]
    Nul,
    #[error("Seatbelt rejected the generated profile: {0}")]
    Apply(String),
    #[error("Seatbelt is supported only on macOS")]
    UnsupportedPlatform,
}
