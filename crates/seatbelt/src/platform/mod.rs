//! Platform dispatch for the irreversible sandbox operation.

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{apply, probe};

#[cfg(not(target_os = "macos"))]
use crate::{CompiledProfile, SeatbeltError};

/// Rejects Seatbelt application on non-macOS targets.
#[cfg(not(target_os = "macos"))]
pub fn apply(_profile: &CompiledProfile) -> Result<(), SeatbeltError> {
    Err(SeatbeltError::UnsupportedPlatform)
}

/// Rejects the Seatbelt compatibility probe on non-macOS targets.
#[cfg(not(target_os = "macos"))]
pub fn probe() -> Result<(), SeatbeltError> {
    Err(SeatbeltError::UnsupportedPlatform)
}
