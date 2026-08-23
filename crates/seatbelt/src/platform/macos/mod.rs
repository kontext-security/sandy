//! Safe macOS-facing wrapper around the private native implementation.

#[allow(unsafe_code, reason = "sole native Seatbelt FFI boundary")]
mod ffi;

use crate::{CompiledProfile, SeatbeltError};

/// Irreversibly applies a compiled profile to the current bootstrap process.
///
/// The target is executed only after this succeeds, and descendants inherit the restriction.
pub fn apply(profile: &CompiledProfile) -> Result<(), SeatbeltError> {
    ffi::apply(profile.source())
}

/// Applies a minimal profile to verify raw Seatbelt availability.
///
/// Applying Seatbelt cannot be undone, so the CLI runs this probe in a sacrificial process rather
/// than restricting the long-lived caller.
pub fn probe() -> Result<(), SeatbeltError> {
    ffi::apply("(version 1)\n(deny default)\n(allow process*)\n(allow file-read-metadata)\n")
}
