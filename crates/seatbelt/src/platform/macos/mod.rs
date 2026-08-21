#[allow(unsafe_code, reason = "sole native Seatbelt FFI boundary")]
mod ffi;

use crate::{CompiledProfile, SeatbeltError};

pub fn apply(profile: &CompiledProfile) -> Result<(), SeatbeltError> {
    ffi::apply(profile.source())
}

pub fn probe() -> Result<(), SeatbeltError> {
    ffi::apply("(version 1)\n(deny default)\n(allow process*)\n(allow file-read-metadata)\n")
}
