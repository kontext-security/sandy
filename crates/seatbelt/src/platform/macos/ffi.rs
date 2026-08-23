//! Private native boundary for Apple's deprecated `sandbox_init` interface.
//!
//! Both symbols are declared by the macOS SDK in `<sandbox.h>`, available since macOS 10.5 and
//! deprecated since macOS 10.8. The public header documents named profiles only. Passing flags `0`
//! to apply raw SBPL is private behavior and is therefore covered by Sandy's live host probe and
//! supported-macOS regression tests rather than treated as a stable SDK contract.

use std::{
    ffi::{CStr, CString},
    ptr,
};

use libc::{c_char, c_int};

use crate::SeatbeltError;

#[link(name = "sandbox")]
unsafe extern "C" {
    // On failure, `error_buffer` is either null or an Apple-owned NUL-terminated allocation that
    // must be released with `sandbox_free_error`.
    fn sandbox_init(profile: *const c_char, flags: u64, error_buffer: *mut *mut c_char) -> c_int;
    // Accepts only null or an allocation returned through `sandbox_init`'s error buffer.
    fn sandbox_free_error(error_buffer: *mut c_char);
}

pub(super) fn apply(source: &str) -> Result<(), SeatbeltError> {
    let profile = CString::new(source).map_err(|_| SeatbeltError::Nul)?;
    let mut error_buffer = ptr::null_mut();

    // SAFETY: profile is a live NUL-terminated C string for the duration of
    // the call. error_buffer points to writable storage for one pointer. With
    // raw-profile flags set to zero, sandbox_init either leaves it null or
    // returns an Apple-owned allocation released by sandbox_free_error.
    // Zero selects the private raw-profile mode. The sacrificial probe establishes support before
    // a normal launch reaches this bootstrap call.
    let status = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error_buffer) };
    if status == 0 {
        return Ok(());
    }

    let message = if error_buffer.is_null() {
        "unknown Seatbelt initialization error".to_owned()
    } else {
        // SAFETY: a non-null error pointer returned by sandbox_init points to a
        // NUL-terminated string and remains valid until freed below.
        let message = unsafe { CStr::from_ptr(error_buffer) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: error_buffer is the non-null Apple allocation returned by
        // the failed call above and has not previously been released.
        unsafe { sandbox_free_error(error_buffer) };
        message
    };

    Err(SeatbeltError::Apply(message))
}
