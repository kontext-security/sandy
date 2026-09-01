use crate::{LinuxError, LinuxErrorKind, ffi};

pub(crate) fn drop_all(last_capability: u32) -> Result<(), LinuxError> {
    ffi::drop_all_capabilities(last_capability)
        .and_then(|()| ffi::verify_no_capabilities())
        .map_err(|_| LinuxError::new(LinuxErrorKind::EnforcementFailed, "capability removal"))
}
