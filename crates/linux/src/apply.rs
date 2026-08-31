use crate::{
    LinuxError, LinuxErrorKind, PreparedLinuxSandbox, capabilities, landlock, mount, namespace,
    seccomp,
};

/// Irreversibly applies a fully prepared Linux sandbox to the current process.
///
/// Any error from this function may leave the process partially restricted.
/// The caller must terminate immediately and must not run untrusted code.
pub fn apply(prepared: PreparedLinuxSandbox) -> Result<(), LinuxError> {
    namespace::enter(&prepared.namespace, prepared.block_network)?;
    mount::construct_and_enter(&prepared.mount)?;
    landlock::apply(prepared.landlock)?;
    capabilities::drop_all(prepared.namespace.last_capability)?;
    seccomp::apply(&prepared.seccomp)?;
    verify_postconditions()
}

fn verify_postconditions() -> Result<(), LinuxError> {
    // After pivot_root the former host root and procfs must be absent. This is
    // an invariant check, not a source of policy authority.
    if std::path::Path::new("/.old_root").exists() {
        Err(LinuxError::new(
            LinuxErrorKind::EnforcementFailed,
            "postcondition verification",
        ))
    } else {
        Ok(())
    }
}
