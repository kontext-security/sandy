//! Typed, caller-policy-only sandboxing for the current process.
//!
//! Sandy applies only the filesystem and network policy supplied by the caller.
//! It does not launch a helper executable, add application compatibility
//! grants, make readable paths executable, sanitize the environment, or close
//! inherited resources.
//! Subprocess creation is disabled unless the caller selects
//! [`SandboxPolicy::allow_subprocesses`] and grants executable mappings.
//!
//! Call [`apply`] before creating threads, opening sensitive files or sockets,
//! or starting untrusted work. Application is irreversible. If it returns an
//! error, terminate the process before running untrusted code because the
//! requested boundary has not been established.
//!
//! ```no_run
//! use sandy::{AccessMode, NetworkPolicy, PathScope, SandboxPolicy};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let workspace = std::env::current_dir()?;
//! let policy = SandboxPolicy::new(NetworkPolicy::BlockAll).grant(
//!     &workspace,
//!     AccessMode::ReadWrite,
//!     PathScope::Subtree,
//! );
//!
//! sandy::apply(policy)?;
//! // Start the restricted application here.
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
#[cfg(target_os = "macos")]
mod resolve;

pub use error::{ErrorKind, SandboxError};
pub use sandy_core::{AccessMode, NetworkPolicy, PathScope, SandboxPolicy};

/// Irreversibly restricts the current process and future descendants.
///
/// Sandy first resolves every caller path, validates the complete policy, and
/// compiles the native rules. Native enforcement is attempted only after that
/// preparation succeeds. The function adds no implicit filesystem or network
/// capabilities.
///
/// Call this before creating threads. Existing threads are outside the portable
/// contract even on platforms that may restrict them as an implementation
/// detail. Already-open file descriptors, sockets, memory, and environment
/// values remain capabilities held by the process.
///
/// # Errors
///
/// Returns [`ErrorKind::Unsupported`] when this build has no enforcement
/// backend, [`ErrorKind::InvalidPolicy`] for invalid caller intent,
/// [`ErrorKind::PreparationFailed`] when trusted preparation cannot complete,
/// or [`ErrorKind::EnforcementFailed`] when the native transition fails.
/// Sandy never retries with weaker enforcement.
pub fn apply(policy: SandboxPolicy) -> Result<(), SandboxError> {
    apply_platform(policy)
}

#[cfg(target_os = "macos")]
fn apply_platform(policy: SandboxPolicy) -> Result<(), SandboxError> {
    let validated = resolve::resolve(policy)?;
    let compiled = sandy_seatbelt::compile(&validated).map_err(|error| match error {
        sandy_seatbelt::SeatbeltError::UnsupportedPlatform
        | sandy_seatbelt::SeatbeltError::UnsupportedPolicy => {
            SandboxError::new(ErrorKind::Unsupported)
        }
        _ => SandboxError::new(ErrorKind::PreparationFailed),
    })?;
    sandy_seatbelt::apply(&compiled).map_err(|error| match error {
        sandy_seatbelt::SeatbeltError::UnsupportedPlatform
        | sandy_seatbelt::SeatbeltError::UnsupportedPolicy => {
            SandboxError::new(ErrorKind::Unsupported)
        }
        _ => SandboxError::new(ErrorKind::EnforcementFailed),
    })
}

#[cfg(not(target_os = "macos"))]
fn apply_platform(_policy: SandboxPolicy) -> Result<(), SandboxError> {
    Err(SandboxError::new(ErrorKind::Unsupported))
}
