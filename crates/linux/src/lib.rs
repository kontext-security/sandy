//! Linux-native enforcement for a validated Sandy policy.
//!
//! This is an implementation crate used by the supported Rust facade and the
//! CLI bootstrap. It is deliberately split into a deterministic plan, ambient
//! preparation, and an irreversible application transaction.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

#[cfg(target_os = "linux")]
mod apply;
#[cfg(target_os = "linux")]
mod capabilities;
mod error;
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod ffi;
#[cfg(target_os = "linux")]
mod landlock;
#[cfg(target_os = "linux")]
mod mount;
#[cfg(target_os = "linux")]
mod namespace;
mod plan;
#[cfg(target_os = "linux")]
mod prepare;
#[cfg(target_os = "linux")]
mod seccomp;

#[cfg(target_os = "linux")]
pub use apply::apply;
pub use error::{LinuxError, LinuxErrorKind};
pub use plan::{LinuxPolicyPlan, plan};
#[cfg(target_os = "linux")]
pub use prepare::{PreparedLinuxSandbox, prepare, prepare_foreground_launch};

/// Native helpers used only by Sandy's sacrificial Linux enforcement tests.
#[cfg(all(target_os = "linux", feature = "live-tests"))]
#[doc(hidden)]
pub mod live_test_support {
    use std::io;

    /// Creates an owner-only System V message queue in the current IPC namespace.
    pub fn create_private_message_queue() -> io::Result<i32> {
        crate::ffi::create_private_message_queue()
    }

    /// Reports whether a System V message queue is visible in the current namespace.
    pub fn message_queue_is_visible(id: i32) -> io::Result<bool> {
        crate::ffi::message_queue_is_visible(id)
    }

    /// Removes a System V message queue created by a live test.
    pub fn remove_message_queue(id: i32) -> io::Result<()> {
        crate::ffi::remove_message_queue(id)
    }

    /// Creates a test key in a fresh anonymous session keyring.
    pub fn create_session_test_key(payload: &[u8]) -> io::Result<i32> {
        crate::ffi::create_session_test_key(payload)
    }

    /// Reads a test key through the native keyctl interface.
    pub fn read_test_key(id: i32) -> io::Result<Vec<u8>> {
        crate::ffi::read_test_key(id)
    }
}
