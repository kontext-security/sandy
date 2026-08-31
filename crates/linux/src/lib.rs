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
mod support;

#[cfg(target_os = "linux")]
pub use apply::apply;
pub use error::{LinuxError, LinuxErrorKind};
pub use plan::{LinuxPolicyPlan, plan};
#[cfg(target_os = "linux")]
pub use prepare::{PreparedLinuxSandbox, prepare};
pub use support::{REQUIRED_LANDLOCK_ABI, SupportInfo, probe};
