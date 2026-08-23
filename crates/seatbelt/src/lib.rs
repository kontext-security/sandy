//! Deterministic macOS Seatbelt compiler and the repository's sole native boundary.
//!
//! The crate accepts only [`sandy_core::ValidatedPolicy`]. It cannot inspect target arguments,
//! environment variables, agent names, profiles, or runtime integrations. [`compile`] is pure and
//! produces an opaque [`CompiledProfile`]; [`apply`] is the irreversible platform operation and is
//! called only by Sandy's fresh bootstrap.
//!
//! Apple's raw-profile interface is private and deprecated. Sandy probes it in a sacrificial
//! process and fails closed when the host does not support the required behavior.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

mod compiler;
mod error;
mod escape;
mod platform;

pub use compiler::{CompiledProfile, compile};
pub use error::SeatbeltError;
pub use platform::{apply, probe};
