#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

mod compiler;
mod error;
mod escape;
mod platform;

pub use compiler::{CompiledProfile, compile};
pub use error::SeatbeltError;
pub use platform::{apply, probe};
