//! Bounded codec for the parent-to-bootstrap launch protocol.
//!
//! Decoding includes semantic validation. Callers never receive an unvalidated manifest from
//! [`decode_launch`].

use thiserror::Error;

use crate::{LaunchManifestV1, ValidatedLaunch, ValidationError};

/// Maximum encoded launch size accepted from either side of the bootstrap boundary.
///
/// The check occurs before JSON deserialization to bound parser input and allocation pressure.
pub const MAX_WIRE_BYTES: usize = 256 * 1024;

/// Encodes a launch manifest while enforcing the protocol size bound.
pub fn encode_launch(launch: &LaunchManifestV1) -> Result<Vec<u8>, WireError> {
    let encoded = serde_json::to_vec(launch).map_err(WireError::Encode)?;
    if encoded.len() > MAX_WIRE_BYTES {
        return Err(WireError::TooLarge(encoded.len()));
    }
    Ok(encoded)
}

/// Decodes and validates a launch manifest.
///
/// Success is the only wire entry point to [`ValidatedLaunch`]; malformed, oversized, and
/// semantically invalid inputs remain distinguishable for phase-specific error reporting.
pub fn decode_launch(input: &[u8]) -> Result<ValidatedLaunch, WireError> {
    if input.len() > MAX_WIRE_BYTES {
        return Err(WireError::TooLarge(input.len()));
    }
    let manifest: LaunchManifestV1 = serde_json::from_slice(input).map_err(WireError::Decode)?;
    ValidatedLaunch::try_from(manifest).map_err(WireError::Validation)
}

/// Failure while crossing the bounded bootstrap wire boundary.
#[derive(Debug, Error)]
pub enum WireError {
    /// A valid in-memory manifest could not be serialized.
    #[error("failed to encode launch manifest: {0}")]
    Encode(serde_json::Error),
    /// Input was not a valid manifest document.
    #[error("failed to decode launch manifest: {0}")]
    Decode(serde_json::Error),
    /// Encoded input or output exceeded [`MAX_WIRE_BYTES`].
    #[error("launch manifest is {0} bytes, exceeding the wire limit")]
    TooLarge(usize),
    /// The decoded transport shape violated the launch security contract.
    #[error("launch manifest validation failed: {0}")]
    Validation(ValidationError),
}
