use thiserror::Error;

use crate::{LaunchManifestV1, ValidatedLaunch, ValidationError};

pub const MAX_WIRE_BYTES: usize = 256 * 1024;

pub fn encode_launch(launch: &LaunchManifestV1) -> Result<Vec<u8>, WireError> {
    let encoded = serde_json::to_vec(launch).map_err(WireError::Encode)?;
    if encoded.len() > MAX_WIRE_BYTES {
        return Err(WireError::TooLarge(encoded.len()));
    }
    Ok(encoded)
}

pub fn decode_launch(input: &[u8]) -> Result<ValidatedLaunch, WireError> {
    if input.len() > MAX_WIRE_BYTES {
        return Err(WireError::TooLarge(input.len()));
    }
    let manifest: LaunchManifestV1 = serde_json::from_slice(input).map_err(WireError::Decode)?;
    ValidatedLaunch::try_from(manifest).map_err(WireError::Validation)
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("failed to encode launch manifest: {0}")]
    Encode(serde_json::Error),
    #[error("failed to decode launch manifest: {0}")]
    Decode(serde_json::Error),
    #[error("launch manifest is {0} bytes, exceeding the wire limit")]
    TooLarge(usize),
    #[error("launch manifest validation failed: {0}")]
    Validation(ValidationError),
}
