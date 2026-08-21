use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OsValue(Vec<u8>);

impl OsValue {
    #[cfg(unix)]
    #[must_use]
    pub fn from_os_str(value: &OsStr) -> Self {
        Self(value.as_bytes().to_vec())
    }

    #[cfg(unix)]
    #[must_use]
    pub fn to_os_string(&self) -> OsString {
        OsString::from_vec(self.0.clone())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn validate_native(&self) -> Result<(), OsValueError> {
        if self.0.contains(&0) {
            return Err(OsValueError::ContainsNul);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OsValueError {
    #[error("OS value contains a NUL byte")]
    ContainsNul,
}
