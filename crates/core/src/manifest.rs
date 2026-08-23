//! Versioned description of one fully resolved Sandy launch.
//!
//! These types are serializable transport types, not proof of validity. Constructing or decoding
//! a [`LaunchManifestV1`] does not authorize execution; callers must convert it into
//! [`crate::ValidatedLaunch`] first.

use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AbsolutePath, PolicySpec};

/// Wire schema understood by the current bootstrap.
///
/// A schema change is an execution-protocol decision: old bootstraps reject unknown versions
/// rather than interpreting them permissively.
pub const MANIFEST_SCHEMA_V1: u32 = 1;

/// Complete transport representation of one target launch.
///
/// The trusted parent resolves all ambient state before encoding this value. The fresh bootstrap
/// validates it again before compiling and applying the contained policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchManifestV1 {
    /// Version of the manifest and bootstrap protocol.
    pub schema_version: u32,
    /// Target executable and byte-preserving arguments.
    pub command: CommandSpec,
    /// Absolute working directory selected by the trusted parent.
    pub working_directory: AbsolutePath,
    /// Complete environment passed to the target after CLI-side filtering.
    pub environment: Vec<EnvironmentEntry>,
    /// Typed kernel capabilities to enforce before target execution.
    pub policy: PolicySpec,
}

/// Executable and arguments passed unchanged to the native execution boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandSpec {
    /// Executable name or path, preserved as native Unix bytes.
    pub program: OsValue,
    /// Ordered target arguments, preserved as native Unix bytes.
    pub arguments: Vec<OsValue>,
}

/// One key-value pair in the target environment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentEntry {
    /// Environment variable name as native Unix bytes.
    pub key: OsValue,
    /// Environment variable value as native Unix bytes.
    pub value: OsValue,
}

/// Serializable, byte-preserving representation of a Unix [`OsStr`].
///
/// JSON strings cannot represent arbitrary Unix path and argument bytes. Sandy therefore encodes
/// the raw byte sequence instead of using a lossy UTF-8 conversion. This type does not reject NUL
/// at construction time so malformed wire input can be represented and rejected uniformly by
/// launch validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OsValue(Vec<u8>);

impl OsValue {
    /// Copies the native Unix bytes without UTF-8 conversion.
    #[cfg(unix)]
    #[must_use]
    pub fn from_os_str(value: &OsStr) -> Self {
        Self(value.as_bytes().to_vec())
    }

    /// Restores the original native Unix byte sequence.
    #[cfg(unix)]
    #[must_use]
    pub fn to_os_string(&self) -> OsString {
        OsString::from_vec(self.0.clone())
    }

    /// Returns the exact serialized bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Rejects values that cannot be passed to native `execve`-style interfaces.
    ///
    /// NUL is checked here, rather than during byte capture, so locally produced and decoded
    /// values go through the same fail-closed validation path.
    pub fn validate_native(&self) -> Result<(), OsValueError> {
        if self.0.contains(&0) {
            return Err(OsValueError::ContainsNul);
        }
        Ok(())
    }
}

/// Failure to represent a serialized OS value at the native process boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OsValueError {
    /// Native Unix strings cannot contain an embedded NUL byte.
    #[error("OS value contains a NUL byte")]
    ContainsNul,
}
