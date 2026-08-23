//! Lexically validated paths used by the platform-neutral security contract.

use std::path::{Component, Path};

use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

/// Absolute UTF-8 path with NUL and parent traversal rejected.
///
/// This type proves lexical properties only. It deliberately does not access the filesystem and
/// therefore does not prove existence, canonical form, file type, ownership, or freedom from
/// symlink races. The trusted CLI resolver establishes those ambient properties before building a
/// launch manifest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AbsolutePath(String);

impl AbsolutePath {
    /// Creates a lexically safe absolute path without consulting the filesystem.
    pub fn new(value: impl Into<String>) -> Result<Self, PathValidationError> {
        let value = value.into();
        let path = Path::new(&value);
        if !path.is_absolute() {
            return Err(PathValidationError::NotAbsolute(value));
        }
        if value.as_bytes().contains(&0) {
            return Err(PathValidationError::ContainsNul);
        }
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(PathValidationError::ParentTraversal(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    /// Returns the validated UTF-8 representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    /// Borrows the validated value as a [`Path`].
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    #[must_use]
    /// Returns whether the path names the filesystem root.
    pub fn is_root(&self) -> bool {
        self.as_path().parent().is_none()
    }
}

impl AsRef<Path> for AbsolutePath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl<'de> Deserialize<'de> for AbsolutePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Failure to establish the lexical invariants of [`AbsolutePath`].
#[derive(Debug, Error)]
pub enum PathValidationError {
    /// The supplied path is relative.
    #[error("path must be absolute: {0}")]
    NotAbsolute(String),
    /// Native path use would be truncated at an embedded NUL.
    #[error("path contains a NUL byte")]
    ContainsNul,
    /// Parent traversal would make component-based policy reasoning ambiguous.
    #[error("path contains parent traversal: {0}")]
    ParentTraversal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_absolute_paths() {
        let path = AbsolutePath::new("/tmp/sandy");
        assert!(path.is_ok());
    }

    #[test]
    fn rejects_relative_and_parent_paths() {
        assert!(matches!(
            AbsolutePath::new("relative"),
            Err(PathValidationError::NotAbsolute(_))
        ));
        assert!(matches!(
            AbsolutePath::new("/tmp/../etc"),
            Err(PathValidationError::ParentTraversal(_))
        ));
    }

    #[test]
    fn rejects_invalid_paths_during_manifest_deserialization() {
        for candidate in [r#""relative""#, r#""/tmp/../secret""#, r#""/tmp/\u0000""#] {
            assert!(serde_json::from_str::<AbsolutePath>(candidate).is_err());
        }
    }
}
