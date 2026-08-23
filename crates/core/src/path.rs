use std::path::{Component, Path};

use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AbsolutePath(String);

impl AbsolutePath {
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
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    #[must_use]
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

#[derive(Debug, Error)]
pub enum PathValidationError {
    #[error("path must be absolute: {0}")]
    NotAbsolute(String),
    #[error("path contains a NUL byte")]
    ContainsNul,
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
