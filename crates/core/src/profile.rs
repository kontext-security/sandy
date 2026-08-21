use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use serde::{Deserialize, Deserializer, de};
use thiserror::Error;

use crate::{AccessMode, PathScope};

pub const PROFILE_SCHEMA_V1: u32 = 1;
pub const GENERIC_PROFILE_NAME: &str = "generic";

const MAX_PROFILE_SOURCE_BYTES: usize = 64 * 1024;
const MAX_EXTEND_DEPTH: usize = 8;
const MAX_PROFILE_NAME_BYTES: usize = 64;
const MAX_TEMPLATE_BYTES: usize = 4 * 1024;
const MAX_BINARY_NAME_BYTES: usize = 128;
const MAX_RESOLVED_GRANTS: usize = 256;
const MAX_RESOLVED_PATHS: usize = 512;

/// A path template from a profile document. Either absolute (`/...`) or
/// home-relative (`~/...`). Lexically validated here; `~` substitution and
/// canonicalization stay in the CLI resolve layer.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TemplatePath(String);

impl TemplatePath {
    pub fn new(value: impl Into<String>) -> Result<Self, ProfileError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ProfileError::InvalidTemplate("path is empty".to_owned()));
        }
        if value.len() > MAX_TEMPLATE_BYTES {
            return Err(ProfileError::InvalidTemplate(
                "path exceeds the template limit".to_owned(),
            ));
        }
        if value.as_bytes().contains(&0) || value.chars().any(char::is_control) {
            return Err(ProfileError::InvalidTemplate(
                "path contains NUL or control characters".to_owned(),
            ));
        }
        let expanded = expand_template_marker(&value)?;
        if expanded
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(ProfileError::InvalidTemplate(
                "path contains parent traversal".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TemplatePath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TemplatePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

fn expand_template_marker(value: &str) -> Result<PathBuf, ProfileError> {
    if let Some(rest) = value.strip_prefix("~/") {
        return Ok(PathBuf::from("/template-home").join(rest));
    }
    if value.starts_with('~') {
        return Err(ProfileError::InvalidTemplate(
            "only the ~/ prefix form is supported".to_owned(),
        ));
    }
    if !value.starts_with('/') {
        return Err(ProfileError::InvalidTemplate(
            "path must be absolute or start with ~/".to_owned(),
        ));
    }
    Ok(PathBuf::from(value))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantTemplate {
    pub path: TemplatePath,
    pub access: AccessMode,
    pub scope: PathScope,
    pub if_exists: bool,
}

impl<'de> Deserialize<'de> for GrantTemplate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            path: TemplatePath,
            access: AccessMode,
            scope: PathScope,
            #[serde(default)]
            if_exists: Option<bool>,
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(Self {
            path: raw.path,
            access: raw.access,
            scope: raw.scope,
            if_exists: raw.if_exists.unwrap_or(true),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectSpec {
    #[serde(default)]
    pub binary_names: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDocumentV1 {
    pub schema_version: u32,
    pub name: String,
    #[serde(default, rename = "abstract")]
    pub is_abstract: bool,
    #[serde(default, deserialize_with = "deserialize_extends")]
    pub extends: Vec<String>,
    #[serde(default)]
    pub detect: DetectSpec,
    #[serde(default)]
    pub grants: Vec<GrantTemplate>,
    #[serde(default)]
    pub protected_paths: Vec<TemplatePath>,
    #[serde(default)]
    pub protected_write_paths: Vec<TemplatePath>,
    #[serde(default)]
    pub kontext_hook_files: Vec<TemplatePath>,
}

fn deserialize_extends<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(name) => Ok(vec![name]),
        OneOrMany::Many(names) => Ok(names),
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedProfile {
    name: String,
    detect: DetectSpec,
    grants: Vec<GrantTemplate>,
    protected_paths: Vec<TemplatePath>,
    protected_write_paths: Vec<TemplatePath>,
    kontext_hook_files: Vec<TemplatePath>,
}

impl ResolvedProfile {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn binary_names(&self) -> &[String] {
        &self.detect.binary_names
    }

    #[must_use]
    pub fn grants(&self) -> &[GrantTemplate] {
        &self.grants
    }

    #[must_use]
    pub fn protected_paths(&self) -> &[TemplatePath] {
        &self.protected_paths
    }

    #[must_use]
    pub fn protected_write_paths(&self) -> &[TemplatePath] {
        &self.protected_write_paths
    }

    #[must_use]
    pub fn kontext_hook_files(&self) -> &[TemplatePath] {
        &self.kontext_hook_files
    }
}

#[derive(Debug)]
pub struct ProfileRegistry {
    documents: BTreeMap<String, ProfileDocumentV1>,
    detection: BTreeMap<String, String>,
}

impl ProfileRegistry {
    /// Builds a registry from `(source_name, JSON source)` pairs. Sources are
    /// compile-time constants; every failure here is a packaging defect and
    /// fails closed.
    pub fn build(sources: &[(&str, &str)]) -> Result<Self, ProfileError> {
        let mut documents = BTreeMap::new();
        let mut detection = BTreeMap::new();
        for (source_name, source) in sources {
            if source.len() > MAX_PROFILE_SOURCE_BYTES {
                return Err(ProfileError::TooLarge((*source_name).to_owned()));
            }
            let document: ProfileDocumentV1 = serde_json::from_str(source)
                .map_err(|error| ProfileError::Parse((*source_name).to_owned(), error))?;
            check_schema(source_name, &document)?;
            validate_name(&document.name)?;
            if documents.contains_key(&document.name) {
                return Err(ProfileError::DuplicateProfile(document.name.clone()));
            }
            if document.extends.len() > 1 {
                return Err(ProfileError::MultipleBases(document.name.clone()));
            }
            if document.is_abstract && !document.detect.binary_names.is_empty() {
                return Err(ProfileError::AbstractDetection(document.name.clone()));
            }
            for base in &document.extends {
                validate_name(base)?;
            }
            for binary in &document.detect.binary_names {
                validate_binary_name(binary)?;
                if let Some(existing) = detection.insert(binary.clone(), document.name.clone()) {
                    return Err(ProfileError::DuplicateDetection {
                        binary_name: binary.clone(),
                        first: existing,
                        second: document.name.clone(),
                    });
                }
            }
            documents.insert(document.name.clone(), document);
        }
        Ok(Self {
            documents,
            detection,
        })
    }

    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.documents.keys().cloned().collect()
    }

    /// Returns the public profiles that may be selected for a launch.
    #[must_use]
    pub fn selectable_names(&self) -> Vec<String> {
        self.documents
            .values()
            .filter(|document| !document.is_abstract)
            .map(|document| document.name.clone())
            .collect()
    }

    /// Returns the profile claiming the given target binary basename, if any.
    #[must_use]
    pub fn detect(&self, binary_name: &str) -> Option<&str> {
        self.detection.get(binary_name).map(String::as_str)
    }

    /// Resolves the inheritance chain base-first and merges sections in
    /// deterministic order with exact-duplicate removal.
    pub fn resolve(&self, name: &str) -> Result<ResolvedProfile, ProfileError> {
        let chain = self.extend_chain(name)?;
        let mut merged = MergedProfile::default();
        for document in chain {
            merged.absorb(document);
        }
        merged.finish(name)
    }

    /// Resolves a public launch profile while rejecting inheritance-only
    /// documents.
    pub fn resolve_selectable(&self, name: &str) -> Result<ResolvedProfile, ProfileError> {
        let document = self
            .documents
            .get(name)
            .ok_or_else(|| ProfileError::UnknownProfile(name.to_owned()))?;
        if document.is_abstract {
            return Err(ProfileError::AbstractProfile(name.to_owned()));
        }
        self.resolve(name)
    }

    fn extend_chain(&self, name: &str) -> Result<Vec<&ProfileDocumentV1>, ProfileError> {
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut cursor = Some(name);
        while let Some(current) = cursor {
            if visited.len() >= MAX_EXTEND_DEPTH {
                return Err(ProfileError::DepthExceeded(name.to_owned()));
            }
            if !visited.insert(current.to_owned()) {
                return Err(ProfileError::Cycle(name.to_owned()));
            }
            let document = self
                .documents
                .get(current)
                .ok_or_else(|| ProfileError::UnknownProfile(current.to_owned()))?;
            cursor = document.extends.first().map(String::as_str);
            chain.push(document);
        }
        chain.reverse();
        Ok(chain)
    }
}

#[derive(Default)]
struct MergedProfile {
    detect: DetectSpec,
    grants: Vec<GrantTemplate>,
    protected_paths: Vec<TemplatePath>,
    protected_write_paths: Vec<TemplatePath>,
    kontext_hook_files: Vec<TemplatePath>,
}

impl MergedProfile {
    fn absorb(&mut self, document: &ProfileDocumentV1) {
        for binary in &document.detect.binary_names {
            if !self.detect.binary_names.contains(binary) {
                self.detect.binary_names.push(binary.clone());
            }
        }
        push_unique(&mut self.grants, &document.grants);
        push_unique(&mut self.protected_paths, &document.protected_paths);
        push_unique(
            &mut self.protected_write_paths,
            &document.protected_write_paths,
        );
        push_unique(&mut self.kontext_hook_files, &document.kontext_hook_files);
    }

    fn finish(self, name: &str) -> Result<ResolvedProfile, ProfileError> {
        if self.grants.len() > MAX_RESOLVED_GRANTS {
            return Err(ProfileError::TooManyGrants(name.to_owned()));
        }
        for (field, paths) in [
            ("protected_paths", &self.protected_paths),
            ("protected_write_paths", &self.protected_write_paths),
            ("kontext_hook_files", &self.kontext_hook_files),
        ] {
            if paths.len() > MAX_RESOLVED_PATHS {
                return Err(ProfileError::TooManyPaths {
                    profile: name.to_owned(),
                    field: field.to_owned(),
                });
            }
        }
        Ok(ResolvedProfile {
            name: name.to_owned(),
            detect: self.detect,
            grants: self.grants,
            protected_paths: self.protected_paths,
            protected_write_paths: self.protected_write_paths,
            kontext_hook_files: self.kontext_hook_files,
        })
    }
}

fn push_unique<T: Clone + PartialEq>(target: &mut Vec<T>, values: &[T]) {
    for value in values {
        if !target.contains(value) {
            target.push(value.clone());
        }
    }
}

fn check_schema(source_name: &str, document: &ProfileDocumentV1) -> Result<(), ProfileError> {
    if document.schema_version != PROFILE_SCHEMA_V1 {
        return Err(ProfileError::UnsupportedSchema {
            name: document.name.clone(),
            version: document.schema_version,
        });
    }
    if source_name != document.name {
        return Err(ProfileError::NameMismatch {
            source_name: (*source_name).to_owned(),
            declared: document.name.clone(),
        });
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), ProfileError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_PROFILE_NAME_BYTES
        && name.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        });
    if valid {
        Ok(())
    } else {
        Err(ProfileError::InvalidName(name.to_owned()))
    }
}

fn validate_binary_name(binary: &str) -> Result<(), ProfileError> {
    let valid = !binary.is_empty()
        && binary.len() <= MAX_BINARY_NAME_BYTES
        && !binary.contains('/')
        && !binary.as_bytes().contains(&0)
        && !binary.chars().any(char::is_control);
    if valid {
        Ok(())
    } else {
        Err(ProfileError::InvalidBinaryName(binary.to_owned()))
    }
}

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("profile source {0} exceeds the embedded profile limit")]
    TooLarge(String),
    #[error("profile {0} is not valid JSON: {1}")]
    Parse(String, #[source] serde_json::Error),
    #[error("profile {name} declares unsupported schema version {version}")]
    UnsupportedSchema { name: String, version: u32 },
    #[error("profile file {source_name:?} declares mismatched profile name {declared:?}")]
    NameMismatch {
        source_name: String,
        declared: String,
    },
    #[error("profile name {0:?} is invalid")]
    InvalidName(String),
    #[error("detected binary name {0:?} is invalid")]
    InvalidBinaryName(String),
    #[error("duplicate agent profile {0:?}")]
    DuplicateProfile(String),
    #[error("profile {0:?} extends more than one base profile")]
    MultipleBases(String),
    #[error("abstract profile {0:?} cannot claim a detected binary name")]
    AbstractDetection(String),
    #[error("profile path is invalid: {0}")]
    InvalidTemplate(String),
    #[error("unknown agent profile {0:?}")]
    UnknownProfile(String),
    #[error("profile {0:?} is inheritance-only and cannot be selected")]
    AbstractProfile(String),
    #[error("agent profile inheritance cycle at {0:?}")]
    Cycle(String),
    #[error("agent profile inheritance depth exceeded at {0:?}")]
    DepthExceeded(String),
    #[error("profiles {first:?} and {second:?} both claim binary {binary_name:?}")]
    DuplicateDetection {
        binary_name: String,
        first: String,
        second: String,
    },
    #[error("resolved profile {0} has too many filesystem grants")]
    TooManyGrants(String),
    #[error("resolved profile {profile} field {field} exceeds its bound")]
    TooManyPaths { profile: String, field: String },
}
