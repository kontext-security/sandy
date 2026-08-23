//! Embedded agent-profile document model and deterministic inheritance.
//!
//! Profiles are trusted package data, but they are still parsed and bounded fail-closed so a
//! packaging defect cannot silently broaden a launch. This module performs lexical validation
//! only. Home expansion, filesystem discovery, and canonicalization belong to the CLI resolver.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use serde::{Deserialize, Deserializer, de};
use thiserror::Error;

use crate::{AccessMode, PathScope};

/// Schema version accepted for embedded profile documents.
pub const PROFILE_SCHEMA_V2: u32 = 2;
/// Fallback profile used when no known binary name is detected.
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
    /// Parses an absolute or `~/`-relative profile path without ambient filesystem access.
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
    /// Returns the original, unexpanded template spelling.
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
    // A fixed synthetic root lets `Path::components` perform lexical checks without pretending
    // to know the user's home directory. The returned path never leaves profile validation.
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

/// Filesystem grant declared by a profile before CLI-side path resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantTemplate {
    /// Absolute or home-relative path template.
    pub path: TemplatePath,
    /// Requested read or read/write access.
    pub access: AccessMode,
    /// Exact-node or recursive matching semantics.
    pub scope: PathScope,
    /// Whether a missing path is skipped instead of making profile resolution fail.
    pub if_exists: bool,
}

/// Agent-owned hook configuration grammar understood by an integration adapter.
///
/// Profiles identify protocol shape, not provider policy. For example, a Codex hook source may
/// contain a Kontext integration today and a different verified service later.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum HookProtocol {
    /// Claude Code settings and managed-settings hook grammar.
    ClaudeSettings,
    /// Codex `hooks.json` grammar.
    CodexHooks,
}

/// One location where the CLI may discover hooks for a known agent protocol.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct HookSourceTemplate {
    /// Parser and validation contract for the source.
    pub protocol: HookProtocol,
    /// Absolute or home-relative source location.
    pub path: TemplatePath,
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

/// Binary-name detection rules declared by a profile.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectSpec {
    /// Exact executable basenames claimed by this profile.
    #[serde(default)]
    pub binary_names: Vec<String>,
}

/// Strictly typed version-2 embedded profile document.
///
/// This is the deserialized document shape, before inheritance is resolved. Unknown fields are
/// rejected to prevent misspelled security settings from being ignored.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDocumentV2 {
    /// Profile schema version; must equal [`PROFILE_SCHEMA_V2`].
    pub schema_version: u32,
    /// Stable lowercase profile identifier and embedded source name.
    pub name: String,
    /// Whether the profile exists only as an inheritance base.
    #[serde(default, rename = "abstract")]
    pub is_abstract: bool,
    /// Optional single base profile. A vector is accepted for schema ergonomics but multiple bases
    /// are rejected during registry construction.
    #[serde(default, deserialize_with = "deserialize_extends")]
    pub extends: Vec<String>,
    /// Executable basenames used for automatic profile selection.
    #[serde(default)]
    pub detect: DetectSpec,
    /// Filesystem capabilities contributed by the profile.
    #[serde(default)]
    pub grants: Vec<GrantTemplate>,
    /// Read-and-write protected subtrees contributed by the profile.
    #[serde(default)]
    pub protected_paths: Vec<TemplatePath>,
    /// Readable but immutable exact paths contributed by the profile.
    #[serde(default)]
    pub protected_write_paths: Vec<TemplatePath>,
    /// Agent hook sources available to optional runtime-control adapters.
    #[serde(default)]
    pub hook_sources: Vec<HookSourceTemplate>,
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

/// Fully inherited profile containing templates ready for CLI-side ambient resolution.
#[derive(Clone, Debug)]
pub struct ResolvedProfile {
    name: String,
    detect: DetectSpec,
    grants: Vec<GrantTemplate>,
    protected_paths: Vec<TemplatePath>,
    protected_write_paths: Vec<TemplatePath>,
    hook_sources: Vec<HookSourceTemplate>,
}

impl ResolvedProfile {
    /// Returns the selected profile name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns all inherited executable basenames in deterministic base-first order.
    #[must_use]
    pub fn binary_names(&self) -> &[String] {
        &self.detect.binary_names
    }

    /// Returns all inherited filesystem grants after exact-duplicate removal.
    #[must_use]
    pub fn grants(&self) -> &[GrantTemplate] {
        &self.grants
    }

    /// Returns inherited read-and-write protected subtrees.
    #[must_use]
    pub fn protected_paths(&self) -> &[TemplatePath] {
        &self.protected_paths
    }

    /// Returns inherited readable-but-immutable exact paths.
    #[must_use]
    pub fn protected_write_paths(&self) -> &[TemplatePath] {
        &self.protected_write_paths
    }

    /// Returns inherited typed hook sources.
    #[must_use]
    pub fn hook_sources(&self) -> &[HookSourceTemplate] {
        &self.hook_sources
    }
}

/// Validated registry of every profile embedded in the Sandy binary.
///
/// Separate maps make profile lookup and automatic binary detection deterministic. Construction
/// rejects ambiguous detection claims before any target can be launched.
#[derive(Debug)]
pub struct ProfileRegistry {
    documents: BTreeMap<String, ProfileDocumentV2>,
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
            let document: ProfileDocumentV2 = serde_json::from_str(source)
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
    /// Returns every embedded profile name, including inheritance-only profiles.
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

    fn extend_chain(&self, name: &str) -> Result<Vec<&ProfileDocumentV2>, ProfileError> {
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut cursor = Some(name);
        while let Some(current) = cursor {
            // Bound traversal before following another edge so a malicious cycle and an overly
            // deep acyclic chain consume the same small, deterministic amount of work.
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
        // Documents were discovered child-to-base. Reversing makes merge order explicit and lets
        // exact duplicate removal retain the base declaration's stable position.
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
    hook_sources: Vec<HookSourceTemplate>,
}

impl MergedProfile {
    fn absorb(&mut self, document: &ProfileDocumentV2) {
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
        push_unique(&mut self.hook_sources, &document.hook_sources);
    }

    fn finish(self, name: &str) -> Result<ResolvedProfile, ProfileError> {
        // Bounds apply after inheritance because every individual embedded document may be small
        // while their resolved union is still large enough to stress later policy generation.
        if self.grants.len() > MAX_RESOLVED_GRANTS {
            return Err(ProfileError::TooManyGrants(name.to_owned()));
        }
        for (field, paths) in [
            ("protected_paths", &self.protected_paths),
            ("protected_write_paths", &self.protected_write_paths),
        ] {
            if paths.len() > MAX_RESOLVED_PATHS {
                return Err(ProfileError::TooManyPaths {
                    profile: name.to_owned(),
                    field: field.to_owned(),
                });
            }
        }
        if self.hook_sources.len() > MAX_RESOLVED_PATHS {
            return Err(ProfileError::TooManyPaths {
                profile: name.to_owned(),
                field: "hook_sources".to_owned(),
            });
        }
        Ok(ResolvedProfile {
            name: name.to_owned(),
            detect: self.detect,
            grants: self.grants,
            protected_paths: self.protected_paths,
            protected_write_paths: self.protected_write_paths,
            hook_sources: self.hook_sources,
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

fn check_schema(source_name: &str, document: &ProfileDocumentV2) -> Result<(), ProfileError> {
    if document.schema_version != PROFILE_SCHEMA_V2 {
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

/// Failure to parse, register, or deterministically resolve an embedded profile.
#[derive(Debug, Error)]
pub enum ProfileError {
    /// One embedded JSON source exceeds its input bound.
    #[error("profile source {0} exceeds the embedded profile limit")]
    TooLarge(String),
    /// An embedded source is malformed or violates its strict document shape.
    #[error("profile {0} is not valid JSON: {1}")]
    Parse(String, #[source] serde_json::Error),
    /// A document declares a schema version this binary does not understand.
    #[error("profile {name} declares unsupported schema version {version}")]
    UnsupportedSchema {
        /// Declared profile name.
        name: String,
        /// Unsupported schema version.
        version: u32,
    },
    /// The registry key and document-declared name disagree.
    #[error("profile file {source_name:?} declares mismatched profile name {declared:?}")]
    NameMismatch {
        /// Name used by the embedded registry entry.
        source_name: String,
        /// Name declared inside the JSON document.
        declared: String,
    },
    /// A profile identifier violates the stable-name grammar.
    #[error("profile name {0:?} is invalid")]
    InvalidName(String),
    /// An automatic-detection entry is not a plain executable basename.
    #[error("detected binary name {0:?} is invalid")]
    InvalidBinaryName(String),
    /// More than one embedded source declares the same profile name.
    #[error("duplicate agent profile {0:?}")]
    DuplicateProfile(String),
    /// Version 2 supports deterministic single inheritance only.
    #[error("profile {0:?} extends more than one base profile")]
    MultipleBases(String),
    /// An inheritance-only profile incorrectly participates in automatic detection.
    #[error("abstract profile {0:?} cannot claim a detected binary name")]
    AbstractDetection(String),
    /// A path template violates its lexical grammar or bound.
    #[error("profile path is invalid: {0}")]
    InvalidTemplate(String),
    /// A requested profile or inherited base is absent.
    #[error("unknown agent profile {0:?}")]
    UnknownProfile(String),
    /// An inheritance-only profile was selected for a launch.
    #[error("profile {0:?} is inheritance-only and cannot be selected")]
    AbstractProfile(String),
    /// The inheritance graph contains a cycle.
    #[error("agent profile inheritance cycle at {0:?}")]
    Cycle(String),
    /// The inheritance graph exceeds the supported traversal depth.
    #[error("agent profile inheritance depth exceeded at {0:?}")]
    DepthExceeded(String),
    /// Two profiles claim the same executable basename.
    #[error("profiles {first:?} and {second:?} both claim binary {binary_name:?}")]
    DuplicateDetection {
        /// Ambiguous executable basename.
        binary_name: String,
        /// First profile that claimed the basename.
        first: String,
        /// Later conflicting profile.
        second: String,
    },
    /// Inheritance produced more filesystem grants than a launch may safely carry.
    #[error("resolved profile {0} has too many filesystem grants")]
    TooManyGrants(String),
    /// Inheritance produced too many entries in a path-bearing field.
    #[error("resolved profile {profile} field {field} exceeds its bound")]
    TooManyPaths {
        /// Profile being resolved.
        profile: String,
        /// Bounded field that overflowed.
        field: String,
    },
}
