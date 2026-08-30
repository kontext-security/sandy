//! Side-effect-free policy intent shared by Sandy's CLI and Rust facade.
//!
//! This module stores caller-supplied paths without consulting the filesystem.
//! A trusted boundary must resolve and canonicalize every entry before lowering
//! it into [`crate::PolicySpec`].

use std::path::PathBuf;

use serde::Deserialize;
use thiserror::Error;

use crate::{AccessMode, FileMetadataPolicy, NetworkPolicy, PathScope};

const MAX_REQUESTED_GRANTS: usize = 1_024;
const MAX_REQUESTED_EXECUTABLES: usize = 1_024;
const MAX_REQUESTED_DENIES: usize = 1_024;
const MAX_POLICY_DOCUMENT_BYTES: usize = 64 * 1024;
const POLICY_DOCUMENT_SCHEMA_V1: u32 = 1;

#[derive(Deserialize)]
struct PolicyDocumentVersion {
    schema_version: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocumentV1 {
    #[serde(rename = "schema_version")]
    _schema_version: u32,
    network: DocumentNetworkPolicyV1,
    #[serde(default)]
    allow_subprocesses: bool,
    #[serde(default)]
    grants: Vec<DocumentGrantV1>,
    #[serde(default)]
    executable_grants: Vec<DocumentExecutableGrantV1>,
    #[serde(default)]
    deny_subtrees: Vec<PathBuf>,
    #[serde(default)]
    deny_write_exact: Vec<PathBuf>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum DocumentNetworkPolicyV1 {
    AllowAll,
    BlockAll,
}

impl From<DocumentNetworkPolicyV1> for NetworkPolicy {
    fn from(policy: DocumentNetworkPolicyV1) -> Self {
        match policy {
            DocumentNetworkPolicyV1::AllowAll => Self::AllowAll,
            DocumentNetworkPolicyV1::BlockAll => Self::BlockAll,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum DocumentAccessModeV1 {
    Read,
    ReadWrite,
}

impl From<DocumentAccessModeV1> for AccessMode {
    fn from(access: DocumentAccessModeV1) -> Self {
        match access {
            DocumentAccessModeV1::Read => Self::Read,
            DocumentAccessModeV1::ReadWrite => Self::ReadWrite,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum DocumentPathScopeV1 {
    Exact,
    Subtree,
}

impl From<DocumentPathScopeV1> for PathScope {
    fn from(scope: DocumentPathScopeV1) -> Self {
        match scope {
            DocumentPathScopeV1::Exact => Self::Exact,
            DocumentPathScopeV1::Subtree => Self::Subtree,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentGrantV1 {
    path: PathBuf,
    access: DocumentAccessModeV1,
    scope: DocumentPathScopeV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentExecutableGrantV1 {
    path: PathBuf,
    scope: DocumentPathScopeV1,
}

/// Complete filesystem and network intent supplied to a Sandy enforcement boundary.
///
/// Construction performs no filesystem access. Relative paths retain their
/// original meaning until the owning boundary captures a working-directory
/// snapshot and resolves them.
#[must_use]
pub struct SandboxPolicy {
    network: NetworkPolicy,
    grants: Vec<UnresolvedGrant>,
    executables: Vec<UnresolvedExecutable>,
    denied_subtrees: Vec<PathBuf>,
    write_denied_exact: Vec<PathBuf>,
    file_metadata: FileMetadataPolicy,
    allow_subprocesses: bool,
    runtime_compatibility: crate::RuntimeCompatibility,
}

impl SandboxPolicy {
    /// Parses one strict, bounded, versioned JSON policy document.
    ///
    /// Parsing performs no filesystem access. Relative paths retain their
    /// meaning until the owning enforcement boundary resolves the returned
    /// policy. Unknown fields, unsupported versions, and oversized capability
    /// sections are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyDocumentError`] when the source is too large, malformed,
    /// uses an unsupported version, or exceeds a capability limit.
    pub fn from_json(source: &[u8]) -> Result<Self, PolicyDocumentError> {
        if source.len() > MAX_POLICY_DOCUMENT_BYTES {
            return Err(PolicyDocumentError::TooLarge);
        }
        // Dispatch on the version before applying version-specific strictness,
        // so a newer document receives an actionable version error.
        let version: PolicyDocumentVersion =
            serde_json::from_slice(source).map_err(|error| PolicyDocumentError::Parse {
                line: error.line(),
                column: error.column(),
            })?;
        if version.schema_version != POLICY_DOCUMENT_SCHEMA_V1 {
            return Err(PolicyDocumentError::UnsupportedVersion(
                version.schema_version,
            ));
        }
        let document: PolicyDocumentV1 =
            serde_json::from_slice(source).map_err(|error| PolicyDocumentError::Parse {
                line: error.line(),
                column: error.column(),
            })?;

        let mut policy = Self::new(document.network.into());
        policy.allow_subprocesses = document.allow_subprocesses;
        policy.grants = document
            .grants
            .into_iter()
            .map(|grant| UnresolvedGrant {
                path: grant.path,
                access: grant.access.into(),
                scope: grant.scope.into(),
            })
            .collect();
        policy.executables = document
            .executable_grants
            .into_iter()
            .map(|grant| UnresolvedExecutable {
                path: grant.path,
                scope: grant.scope.into(),
            })
            .collect();
        policy.denied_subtrees = document.deny_subtrees;
        policy.write_denied_exact = document.deny_write_exact;
        validate_policy_intent(&policy).map_err(|_| PolicyDocumentError::TooManyCapabilities)?;
        Ok(policy)
    }

    /// Creates an empty filesystem policy with explicit network behavior.
    pub fn new(network: NetworkPolicy) -> Self {
        Self {
            network,
            grants: Vec::new(),
            executables: Vec::new(),
            denied_subtrees: Vec::new(),
            write_denied_exact: Vec::new(),
            file_metadata: FileMetadataPolicy::Deny,
            allow_subprocesses: false,
            runtime_compatibility: crate::RuntimeCompatibility::Minimal,
        }
    }

    /// Grants read or read/write access to one path or subtree.
    ///
    /// The path is resolved only when the owning enforcement boundary prepares
    /// the policy. This method does not grant access to the current directory.
    pub fn grant(mut self, path: impl Into<PathBuf>, access: AccessMode, scope: PathScope) -> Self {
        self.grants.push(UnresolvedGrant {
            path: path.into(),
            access,
            scope,
        });
        self
    }

    /// Allows native executable mapping from one exact path or subtree.
    ///
    /// With [`SandboxPolicy::allow_subprocesses`], this also permits launching
    /// a matching executable. It does not grant ordinary file reads or writes;
    /// add a separate [`SandboxPolicy::grant`] for data access.
    pub fn allow_execute(mut self, path: impl Into<PathBuf>, scope: PathScope) -> Self {
        self.executables.push(UnresolvedExecutable {
            path: path.into(),
            scope,
        });
        self
    }

    /// Allows ordinary descendant process creation and platform runtime services.
    ///
    /// Executable path mapping and launch authority remain scoped by
    /// [`SandboxPolicy::allow_execute`]. On macOS, subprocess compatibility
    /// includes broad Mach lookup and same-user local services; callers should
    /// enable it only when they need descendants.
    pub fn allow_subprocesses(mut self) -> Self {
        self.allow_subprocesses = true;
        self
    }

    /// Denies reads, writes, executable mapping, and launch to a subtree.
    ///
    /// This terminal restriction overrides overlapping grants independently of
    /// builder call order.
    pub fn deny_subtree(mut self, path: impl Into<PathBuf>) -> Self {
        self.denied_subtrees.push(path.into());
        self
    }

    /// Denies writes to exactly one path without granting read access.
    ///
    /// A separate grant is required when the restricted process must read the
    /// entry. During preparation, Sandy also pins writable ancestors between
    /// this entry and an enclosing recursive write grant so the entry cannot be
    /// relocated through an ancestor rename. Adjacent entries remain writable.
    pub fn deny_write_exact(mut self, path: impl Into<PathBuf>) -> Self {
        self.write_denied_exact.push(path.into());
        self
    }
}

/// One unresolved positive filesystem intent.
///
/// This is an implementation-crate handoff and is not re-exported by the
/// supported facade.
#[doc(hidden)]
pub struct UnresolvedGrant {
    /// Caller-supplied path, potentially relative.
    pub path: PathBuf,
    /// Requested filesystem operations.
    pub access: AccessMode,
    /// Exact or recursive matching semantics.
    pub scope: PathScope,
}

/// One unresolved executable-mapping intent.
#[doc(hidden)]
pub struct UnresolvedExecutable {
    /// Caller-supplied path, potentially relative.
    pub path: PathBuf,
    /// Exact or recursive matching semantics.
    pub scope: PathScope,
}

/// Decomposed policy intent consumed by trusted ambient-resolution owners.
///
/// This is an implementation-crate handoff and is not re-exported by the
/// supported facade.
#[doc(hidden)]
pub struct SandboxPolicyParts {
    /// Explicit network behavior.
    pub network: NetworkPolicy,
    /// Positive filesystem intents.
    pub grants: Vec<UnresolvedGrant>,
    /// Positive executable-mapping intents.
    pub executables: Vec<UnresolvedExecutable>,
    /// Recursive read/write denies.
    pub denied_subtrees: Vec<PathBuf>,
    /// Exact write denies.
    pub write_denied_exact: Vec<PathBuf>,
    /// Explicit metadata behavior selected by an internal product boundary.
    pub file_metadata: FileMetadataPolicy,
    /// Whether ordinary descendant process startup is enabled.
    pub allow_subprocesses: bool,
    /// Explicit compatibility behavior selected by an internal product boundary.
    pub runtime_compatibility: crate::RuntimeCompatibility,
}

impl SandboxPolicyParts {
    /// Checks product-owned unresolved contributions before ambient expansion.
    ///
    /// Sibling packages use this when a typed product intent deliberately
    /// stays outside the supported facade builder until one shared path
    /// resolution produces multiple independent capabilities.
    #[doc(hidden)]
    pub fn check_additional_bounds(
        &self,
        grants: usize,
        executables: usize,
    ) -> Result<(), PolicyIntentError> {
        if self
            .grants
            .len()
            .checked_add(grants)
            .is_none_or(|count| count > MAX_REQUESTED_GRANTS)
        {
            return Err(PolicyIntentError::TooManyGrants);
        }
        if self
            .executables
            .len()
            .checked_add(executables)
            .is_none_or(|count| count > MAX_REQUESTED_EXECUTABLES)
        {
            return Err(PolicyIntentError::TooManyExecutables);
        }
        Ok(())
    }
}

/// Enables the CLI's typed macOS metadata compatibility capability.
///
/// This function is intentionally not re-exported by the supported facade.
#[doc(hidden)]
pub fn allow_file_metadata(mut policy: SandboxPolicy) -> SandboxPolicy {
    policy.file_metadata = FileMetadataPolicy::Allow;
    policy
}

/// Enables the CLI's foreground compatibility behavior.
///
/// This function is intentionally not re-exported by the supported facade.
#[doc(hidden)]
pub fn allow_foreground_cli_compatibility(mut policy: SandboxPolicy) -> SandboxPolicy {
    policy.allow_subprocesses = true;
    policy.runtime_compatibility = crate::RuntimeCompatibility::ForegroundCli;
    policy
}

/// Checks request bounds before ambient path expansion and returns its parts.
///
/// The function is public only for sibling workspace packages. It is not part
/// of the supported `sandy-sandbox` facade.
#[doc(hidden)]
pub fn into_policy_parts(policy: SandboxPolicy) -> Result<SandboxPolicyParts, PolicyIntentError> {
    validate_policy_intent(&policy)?;
    Ok(SandboxPolicyParts {
        network: policy.network,
        grants: policy.grants,
        executables: policy.executables,
        denied_subtrees: policy.denied_subtrees,
        write_denied_exact: policy.write_denied_exact,
        file_metadata: policy.file_metadata,
        allow_subprocesses: policy.allow_subprocesses,
        runtime_compatibility: policy.runtime_compatibility,
    })
}

fn validate_policy_intent(policy: &SandboxPolicy) -> Result<(), PolicyIntentError> {
    if policy.grants.len() > MAX_REQUESTED_GRANTS {
        return Err(PolicyIntentError::TooManyGrants);
    }
    if policy.executables.len() > MAX_REQUESTED_EXECUTABLES {
        return Err(PolicyIntentError::TooManyExecutables);
    }
    if policy.denied_subtrees.len() > MAX_REQUESTED_DENIES
        || policy.write_denied_exact.len() > MAX_REQUESTED_DENIES
    {
        return Err(PolicyIntentError::TooManyDenies);
    }
    Ok(())
}

/// Failure to parse or bound a serialized sandbox policy.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum PolicyDocumentError {
    /// The source exceeds Sandy's policy-document size limit.
    #[error("sandbox policy document is too large")]
    TooLarge,
    /// The source is not strict JSON matching the supported document shape.
    #[error("sandbox policy document is invalid at line {line}, column {column}")]
    Parse {
        /// One-based source line reported by the JSON parser.
        line: usize,
        /// One-based source column reported by the JSON parser.
        column: usize,
    },
    /// The document names a schema version this release does not implement.
    #[error("unsupported sandbox policy schema version {0}")]
    UnsupportedVersion(u32),
    /// At least one capability section exceeds its entry limit.
    #[error("sandbox policy document contains too many capabilities")]
    TooManyCapabilities,
}

/// Failure to validate bounded caller policy intent.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PolicyIntentError {
    /// The caller supplied more positive filesystem intents than Sandy accepts.
    #[error("policy contains too many filesystem grants")]
    TooManyGrants,
    /// The caller supplied more executable mappings than Sandy accepts.
    #[error("policy contains too many executable mappings")]
    TooManyExecutables,
    /// The caller supplied more terminal filesystem denies than Sandy accepts.
    #[error("policy contains too many filesystem denies")]
    TooManyDenies,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_builder_order_without_filesystem_access() -> Result<(), Box<dyn std::error::Error>>
    {
        let parts = into_policy_parts(
            SandboxPolicy::new(NetworkPolicy::BlockAll)
                .allow_subprocesses()
                .grant("relative", AccessMode::Read, PathScope::Exact)
                .allow_execute("tool", PathScope::Exact)
                .deny_subtree("private")
                .deny_write_exact("settings.json"),
        )?;

        assert_eq!(parts.network, NetworkPolicy::BlockAll);
        assert!(parts.allow_subprocesses);
        assert_eq!(parts.grants[0].path, PathBuf::from("relative"));
        assert_eq!(parts.executables[0].path, PathBuf::from("tool"));
        assert_eq!(parts.denied_subtrees, [PathBuf::from("private")]);
        assert_eq!(parts.write_denied_exact, [PathBuf::from("settings.json")]);
        Ok(())
    }

    #[test]
    fn parses_complete_document_without_filesystem_access() -> Result<(), Box<dyn std::error::Error>>
    {
        let policy = SandboxPolicy::from_json(
            br#"{
                "schema_version": 1,
                "network": "block_all",
                "allow_subprocesses": true,
                "grants": [
                    {"path": "missing/workspace", "access": "read_write", "scope": "subtree"}
                ],
                "executable_grants": [
                    {"path": "missing/workspace", "scope": "subtree"}
                ],
                "deny_subtrees": ["missing/workspace/credentials"],
                "deny_write_exact": ["missing/workspace/settings.json"]
            }"#,
        )?;
        let parts = into_policy_parts(policy)?;

        assert_eq!(parts.network, NetworkPolicy::BlockAll);
        assert!(parts.allow_subprocesses);
        assert_eq!(parts.grants.len(), 1);
        assert_eq!(parts.grants[0].path, PathBuf::from("missing/workspace"));
        assert_eq!(parts.grants[0].access, AccessMode::ReadWrite);
        assert_eq!(parts.grants[0].scope, PathScope::Subtree);
        assert_eq!(parts.executables.len(), 1);
        assert_eq!(
            parts.executables[0].path,
            PathBuf::from("missing/workspace")
        );
        assert_eq!(parts.executables[0].scope, PathScope::Subtree);
        assert_eq!(
            parts.denied_subtrees,
            [PathBuf::from("missing/workspace/credentials")]
        );
        assert_eq!(
            parts.write_denied_exact,
            [PathBuf::from("missing/workspace/settings.json")]
        );
        Ok(())
    }

    #[test]
    fn rejects_unknown_fields_and_missing_required_fields() {
        for source in [
            br#"{"schema_version":1,"network":"block_all","extra":true}"#.as_slice(),
            br#"{"schema_version":1}"#.as_slice(),
            br#"{"network":"block_all"}"#.as_slice(),
            br#"{"schema_version":1,"network":"block_all","grants":[{"path":"p","access":"read","scope":"exact","extra":true}]}"#.as_slice(),
            &[0xff],
        ] {
            assert!(matches!(
                SandboxPolicy::from_json(source),
                Err(PolicyDocumentError::Parse { .. })
            ));
        }
    }

    #[test]
    fn version_one_vocabulary_is_frozen() {
        for source in [
            br#"{"schema_version":1,"network":"filtered"}"#.as_slice(),
            br#"{"schema_version":1,"network":"block_all","grants":[{"path":"p","access":"write","scope":"exact"}]}"#.as_slice(),
            br#"{"schema_version":1,"network":"block_all","grants":[{"path":"p","access":"read","scope":"recursive"}]}"#.as_slice(),
            br#"{"schema_version":1,"network":"block_all","executable_grants":[{"path":"p","scope":"recursive"}]}"#.as_slice(),
        ] {
            assert!(matches!(
                SandboxPolicy::from_json(source),
                Err(PolicyDocumentError::Parse { .. })
            ));
        }
    }

    #[test]
    fn rejects_unsupported_versions() {
        assert_eq!(
            SandboxPolicy::from_json(
                br#"{"schema_version":2,"network":"block_all","future_field":true}"#
            )
            .err(),
            Some(PolicyDocumentError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn defaults_optional_capabilities_to_empty() -> Result<(), Box<dyn std::error::Error>> {
        let parts = into_policy_parts(SandboxPolicy::from_json(
            br#"{"schema_version":1,"network":"block_all"}"#,
        )?)?;

        assert_eq!(parts.network, NetworkPolicy::BlockAll);
        assert!(!parts.allow_subprocesses);
        assert!(parts.grants.is_empty());
        assert!(parts.executables.is_empty());
        assert!(parts.denied_subtrees.is_empty());
        assert!(parts.write_denied_exact.is_empty());
        Ok(())
    }

    #[test]
    fn bounds_document_bytes_and_capabilities() {
        let oversized = vec![b' '; MAX_POLICY_DOCUMENT_BYTES + 1];
        assert_eq!(
            SandboxPolicy::from_json(&oversized).err(),
            Some(PolicyDocumentError::TooLarge)
        );

        for (field, entry, limit) in [
            (
                "grants",
                r#"{"path":"p","access":"read","scope":"exact"}"#,
                MAX_REQUESTED_GRANTS,
            ),
            (
                "executable_grants",
                r#"{"path":"p","scope":"exact"}"#,
                MAX_REQUESTED_EXECUTABLES,
            ),
            ("deny_subtrees", r#""p""#, MAX_REQUESTED_DENIES),
            ("deny_write_exact", r#""p""#, MAX_REQUESTED_DENIES),
        ] {
            let entries = (0..=limit).map(|_| entry).collect::<Vec<_>>().join(",");
            let source =
                format!(r#"{{"schema_version":1,"network":"block_all","{field}":[{entries}]}}"#);
            assert!(source.len() <= MAX_POLICY_DOCUMENT_BYTES);
            assert_eq!(
                SandboxPolicy::from_json(source.as_bytes()).err(),
                Some(PolicyDocumentError::TooManyCapabilities)
            );
        }
    }

    #[test]
    fn parse_errors_do_not_disclose_policy_contents() -> Result<(), Box<dyn std::error::Error>> {
        let sensitive = "/private/credential-name-must-not-appear";
        let source = format!(
            r#"{{"schema_version":1,"network":"block_all","grants":[{{"path":"{sensitive}","access":"read","scope":"exact","unexpected":true}}]}}"#
        );
        let error = SandboxPolicy::from_json(source.as_bytes())
            .err()
            .ok_or("the unknown field must be rejected")?;

        assert!(!error.to_string().contains(sensitive));
        assert!(!format!("{error:?}").contains(sensitive));
        Ok(())
    }

    #[test]
    fn bounds_requests_before_resolution() {
        let mut policy = SandboxPolicy::new(NetworkPolicy::BlockAll);
        for index in 0..=MAX_REQUESTED_GRANTS {
            policy = policy.grant(format!("path-{index}"), AccessMode::Read, PathScope::Exact);
        }
        assert!(matches!(
            into_policy_parts(policy),
            Err(PolicyIntentError::TooManyGrants)
        ));

        let mut policy = SandboxPolicy::new(NetworkPolicy::BlockAll);
        for index in 0..=MAX_REQUESTED_EXECUTABLES {
            policy = policy.allow_execute(format!("tool-{index}"), PathScope::Exact);
        }
        assert!(matches!(
            into_policy_parts(policy),
            Err(PolicyIntentError::TooManyExecutables)
        ));
    }

    #[test]
    fn bounds_product_owned_intent_before_resolution() -> Result<(), PolicyIntentError> {
        let parts = into_policy_parts(SandboxPolicy::new(NetworkPolicy::BlockAll).grant(
            "base",
            AccessMode::Read,
            PathScope::Exact,
        ))?;

        assert!(matches!(
            parts.check_additional_bounds(MAX_REQUESTED_GRANTS, 0),
            Err(PolicyIntentError::TooManyGrants)
        ));
        assert!(matches!(
            parts.check_additional_bounds(0, MAX_REQUESTED_EXECUTABLES + 1),
            Err(PolicyIntentError::TooManyExecutables)
        ));
        Ok(())
    }
}
