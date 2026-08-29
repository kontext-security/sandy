//! Side-effect-free policy intent shared by Sandy's CLI and Rust facade.
//!
//! This module stores caller-supplied paths without consulting the filesystem.
//! A trusted boundary must resolve and canonicalize every entry before lowering
//! it into [`crate::PolicySpec`].

use std::path::PathBuf;

use thiserror::Error;

use crate::{AccessMode, FileMetadataPolicy, NetworkPolicy, PathScope};

const MAX_REQUESTED_GRANTS: usize = 1_024;
const MAX_REQUESTED_DENIES: usize = 1_024;

/// Complete filesystem and network intent supplied to a Sandy enforcement boundary.
///
/// Construction performs no filesystem access. Relative paths retain their
/// original meaning until the owning boundary captures a working-directory
/// snapshot and resolves them.
#[must_use]
pub struct SandboxPolicy {
    network: NetworkPolicy,
    grants: Vec<UnresolvedGrant>,
    denied_subtrees: Vec<PathBuf>,
    write_denied_exact: Vec<PathBuf>,
    file_metadata: FileMetadataPolicy,
}

impl SandboxPolicy {
    /// Creates an empty filesystem policy with explicit network behavior.
    pub fn new(network: NetworkPolicy) -> Self {
        Self {
            network,
            grants: Vec::new(),
            denied_subtrees: Vec::new(),
            write_denied_exact: Vec::new(),
            file_metadata: FileMetadataPolicy::Deny,
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

    /// Denies reads and writes to a path and all descendants.
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
    /// entry.
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
    /// Recursive read/write denies.
    pub denied_subtrees: Vec<PathBuf>,
    /// Exact write denies.
    pub write_denied_exact: Vec<PathBuf>,
    /// Explicit metadata behavior selected by an internal product boundary.
    pub file_metadata: FileMetadataPolicy,
}

/// Enables the CLI's typed macOS metadata compatibility capability.
///
/// This function is intentionally not re-exported by the supported facade.
#[doc(hidden)]
pub fn allow_file_metadata(mut policy: SandboxPolicy) -> SandboxPolicy {
    policy.file_metadata = FileMetadataPolicy::Allow;
    policy
}

/// Checks request bounds before ambient path expansion and returns its parts.
///
/// The function is public only for sibling workspace packages. It is not part
/// of the supported `sandy-sandbox` facade.
#[doc(hidden)]
pub fn into_policy_parts(policy: SandboxPolicy) -> Result<SandboxPolicyParts, PolicyIntentError> {
    if policy.grants.len() > MAX_REQUESTED_GRANTS {
        return Err(PolicyIntentError::TooManyGrants);
    }
    if policy.denied_subtrees.len() > MAX_REQUESTED_DENIES
        || policy.write_denied_exact.len() > MAX_REQUESTED_DENIES
    {
        return Err(PolicyIntentError::TooManyDenies);
    }
    Ok(SandboxPolicyParts {
        network: policy.network,
        grants: policy.grants,
        denied_subtrees: policy.denied_subtrees,
        write_denied_exact: policy.write_denied_exact,
        file_metadata: policy.file_metadata,
    })
}

/// Failure to validate bounded caller policy intent.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PolicyIntentError {
    /// The caller supplied more positive filesystem intents than Sandy accepts.
    #[error("policy contains too many filesystem grants")]
    TooManyGrants,
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
                .grant("relative", AccessMode::Read, PathScope::Exact)
                .deny_subtree("private")
                .deny_write_exact("settings.json"),
        )?;

        assert_eq!(parts.network, NetworkPolicy::BlockAll);
        assert_eq!(parts.grants[0].path, PathBuf::from("relative"));
        assert_eq!(parts.denied_subtrees, [PathBuf::from("private")]);
        assert_eq!(parts.write_denied_exact, [PathBuf::from("settings.json")]);
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
    }
}
