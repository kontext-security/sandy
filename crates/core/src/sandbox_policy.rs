//! Side-effect-free policy intent shared by Sandy's CLI and Rust facade.
//!
//! This module stores caller-supplied paths without consulting the filesystem.
//! A trusted boundary must resolve and canonicalize every entry before lowering
//! it into [`crate::PolicySpec`].

use std::path::PathBuf;

use thiserror::Error;

use crate::{AccessMode, FileMetadataPolicy, NetworkPolicy, PathScope};

const MAX_REQUESTED_GRANTS: usize = 1_024;
const MAX_REQUESTED_EXECUTABLES: usize = 1_024;
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
    executables: Vec<UnresolvedExecutable>,
    denied_subtrees: Vec<PathBuf>,
    write_denied_exact: Vec<PathBuf>,
    file_metadata: FileMetadataPolicy,
    allow_subprocesses: bool,
    runtime_compatibility: crate::RuntimeCompatibility,
}

impl SandboxPolicy {
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
