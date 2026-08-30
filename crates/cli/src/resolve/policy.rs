//! CLI-owned composition and ambient resolution for shared policy intent.

use std::path::{Path, PathBuf};

use sandy_core::{
    AbsolutePath, AccessMode, ExecutableGrant, FileGrant, PathScope, ResolvedPolicyDraft,
    SandboxPolicy, into_policy_parts,
};

use crate::error::AppError;

use super::{absolute_if_utf8, grant, scoped_write_protections};

/// Unresolved CLI policy plus file capabilities that require the CLI's
/// existing executable-mapping compatibility.
///
/// Keeping the pair as one typed intent ensures ambient resolution happens
/// once. The resolved filesystem identity is then shared by the independent
/// file and executable capabilities.
#[must_use]
pub(crate) struct CliPolicyIntent {
    policy: SandboxPolicy,
    execution_compatible_files: Vec<ExecutionCompatibleFile>,
    resolved_files: Vec<FileGrant>,
}

struct ExecutionCompatibleFile {
    path: PathBuf,
    access: AccessMode,
    scope: PathScope,
}

impl CliPolicyIntent {
    pub(crate) fn new(policy: SandboxPolicy) -> Self {
        Self {
            policy,
            execution_compatible_files: Vec::new(),
            resolved_files: Vec::new(),
        }
    }

    pub(crate) fn grant_file(
        mut self,
        path: impl Into<PathBuf>,
        access: AccessMode,
        scope: PathScope,
    ) -> Self {
        self.policy = self.policy.grant(path, access, scope);
        self
    }

    pub(crate) fn grant_with_execution_compatibility(
        mut self,
        path: impl Into<PathBuf>,
        access: AccessMode,
        scope: PathScope,
    ) -> Self {
        self.execution_compatible_files
            .push(ExecutionCompatibleFile {
                path: path.into(),
                access,
                scope,
            });
        self
    }

    /// Adds a file capability already resolved by this product boundary.
    ///
    /// This is intentionally file-only. It is used when another launch field
    /// must consume the exact same resolved path without a second filesystem
    /// lookup.
    pub(crate) fn grant_resolved_file(mut self, grant: FileGrant) -> Self {
        self.resolved_files.push(grant);
        self
    }

    pub(crate) fn deny_subtree(mut self, path: impl Into<PathBuf>) -> Self {
        self.policy = self.policy.deny_subtree(path);
        self
    }

    pub(crate) fn deny_write_exact(mut self, path: impl Into<PathBuf>) -> Self {
        self.policy = self.policy.deny_write_exact(path);
        self
    }
}

pub(crate) fn resolve_policy(
    intent: CliPolicyIntent,
    protected: &[AbsolutePath],
) -> Result<ResolvedPolicyDraft, AppError> {
    let CliPolicyIntent {
        policy,
        execution_compatible_files,
        resolved_files,
    } = intent;
    let parts = into_policy_parts(policy)?;
    parts.check_additional_bounds(
        execution_compatible_files
            .len()
            .checked_add(resolved_files.len())
            .ok_or(sandy_core::PolicyIntentError::TooManyGrants)?,
        execution_compatible_files.len(),
    )?;
    let mut draft = ResolvedPolicyDraft::new(parts.network);
    for unresolved in parts.grants {
        draft.add_file(grant(
            &unresolved.path,
            unresolved.access,
            unresolved.scope,
            protected,
        )?);
    }

    for unresolved in execution_compatible_files {
        let resolved = grant(
            &unresolved.path,
            unresolved.access,
            unresolved.scope,
            protected,
        )?;
        if !resolved.path.is_root() {
            draft.add_executable(ExecutableGrant {
                path: resolved.path.clone(),
                scope: resolved.scope,
            });
        }
        draft.add_file(resolved);
    }

    for resolved in resolved_files {
        draft.add_file(resolved);
    }

    for path in parts.denied_subtrees {
        if !path.is_absolute() || path == Path::new("/") {
            return Err(AppError::InvalidPolicyPath(path));
        }
        draft.add_protected_path(absolute_if_utf8(&path)?);
    }

    for unresolved in parts.executables {
        let resolved = grant(
            &unresolved.path,
            sandy_core::AccessMode::Read,
            unresolved.scope,
            protected,
        )?;
        draft.add_executable(ExecutableGrant {
            path: resolved.path,
            scope: resolved.scope,
        });
    }

    for path in parts.write_denied_exact {
        for protection in scoped_write_protections([path], PathScope::Exact)? {
            draft.add_write_protection(protection);
        }
    }

    draft.set_file_metadata(parts.file_metadata);
    draft.set_allow_subprocesses(parts.allow_subprocesses);
    draft.set_runtime_compatibility(parts.runtime_compatibility);
    Ok(draft)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use sandy_core::NetworkPolicy;

    use super::*;

    #[test]
    fn paired_capabilities_share_one_resolved_identity() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let target = root.path().join("target");
        let alias = root.path().join("alias");
        fs::create_dir(&target)?;
        symlink(&target, &alias)?;

        let policy = resolve_policy(
            CliPolicyIntent::new(SandboxPolicy::new(NetworkPolicy::BlockAll))
                .grant_with_execution_compatibility(alias, AccessMode::Read, PathScope::Subtree),
            &[],
        )?
        .finish()?
        .into_spec();
        let canonical = fs::canonicalize(target)?;

        assert_eq!(policy.files.len(), 1);
        assert_eq!(policy.executables.len(), 1);
        assert_eq!(policy.files[0].path.as_path(), canonical);
        assert_eq!(policy.executables[0].path, policy.files[0].path);
        assert_eq!(policy.executables[0].scope, policy.files[0].scope);
        Ok(())
    }

    #[test]
    fn root_alias_never_becomes_an_executable_mapping() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let alias = root.path().join("root-alias");
        symlink("/", &alias)?;

        let policy = resolve_policy(
            CliPolicyIntent::new(SandboxPolicy::new(NetworkPolicy::BlockAll))
                .grant_with_execution_compatibility(alias, AccessMode::Read, PathScope::Exact),
            &[],
        )?
        .finish()?
        .into_spec();

        assert_eq!(policy.files.len(), 1);
        assert!(policy.files[0].path.is_root());
        assert!(policy.executables.is_empty());
        Ok(())
    }

    #[test]
    fn resolved_file_capability_does_not_add_executable_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let bundle = root.path().join("roots.pem");
        fs::write(&bundle, "certificate")?;
        let resolved = grant(&bundle, AccessMode::Read, PathScope::Exact, &[])?;

        let policy = resolve_policy(
            CliPolicyIntent::new(SandboxPolicy::new(NetworkPolicy::BlockAll))
                .grant_resolved_file(resolved.clone()),
            &[],
        )?
        .finish()?
        .into_spec();

        assert_eq!(policy.files, [resolved]);
        assert!(policy.executables.is_empty());
        Ok(())
    }
}
