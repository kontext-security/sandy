//! CLI-owned composition and ambient resolution for shared policy intent.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use sandy_core::{
    AbsolutePath, AccessMode, ExecutableGrant, FileGrant, PathScope, ResolvedPolicyDraft,
    SandboxPolicy, into_policy_parts,
};

use crate::error::AppError;

use super::{absolute_if_utf8, grant, scoped_write_protections};

/// Unresolved CLI policy plus product-owned paths that intentionally require
/// both ordinary file access and executable mapping.
///
/// Keeping the pair as one typed intent ensures ambient resolution happens
/// once. The resolved filesystem identity is then shared by the independent
/// file and executable capabilities.
#[must_use]
pub(crate) struct CliPolicyIntent {
    policy: SandboxPolicy,
    file_and_executable_grants: Vec<FileAndExecutableGrant>,
    resolved_files: Vec<FileGrant>,
    resolved_write_protections: Vec<sandy_core::WriteProtection>,
    user_profile_files: Vec<UserProfileFile>,
    user_profile_executables: Vec<UserProfileExecutable>,
}

struct FileAndExecutableGrant {
    path: PathBuf,
    access: AccessMode,
    scope: PathScope,
}

struct UserProfileFile {
    path: PathBuf,
    access: AccessMode,
    scope: PathScope,
    position: usize,
}

struct UserProfileExecutable {
    path: PathBuf,
    scope: PathScope,
    position: usize,
}

struct GrantResolver<'a> {
    protected: &'a [AbsolutePath],
    resolved: BTreeMap<PathBuf, AbsolutePath>,
}

impl<'a> GrantResolver<'a> {
    fn new(protected: &'a [AbsolutePath]) -> Self {
        Self {
            protected,
            resolved: BTreeMap::new(),
        }
    }

    fn resolve(
        &mut self,
        path: &Path,
        access: AccessMode,
        scope: PathScope,
    ) -> Result<FileGrant, AppError> {
        if let Some(resolved) = self.resolved.get(path) {
            if resolved.is_root() && (access != AccessMode::Read || scope != PathScope::Exact) {
                return Err(AppError::UnsafeWorkingDirectory);
            }
            return Ok(FileGrant {
                path: resolved.clone(),
                access,
                scope,
            });
        }
        let resolved = grant(path, access, scope, self.protected)?;
        self.resolved
            .insert(path.to_path_buf(), resolved.path.clone());
        Ok(resolved)
    }
}

impl CliPolicyIntent {
    pub(crate) fn new(policy: SandboxPolicy) -> Self {
        Self {
            policy,
            file_and_executable_grants: Vec::new(),
            resolved_files: Vec::new(),
            resolved_write_protections: Vec::new(),
            user_profile_files: Vec::new(),
            user_profile_executables: Vec::new(),
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

    /// Grants both ordinary file access and executable mapping to one resolved
    /// filesystem identity.
    pub(crate) fn grant_file_and_execute(
        mut self,
        path: impl Into<PathBuf>,
        access: AccessMode,
        scope: PathScope,
    ) -> Self {
        self.file_and_executable_grants
            .push(FileAndExecutableGrant {
                path: path.into(),
                access,
                scope,
            });
        self
    }

    pub(crate) fn grant_user_profile_file(
        mut self,
        path: impl Into<PathBuf>,
        access: AccessMode,
        scope: PathScope,
        position: usize,
    ) -> Self {
        self.user_profile_files.push(UserProfileFile {
            path: path.into(),
            access,
            scope,
            position,
        });
        self
    }

    pub(crate) fn allow_execute(mut self, path: impl Into<PathBuf>, scope: PathScope) -> Self {
        self.policy = self.policy.allow_execute(path, scope);
        self
    }

    pub(crate) fn allow_user_profile_execute(
        mut self,
        path: impl Into<PathBuf>,
        scope: PathScope,
        position: usize,
    ) -> Self {
        self.user_profile_executables.push(UserProfileExecutable {
            path: path.into(),
            scope,
            position,
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

    pub(crate) fn deny_resolved_write(mut self, protection: sandy_core::WriteProtection) -> Self {
        self.resolved_write_protections.push(protection);
        self
    }
}

pub(crate) fn resolve_policy(
    intent: CliPolicyIntent,
    protected: &[AbsolutePath],
) -> Result<ResolvedPolicyDraft, AppError> {
    let CliPolicyIntent {
        policy,
        file_and_executable_grants,
        resolved_files,
        resolved_write_protections,
        user_profile_files,
        user_profile_executables,
    } = intent;
    let parts = into_policy_parts(policy)?;
    parts.check_additional_bounds(
        file_and_executable_grants
            .len()
            .checked_add(resolved_files.len())
            .and_then(|count| count.checked_add(user_profile_files.len()))
            .ok_or(sandy_core::PolicyIntentError::TooManyGrants)?,
        file_and_executable_grants
            .len()
            .checked_add(user_profile_executables.len())
            .ok_or(sandy_core::PolicyIntentError::TooManyExecutables)?,
    )?;
    let mut draft = ResolvedPolicyDraft::new(parts.network);
    let mut resolver = GrantResolver::new(protected);
    for unresolved in parts.grants {
        draft.add_file(resolver.resolve(&unresolved.path, unresolved.access, unresolved.scope)?);
    }

    for unresolved in file_and_executable_grants {
        let resolved = resolver.resolve(&unresolved.path, unresolved.access, unresolved.scope)?;
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

    for unresolved in user_profile_files {
        let resolved = resolver
            .resolve(&unresolved.path, unresolved.access, unresolved.scope)
            .map_err(|error| AppError::UserProfileGrant {
                position: unresolved.position,
                reason: redacted_path_error(&error),
            })?;
        draft.add_file(resolved);
    }

    for unresolved in user_profile_executables {
        let resolved = resolver
            .resolve(&unresolved.path, AccessMode::Read, unresolved.scope)
            .map_err(|error| AppError::UserProfilePath {
                section: "executable_grants",
                position: unresolved.position,
                reason: redacted_path_error(&error),
            })?;
        if resolved.path.is_root() {
            return Err(AppError::UserProfilePath {
                section: "executable_grants",
                position: unresolved.position,
                reason: "cannot be the filesystem root",
            });
        }
        draft.add_executable(ExecutableGrant {
            path: resolved.path,
            scope: resolved.scope,
        });
    }

    for path in parts.denied_subtrees {
        if !path.is_absolute() || path == Path::new("/") {
            return Err(AppError::InvalidPolicyPath(path));
        }
        draft.add_protected_path(absolute_if_utf8(&path)?);
    }

    for unresolved in parts.executables {
        let resolved = resolver.resolve(
            &unresolved.path,
            sandy_core::AccessMode::Read,
            unresolved.scope,
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
    for protection in resolved_write_protections {
        draft.add_write_protection(protection);
    }

    draft.set_file_metadata(parts.file_metadata);
    draft.set_allow_subprocesses(parts.allow_subprocesses);
    draft.set_runtime_compatibility(parts.runtime_compatibility);
    Ok(draft)
}

fn redacted_path_error(error: &AppError) -> &'static str {
    match error {
        AppError::MissingPath(_) | AppError::Io { .. } => "is unavailable",
        AppError::ProtectedPath(_) => "overlaps protected data",
        _ => "is invalid",
    }
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
                .grant_file_and_execute(alias, AccessMode::Read, PathScope::Subtree),
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
                .grant_file_and_execute(alias, AccessMode::Read, PathScope::Exact),
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

    #[test]
    fn repeated_spelling_keeps_one_resolved_identity_after_symlink_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let first = root.path().join("first");
        let second = root.path().join("second");
        let alias = root.path().join("alias");
        fs::create_dir(&first)?;
        fs::create_dir(&second)?;
        symlink(&first, &alias)?;

        let mut resolver = GrantResolver::new(&[]);
        let file = resolver.resolve(&alias, AccessMode::Read, PathScope::Subtree)?;
        fs::remove_file(&alias)?;
        symlink(&second, &alias)?;
        let executable = resolver.resolve(&alias, AccessMode::Read, PathScope::Subtree)?;

        assert_eq!(file.path, executable.path);
        assert_eq!(file.path.as_path(), fs::canonicalize(first)?);
        Ok(())
    }

    #[test]
    fn user_executable_root_alias_is_rejected_with_positioned_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let alias = root.path().join("root-alias");
        symlink("/", &alias)?;

        let error = resolve_policy(
            CliPolicyIntent::new(SandboxPolicy::new(NetworkPolicy::BlockAll))
                .allow_user_profile_execute(alias, PathScope::Exact, 2),
            &[],
        )
        .err()
        .ok_or("root executable grant should fail")?;
        assert!(matches!(
            error,
            AppError::UserProfilePath {
                section: "executable_grants",
                position: 2,
                reason: "cannot be the filesystem root",
            }
        ));
        Ok(())
    }

    #[test]
    fn resolved_write_protections_are_not_ambiently_resolved_again()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let first = root.path().join("first");
        let second = root.path().join("second");
        let alias = root.path().join("alias");
        fs::write(&first, "first")?;
        fs::write(&second, "second")?;
        symlink(&first, &alias)?;
        let protections = crate::resolve::write_protections([alias.clone()])?;
        fs::remove_file(&alias)?;
        symlink(&second, &alias)?;

        let mut intent = CliPolicyIntent::new(SandboxPolicy::new(NetworkPolicy::BlockAll));
        for protection in protections {
            intent = intent.deny_resolved_write(protection);
        }
        let policy = resolve_policy(intent, &[])?.finish()?.into_spec();
        let first = fs::canonicalize(first)?;
        let second = fs::canonicalize(second)?;

        assert!(
            policy
                .write_protections
                .iter()
                .any(|item| item.path.as_path() == alias)
        );
        assert!(
            policy
                .write_protections
                .iter()
                .any(|item| item.path.as_path() == first)
        );
        assert!(
            !policy
                .write_protections
                .iter()
                .any(|item| item.path.as_path() == second)
        );
        Ok(())
    }
}
