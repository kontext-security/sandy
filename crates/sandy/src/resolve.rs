use std::{
    collections::BTreeSet,
    env, fs,
    path::{Component, Path, PathBuf},
};

use sandy_core::{
    AbsolutePath, ExecutableGrant, FileGrant, FileMetadataPolicy, PathScope, ResolvedPolicyDraft,
    RuntimeCompatibility, SandboxPolicy, ValidatedPolicy, WriteProtection, into_policy_parts,
};

use crate::{ErrorKind, SandboxError};

pub(crate) struct ResolvedPolicy {
    policy: ValidatedPolicy,
    #[cfg(target_os = "linux")]
    working_directory: AbsolutePath,
}

impl ResolvedPolicy {
    pub(crate) fn policy(&self) -> &ValidatedPolicy {
        &self.policy
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn working_directory(&self) -> &AbsolutePath {
        &self.working_directory
    }

    #[cfg(test)]
    fn spec(&self) -> &sandy_core::PolicySpec {
        self.policy.spec()
    }
}

pub(crate) fn resolve(policy: SandboxPolicy) -> Result<ResolvedPolicy, SandboxError> {
    let working_directory = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(|_| SandboxError::new(ErrorKind::PreparationFailed))?;
    let parts =
        into_policy_parts(policy).map_err(|_| SandboxError::new(ErrorKind::InvalidPolicy))?;
    if parts.file_metadata != FileMetadataPolicy::Deny
        || parts.runtime_compatibility != RuntimeCompatibility::Minimal
    {
        return Err(SandboxError::new(ErrorKind::InvalidPolicy));
    }

    let mut draft = ResolvedPolicyDraft::new(parts.network);
    draft.set_allow_subprocesses(parts.allow_subprocesses);

    for grant in parts.grants {
        let path = canonical_existing(&working_directory, &grant.path)?;
        if path == Path::new("/")
            && (grant.access != sandy_core::AccessMode::Read || grant.scope != PathScope::Exact)
        {
            return Err(SandboxError::new(ErrorKind::InvalidPolicy));
        }
        draft.add_file(FileGrant {
            path: absolute(&path)?,
            access: grant.access,
            scope: grant.scope,
        });
    }

    for grant in parts.executables {
        let path = canonical_existing(&working_directory, &grant.path)?;
        reject_root(&path)?;
        draft.add_executable(ExecutableGrant {
            path: absolute(&path)?,
            scope: grant.scope,
        });
    }

    let mut protected_paths = BTreeSet::new();
    for requested in parts.denied_subtrees {
        for path in lexical_and_canonical(&working_directory, &requested)? {
            reject_root(&path)?;
            protected_paths.insert(absolute(&path)?);
        }
    }

    let mut write_protections = BTreeSet::new();
    for requested in parts.write_denied_exact {
        for path in lexical_and_canonical(&working_directory, &requested)? {
            reject_root(&path)?;
            write_protections.insert(WriteProtection {
                path: absolute(&path)?,
                scope: PathScope::Exact,
            });
        }
    }

    for path in protected_paths {
        draft.add_protected_path(path);
    }
    for protection in write_protections {
        draft.add_write_protection(protection);
    }

    let policy = draft
        .finish()
        .map_err(|_| SandboxError::new(ErrorKind::InvalidPolicy))?;
    #[cfg(target_os = "linux")]
    let working_directory = absolute(&working_directory)?;
    Ok(ResolvedPolicy {
        policy,
        #[cfg(target_os = "linux")]
        working_directory,
    })
}

fn lexical_and_canonical(
    working_directory: &Path,
    requested: &Path,
) -> Result<BTreeSet<PathBuf>, SandboxError> {
    let candidate = absolute_candidate(working_directory, requested)?;
    let canonical =
        fs::canonicalize(&candidate).map_err(|_| SandboxError::new(ErrorKind::InvalidPolicy))?;
    let mut paths = BTreeSet::from([canonical]);
    if !candidate
        .components()
        .any(|component| component == Component::ParentDir)
    {
        paths.insert(normalize_without_parent(&candidate)?);
    }
    Ok(paths)
}

fn canonical_existing(working_directory: &Path, requested: &Path) -> Result<PathBuf, SandboxError> {
    let candidate = absolute_candidate(working_directory, requested)?;
    fs::canonicalize(candidate).map_err(|_| SandboxError::new(ErrorKind::InvalidPolicy))
}

fn absolute_candidate(working_directory: &Path, requested: &Path) -> Result<PathBuf, SandboxError> {
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        working_directory.join(requested)
    };
    if !candidate.is_absolute() {
        return Err(SandboxError::new(ErrorKind::InvalidPolicy));
    }
    Ok(candidate)
}

fn normalize_without_parent(candidate: &Path) -> Result<PathBuf, SandboxError> {
    let mut normalized = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => return Err(SandboxError::new(ErrorKind::InvalidPolicy)),
            Component::Normal(component) => normalized.push(component),
        }
    }
    Ok(normalized)
}

fn reject_root(path: &Path) -> Result<(), SandboxError> {
    if path == Path::new("/") {
        Err(SandboxError::new(ErrorKind::InvalidPolicy))
    } else {
        Ok(())
    }
}

fn absolute(path: &Path) -> Result<AbsolutePath, SandboxError> {
    let value = path
        .to_str()
        .ok_or_else(|| SandboxError::new(ErrorKind::InvalidPolicy))?;
    AbsolutePath::new(value.to_owned()).map_err(|_| SandboxError::new(ErrorKind::InvalidPolicy))
}

#[cfg(test)]
mod tests {
    use std::{error::Error as _, os::unix::fs::symlink};

    use sandy_core::{AccessMode, NetworkPolicy, PolicySpec};

    use super::*;

    #[test]
    fn resolves_grants_without_adding_a_runtime_baseline() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace)?;

        let resolved = resolve(SandboxPolicy::new(NetworkPolicy::BlockAll).grant(
            &workspace,
            AccessMode::ReadWrite,
            PathScope::Subtree,
        ))?;

        assert_eq!(resolved.spec().files.len(), 1);
        assert!(resolved.spec().executables.is_empty());
        assert_eq!(
            resolved.spec().files[0].path.as_path(),
            fs::canonicalize(workspace)?
        );
        assert_eq!(resolved.spec().file_metadata, FileMetadataPolicy::Deny);
        assert!(!resolved.spec().allow_subprocesses);
        assert_eq!(
            resolved.spec().runtime_compatibility,
            RuntimeCompatibility::Minimal
        );
        assert_eq!(resolved.spec().network, NetworkPolicy::BlockAll);
        Ok(())
    }

    #[test]
    fn preserves_complete_facade_policy_semantics() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        let configuration = workspace.join("configuration");
        let settings = configuration.join("settings.json");
        let credentials = workspace.join("credentials");
        let tool = workspace.join("tool");
        fs::create_dir_all(&configuration)?;
        fs::create_dir(&credentials)?;
        fs::write(&settings, "settings")?;
        fs::write(&tool, "tool")?;
        let lexical_credentials = absolute(&normalize_without_parent(&credentials)?)?;
        let lexical_settings = absolute(&normalize_without_parent(&settings)?)?;

        let resolved = resolve(
            SandboxPolicy::new(NetworkPolicy::BlockAll)
                .grant(&workspace, AccessMode::Read, PathScope::Subtree)
                .grant(&workspace, AccessMode::ReadWrite, PathScope::Subtree)
                .allow_execute(&tool, PathScope::Exact)
                .allow_execute(&tool, PathScope::Exact)
                .allow_subprocesses()
                .deny_subtree(&credentials)
                .deny_write_exact(&settings),
        )?;

        let workspace = absolute(&fs::canonicalize(workspace)?)?;
        let configuration = absolute(&fs::canonicalize(configuration)?)?;
        let settings = absolute(&fs::canonicalize(settings)?)?;
        let credentials = absolute(&fs::canonicalize(credentials)?)?;
        let tool = absolute(&fs::canonicalize(tool)?)?;
        let protected_paths = BTreeSet::from([lexical_credentials, credentials])
            .into_iter()
            .collect();
        let write_protections = BTreeSet::from([
            WriteProtection {
                path: configuration,
                scope: PathScope::Exact,
            },
            WriteProtection {
                path: lexical_settings,
                scope: PathScope::Exact,
            },
            WriteProtection {
                path: settings,
                scope: PathScope::Exact,
            },
        ])
        .into_iter()
        .collect();
        let expected = PolicySpec {
            files: vec![FileGrant {
                path: workspace,
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }],
            executables: vec![ExecutableGrant {
                path: tool,
                scope: PathScope::Exact,
            }],
            protected_paths,
            write_protections,
            allow_subprocesses: true,
            network: NetworkPolicy::BlockAll,
            ..PolicySpec::default()
        };

        assert_eq!(resolved.spec(), &expected);
        Ok(())
    }

    #[test]
    fn resolves_parent_components_after_following_symlinks()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        let outside = root.path().join("outside");
        let linked_directory = outside.join("directory");
        fs::create_dir_all(&workspace)?;
        fs::create_dir_all(&linked_directory)?;
        fs::write(workspace.join("secret"), "wrong")?;
        fs::write(outside.join("secret"), "requested")?;
        symlink(&linked_directory, workspace.join("link"))?;
        let requested = workspace.join("link/../secret");

        let resolved = resolve(
            SandboxPolicy::new(NetworkPolicy::BlockAll)
                .grant(&requested, AccessMode::Read, PathScope::Exact)
                .deny_subtree(&requested),
        )?;
        let actual =
            AbsolutePath::new(fs::canonicalize(outside.join("secret"))?.to_string_lossy())?;
        let wrong =
            AbsolutePath::new(fs::canonicalize(workspace.join("secret"))?.to_string_lossy())?;

        assert_eq!(resolved.spec().files[0].path, actual);
        assert!(resolved.spec().protected_paths.contains(&actual));
        assert!(!resolved.spec().protected_paths.contains(&wrong));
        Ok(())
    }

    #[test]
    fn preserves_both_spellings_of_a_symlinked_deny() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let target = root.path().join("target");
        let alias = root.path().join("alias");
        fs::create_dir(&target)?;
        symlink(&target, &alias)?;

        let resolved = resolve(
            SandboxPolicy::new(NetworkPolicy::BlockAll)
                .deny_subtree(&alias)
                .deny_write_exact(&alias),
        )?;
        let canonical = AbsolutePath::new(fs::canonicalize(&target)?.to_string_lossy())?;
        let lexical = AbsolutePath::new(alias.to_string_lossy())?;

        assert!(resolved.spec().protected_paths.contains(&canonical));
        assert!(resolved.spec().protected_paths.contains(&lexical));
        assert!(
            resolved
                .spec()
                .write_protections
                .iter()
                .any(|protection| protection.path == canonical)
        );
        assert!(
            resolved
                .spec()
                .write_protections
                .iter()
                .any(|protection| protection.path == lexical)
        );
        Ok(())
    }

    #[test]
    fn rejects_nonexistent_paths_without_disclosing_them() -> Result<(), Box<dyn std::error::Error>>
    {
        let sensitive = "/private/tmp/credential-name-must-not-appear";
        let error = resolve(SandboxPolicy::new(NetworkPolicy::BlockAll).grant(
            sensitive,
            AccessMode::Read,
            PathScope::Exact,
        ))
        .err()
        .ok_or("a nonexistent grant must fail")?;

        assert_eq!(error.kind(), ErrorKind::InvalidPolicy);
        assert!(!error.to_string().contains(sensitive));
        assert!(!format!("{error:?}").contains(sensitive));
        assert!(error.source().is_none());
        Ok(())
    }

    #[test]
    fn classifies_unrepresentable_existing_paths_as_invalid_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("line\nbreak");
        fs::write(&path, "content")?;

        let error = resolve(SandboxPolicy::new(NetworkPolicy::BlockAll).grant(
            &path,
            AccessMode::Read,
            PathScope::Exact,
        ))
        .err()
        .ok_or("an unrepresentable path must fail")?;

        assert_eq!(error.kind(), ErrorKind::InvalidPolicy);
        Ok(())
    }

    #[test]
    fn rejects_product_only_compatibility_intent() -> Result<(), Box<dyn std::error::Error>> {
        for policy in [
            sandy_core::allow_file_metadata(SandboxPolicy::new(NetworkPolicy::BlockAll)),
            sandy_core::allow_foreground_cli_compatibility(SandboxPolicy::new(
                NetworkPolicy::BlockAll,
            )),
        ] {
            let error = resolve(policy)
                .err()
                .ok_or("product-only compatibility must not enter the facade")?;
            assert_eq!(error.kind(), ErrorKind::InvalidPolicy);
        }
        Ok(())
    }
}
