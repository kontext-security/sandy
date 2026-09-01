use sandy_core::{
    FileMetadataPolicy, NetworkPolicy, PathScope, RuntimeCompatibility, ValidatedPolicy,
};

use crate::{LinuxError, LinuxErrorKind};

const BASELINE_LANDLOCK_ABI: u32 = 6;

/// Deterministic Linux lowering of a validated platform-neutral policy.
///
/// This type owns no file descriptors and performs no ambient discovery. It
/// exists so representability decisions can be reviewed and tested separately
/// from path pinning and irreversible enforcement.
pub struct LinuxPolicyPlan {
    pub(crate) policy: ValidatedPolicy,
}

impl LinuxPolicyPlan {
    /// Returns whether a private network namespace is required.
    #[must_use]
    pub(crate) fn blocks_network(&self) -> bool {
        self.policy.spec().network == NetworkPolicy::BlockAll
    }

    /// Returns whether ordinary descendant process creation is authorized.
    #[must_use]
    pub(crate) fn allows_subprocesses(&self) -> bool {
        self.policy.spec().allow_subprocesses
    }

    /// Returns the minimum Landlock ABI required by this policy.
    ///
    /// The initial backend uses one fixed semantic floor for every accepted
    /// policy, including process-signal isolation.
    #[must_use]
    pub fn required_landlock_abi(&self) -> u32 {
        BASELINE_LANDLOCK_ABI
    }
}

/// Lowers a validated policy into deterministic Linux semantics.
///
/// Unsupported combinations are rejected here whenever their incompatibility
/// is independent of the ambient filesystem. File-type-dependent checks occur
/// during the target-specific `prepare` phase.
pub fn plan(policy: &ValidatedPolicy) -> Result<LinuxPolicyPlan, LinuxError> {
    let spec = policy.spec();

    if spec.file_metadata != FileMetadataPolicy::Deny {
        return Err(unsupported("filesystem metadata policy"));
    }
    if !spec.local_host_tcp.is_empty() {
        return Err(unsupported("local-host TCP policy"));
    }
    if !spec.unix_sockets.is_empty() {
        return Err(unsupported("pathname Unix-socket policy"));
    }
    if spec.runtime_compatibility != RuntimeCompatibility::Minimal
        && spec.runtime_compatibility != RuntimeCompatibility::ForegroundCli
    {
        return Err(unsupported("runtime compatibility policy"));
    }
    // A read-only recursive mount protects only names reached through that
    // mount. A pre-existing hard link outside the protected subtree can still
    // mutate the same inode through a writable mount. Reject the shape until
    // Linux can prove the complete requested semantics.
    if spec
        .write_protections
        .iter()
        .any(|protection| protection.scope == PathScope::Subtree)
    {
        return Err(unsupported("recursive write protection"));
    }

    // A private filesystem view hides non-granted paths completely. A deny
    // nested inside a visible subtree, however, would leave at least a mount
    // placeholder observable. Reject it until an implementation can prove the
    // same metadata-denial semantics as a fully absent path.
    for protected in &spec.protected_paths {
        let overlaps_visible_subtree = spec.files.iter().any(|grant| {
            !denied(&grant.path, &spec.protected_paths)
                && grant.scope == PathScope::Subtree
                && protected.as_path().starts_with(grant.path.as_path())
        }) || spec.executables.iter().any(|grant| {
            !denied(&grant.path, &spec.protected_paths)
                && grant.scope == PathScope::Subtree
                && protected.as_path().starts_with(grant.path.as_path())
        });
        if overlaps_visible_subtree {
            return Err(unsupported("nested confidential path"));
        }
    }

    Ok(LinuxPolicyPlan {
        policy: policy.clone(),
    })
}

fn denied(path: &sandy_core::AbsolutePath, protected: &[sandy_core::AbsolutePath]) -> bool {
    protected
        .iter()
        .any(|entry| path.as_path().starts_with(entry.as_path()))
}

fn unsupported(phase: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::Unsupported, phase)
}

#[cfg(test)]
mod tests {
    use sandy_core::{
        AbsolutePath, AccessMode, FileGrant, NetworkPolicy, PathScope, PolicySpec, ValidatedPolicy,
        WriteProtection,
    };

    use super::*;

    fn path(value: &str) -> Result<AbsolutePath, Box<dyn std::error::Error>> {
        Ok(AbsolutePath::new(value.to_owned())?)
    }

    #[test]
    fn accepts_monotonic_allowlists() -> Result<(), Box<dyn std::error::Error>> {
        let policy = ValidatedPolicy::try_from(PolicySpec {
            files: vec![FileGrant {
                path: path("/workspace")?,
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }],
            network: NetworkPolicy::BlockAll,
            ..PolicySpec::default()
        })?;

        let plan = plan(&policy)?;
        assert!(plan.blocks_network());
        assert!(!plan.allows_subprocesses());
        assert_eq!(plan.required_landlock_abi(), 6);
        Ok(())
    }

    #[test]
    fn rejects_confidential_child_of_visible_subtree() -> Result<(), Box<dyn std::error::Error>> {
        let policy = ValidatedPolicy::try_from(PolicySpec {
            files: vec![FileGrant {
                path: path("/workspace")?,
                access: AccessMode::Read,
                scope: PathScope::Subtree,
            }],
            protected_paths: vec![path("/workspace/.secret")?],
            network: NetworkPolicy::BlockAll,
            ..PolicySpec::default()
        })?;

        let error = plan(&policy).err().ok_or("policy unexpectedly supported")?;
        assert_eq!(error.kind(), LinuxErrorKind::Unsupported);
        Ok(())
    }

    #[test]
    fn accepts_a_deny_that_completely_removes_a_grant() -> Result<(), Box<dyn std::error::Error>> {
        for (granted, protected) in [
            (path("/workspace")?, path("/workspace")?),
            (path("/workspace/project")?, path("/workspace")?),
        ] {
            let policy = ValidatedPolicy::try_from(PolicySpec {
                files: vec![FileGrant {
                    path: granted,
                    access: AccessMode::Read,
                    scope: PathScope::Subtree,
                }],
                protected_paths: vec![protected],
                ..PolicySpec::default()
            })?;
            assert!(plan(&policy).is_ok());
        }
        Ok(())
    }

    #[test]
    fn rejects_recursive_write_protection() -> Result<(), Box<dyn std::error::Error>> {
        let policy = ValidatedPolicy::try_from(PolicySpec {
            files: vec![FileGrant {
                path: path("/workspace")?,
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }],
            write_protections: vec![WriteProtection {
                path: path("/workspace/protected")?,
                scope: PathScope::Subtree,
            }],
            ..PolicySpec::default()
        })?;

        let error = plan(&policy).err().ok_or("policy unexpectedly supported")?;
        assert_eq!(error.kind(), LinuxErrorKind::Unsupported);
        Ok(())
    }

    #[test]
    fn rejects_local_host_tcp_without_broadening_it() -> Result<(), Box<dyn std::error::Error>> {
        use sandy_core::{LocalHostTcpGrant, LocalHostTcpOperation, TcpPort};

        let port = TcpPort::new(443).ok_or("invalid test port")?;
        let policy = ValidatedPolicy::try_from(PolicySpec {
            local_host_tcp: vec![LocalHostTcpGrant {
                port,
                operation: LocalHostTcpOperation::Connect,
            }],
            network: NetworkPolicy::BlockAll,
            ..PolicySpec::default()
        })?;

        let error = plan(&policy).err().ok_or("policy unexpectedly supported")?;
        assert_eq!(error.kind(), LinuxErrorKind::Unsupported);
        Ok(())
    }

    #[test]
    fn rejects_pathname_socket_authority_until_the_backend_contract_supports_it()
    -> Result<(), Box<dyn std::error::Error>> {
        use sandy_core::{UnixSocketGrant, UnixSocketOperation};

        let policy = ValidatedPolicy::try_from(PolicySpec {
            unix_sockets: vec![UnixSocketGrant {
                path: path("/service.sock")?,
                operation: UnixSocketOperation::Connect,
            }],
            ..PolicySpec::default()
        })?;

        let error = plan(&policy).err().ok_or("policy unexpectedly supported")?;
        assert_eq!(error.kind(), LinuxErrorKind::Unsupported);
        Ok(())
    }
}
