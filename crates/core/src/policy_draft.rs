//! Trusted assembly of fully resolved policy capabilities.
//!
//! Ambient owners resolve filesystem identity before adding capabilities here.
//! This module performs no discovery; it only normalizes trusted contributions,
//! derives required ancestor protections, and completes validation.

use crate::{
    AbsolutePath, ExecutableGrant, FileGrant, FileMetadataPolicy, LocalHostTcpGrant, NetworkPolicy,
    PolicySpec, RuntimeCompatibility, UnixSocketGrant, ValidatedPolicy, ValidationError,
    WriteProtection, validation::validate_policy_bounds,
};

/// Mutable trusted assembly state between ambient resolution and validation.
///
/// Fields stay private so sibling packages must use typed contributions and
/// cannot accidentally treat an arbitrary wire policy as prepared input.
/// Decoded manifests never pass through this type.
#[doc(hidden)]
#[must_use = "resolved policy drafts must be finished before enforcement"]
pub struct ResolvedPolicyDraft {
    policy: PolicySpec,
}

impl ResolvedPolicyDraft {
    /// Starts an empty resolved policy with explicit network behavior.
    pub fn new(network: NetworkPolicy) -> Self {
        Self {
            policy: PolicySpec {
                network,
                ..PolicySpec::default()
            },
        }
    }

    /// Adds one resolved filesystem capability.
    pub fn add_file(&mut self, grant: FileGrant) {
        self.policy.files.push(grant);
    }

    /// Adds one resolved executable-mapping capability.
    pub fn add_executable(&mut self, grant: ExecutableGrant) {
        self.policy.executables.push(grant);
    }

    /// Adds one resolved terminal read/write denial.
    pub fn add_protected_path(&mut self, path: AbsolutePath) {
        self.policy.protected_paths.push(path);
    }

    /// Adds one resolved terminal write denial.
    pub fn add_write_protection(&mut self, protection: WriteProtection) {
        self.policy.write_protections.push(protection);
    }

    /// Adds one exact Unix-socket capability.
    pub fn add_unix_socket(&mut self, grant: UnixSocketGrant) {
        self.policy.unix_sockets.push(grant);
    }

    /// Adds one exact local-host TCP capability.
    pub fn add_local_host_tcp(&mut self, grant: LocalHostTcpGrant) {
        self.policy.local_host_tcp.push(grant);
    }

    /// Selects resolved filesystem-metadata behavior.
    pub fn set_file_metadata(&mut self, policy: FileMetadataPolicy) {
        self.policy.file_metadata = policy;
    }

    /// Selects whether ordinary descendant process startup is permitted.
    pub fn set_allow_subprocesses(&mut self, allow: bool) {
        self.policy.allow_subprocesses = allow;
    }

    /// Selects product-owned runtime compatibility behavior.
    pub fn set_runtime_compatibility(&mut self, compatibility: RuntimeCompatibility) {
        self.policy.runtime_compatibility = compatibility;
    }

    /// Normalizes trusted contributions, closes ancestor protections, and
    /// returns the proof required by an enforcement backend.
    ///
    /// Raw contributions are bounded before normalization so duplicate input
    /// cannot evade resource limits. Derived protections are bounded again
    /// before the strict validation transition.
    pub fn finish(mut self) -> Result<ValidatedPolicy, ValidationError> {
        validate_policy_bounds(&self.policy)?;
        self.policy.normalize();
        self.policy.close_write_protection_ancestors();
        validate_policy_bounds(&self.policy)?;
        self.policy.normalize();
        ValidatedPolicy::try_from(self.policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccessMode, LocalHostTcpOperation, PathScope, TcpPort, UnixSocketOperation,
        validation::{
            MAX_EXECUTABLE_GRANTS, MAX_FILE_GRANTS, MAX_LOCAL_HOST_TCP_GRANTS, MAX_PROTECTED_PATHS,
            MAX_UNIX_SOCKET_GRANTS,
        },
    };

    fn path(value: impl Into<String>) -> Result<AbsolutePath, crate::PathValidationError> {
        AbsolutePath::new(value)
    }

    #[test]
    fn rejects_raw_contributions_before_normalization() -> Result<(), Box<dyn std::error::Error>> {
        let duplicate = FileGrant {
            path: path("/workspace")?,
            access: AccessMode::Read,
            scope: PathScope::Exact,
        };
        let mut draft = ResolvedPolicyDraft::new(NetworkPolicy::BlockAll);
        for _ in 0..=MAX_FILE_GRANTS {
            draft.add_file(duplicate.clone());
        }

        assert!(matches!(
            draft.finish(),
            Err(ValidationError::TooManyFileGrants)
        ));

        let executable = ExecutableGrant {
            path: path("/workspace/tool")?,
            scope: PathScope::Exact,
        };
        let mut draft = ResolvedPolicyDraft::new(NetworkPolicy::BlockAll);
        for _ in 0..=MAX_EXECUTABLE_GRANTS {
            draft.add_executable(executable.clone());
        }
        assert!(matches!(
            draft.finish(),
            Err(ValidationError::TooManyExecutableGrants)
        ));

        let socket = UnixSocketGrant {
            path: path("/private/tmp/control.sock")?,
            operation: UnixSocketOperation::Connect,
        };
        let mut draft = ResolvedPolicyDraft::new(NetworkPolicy::BlockAll);
        for _ in 0..=MAX_UNIX_SOCKET_GRANTS {
            draft.add_unix_socket(socket.clone());
        }
        assert!(matches!(
            draft.finish(),
            Err(ValidationError::TooManyUnixSocketGrants)
        ));

        let endpoint = LocalHostTcpGrant {
            port: TcpPort::new(4318).ok_or("test port must be nonzero")?,
            operation: LocalHostTcpOperation::Connect,
        };
        let mut draft = ResolvedPolicyDraft::new(NetworkPolicy::BlockAll);
        for _ in 0..=MAX_LOCAL_HOST_TCP_GRANTS {
            draft.add_local_host_tcp(endpoint.clone());
        }
        assert!(matches!(
            draft.finish(),
            Err(ValidationError::TooManyLocalHostTcpGrants)
        ));

        let mut draft = ResolvedPolicyDraft::new(NetworkPolicy::BlockAll);
        for _ in 0..=MAX_PROTECTED_PATHS {
            draft.add_protected_path(path("/workspace/secret")?);
        }
        assert!(matches!(
            draft.finish(),
            Err(ValidationError::TooManyProtectedPaths)
        ));
        Ok(())
    }

    #[test]
    fn normalizes_independent_trusted_contributions() -> Result<(), Box<dyn std::error::Error>> {
        let workspace = path("/workspace")?;
        let executable = ExecutableGrant {
            path: path("/workspace/tool")?,
            scope: PathScope::Exact,
        };
        let socket = UnixSocketGrant {
            path: path("/private/tmp/control.sock")?,
            operation: UnixSocketOperation::Connect,
        };
        let mut draft = ResolvedPolicyDraft::new(NetworkPolicy::BlockAll);
        draft.add_file(FileGrant {
            path: workspace.clone(),
            access: AccessMode::Read,
            scope: PathScope::Subtree,
        });
        draft.add_file(FileGrant {
            path: workspace.clone(),
            access: AccessMode::ReadWrite,
            scope: PathScope::Subtree,
        });
        draft.add_executable(executable.clone());
        draft.add_executable(executable.clone());
        draft.add_unix_socket(socket.clone());
        draft.add_unix_socket(socket);

        let policy = draft.finish()?;

        assert_eq!(
            policy.spec().files,
            [FileGrant {
                path: workspace,
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }]
        );
        assert_eq!(policy.spec().executables, [executable]);
        assert_eq!(policy.spec().unix_sockets.len(), 1);
        Ok(())
    }

    #[test]
    fn closes_writable_ancestors_before_validation() -> Result<(), Box<dyn std::error::Error>> {
        let mut draft = ResolvedPolicyDraft::new(NetworkPolicy::BlockAll);
        draft.add_file(FileGrant {
            path: path("/workspace")?,
            access: AccessMode::ReadWrite,
            scope: PathScope::Subtree,
        });
        draft.add_write_protection(WriteProtection {
            path: path("/workspace/config/hooks/managed.json")?,
            scope: PathScope::Exact,
        });

        let policy = draft.finish()?;
        let protected = policy
            .spec()
            .write_protections
            .iter()
            .map(|protection| protection.path.as_str())
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(
            protected,
            std::collections::BTreeSet::from([
                "/workspace/config",
                "/workspace/config/hooks",
                "/workspace/config/hooks/managed.json",
            ])
        );
        Ok(())
    }

    #[test]
    fn bounds_ancestor_closure_output() -> Result<(), Box<dyn std::error::Error>> {
        let mut resource = String::from("/workspace");
        for index in 0..=MAX_PROTECTED_PATHS {
            resource.push('/');
            resource.push_str(&format!("level-{index}"));
        }
        let mut draft = ResolvedPolicyDraft::new(NetworkPolicy::BlockAll);
        draft.add_file(FileGrant {
            path: path("/workspace")?,
            access: AccessMode::ReadWrite,
            scope: PathScope::Subtree,
        });
        draft.add_write_protection(WriteProtection {
            path: path(resource)?,
            scope: PathScope::Exact,
        });

        assert!(matches!(
            draft.finish(),
            Err(ValidationError::TooManyProtectedPaths)
        ));
        Ok(())
    }

    #[test]
    fn strict_policy_validation_still_rejects_duplicate_wire_input()
    -> Result<(), Box<dyn std::error::Error>> {
        let grant = FileGrant {
            path: path("/workspace")?,
            access: AccessMode::Read,
            scope: PathScope::Exact,
        };
        let policy = PolicySpec {
            files: vec![grant.clone(), grant],
            network: NetworkPolicy::BlockAll,
            ..PolicySpec::default()
        };

        assert!(matches!(
            ValidatedPolicy::try_from(policy),
            Err(ValidationError::DuplicateGrant(_))
        ));
        Ok(())
    }
}
