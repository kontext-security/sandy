use std::collections::BTreeSet;

use sandy_core::{
    AbsolutePath, AccessMode, FileGrant, PathScope, PolicySpec, UnixSocketGrant, WriteProtection,
};

use crate::error::AppError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IntegrationMode {
    Detect,
    Required,
}

impl IntegrationMode {
    pub(crate) fn is_required(self) -> bool {
        self == Self::Required
    }
}

/// The validated, provider-independent result of resolving one integration.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedRuntimeControl {
    service: &'static str,
    outcome: RuntimeControlOutcome,
}

#[derive(Clone, Debug)]
enum RuntimeControlOutcome {
    Inactive,
    Unavailable {
        reason: String,
    },
    Active {
        version: Option<String>,
        capabilities: RuntimeControlCapabilities,
    },
}

impl ResolvedRuntimeControl {
    pub(crate) fn inactive(service: &'static str) -> Self {
        Self {
            service,
            outcome: RuntimeControlOutcome::Inactive,
        }
    }

    pub(crate) fn unavailable(service: &'static str, reason: impl Into<String>) -> Self {
        Self {
            service,
            outcome: RuntimeControlOutcome::Unavailable {
                reason: reason.into(),
            },
        }
    }

    pub(crate) fn active(
        service: &'static str,
        version: Option<String>,
        capabilities: RuntimeControlCapabilities,
    ) -> Result<Self, AppError> {
        capabilities.validate(service)?;
        Ok(Self {
            service,
            outcome: RuntimeControlOutcome::Active {
                version,
                capabilities,
            },
        })
    }

    pub(crate) fn service(&self) -> &'static str {
        self.service
    }

    pub(crate) fn is_active(&self) -> bool {
        matches!(&self.outcome, RuntimeControlOutcome::Active { .. })
    }

    pub(crate) fn version(&self) -> Option<&str> {
        match &self.outcome {
            RuntimeControlOutcome::Active { version, .. } => version.as_deref(),
            RuntimeControlOutcome::Inactive | RuntimeControlOutcome::Unavailable { .. } => None,
        }
    }

    pub(crate) fn unavailable_reason(&self) -> Option<&str> {
        match &self.outcome {
            RuntimeControlOutcome::Unavailable { reason } => Some(reason),
            RuntimeControlOutcome::Inactive | RuntimeControlOutcome::Active { .. } => None,
        }
    }

    fn capabilities(&self) -> Option<&RuntimeControlCapabilities> {
        match &self.outcome {
            RuntimeControlOutcome::Active { capabilities, .. } => Some(capabilities),
            RuntimeControlOutcome::Inactive | RuntimeControlOutcome::Unavailable { .. } => None,
        }
    }
}

/// An exact hook executable that is readable but immutable in the sandbox.
///
/// Keeping the integrity requirement in the type prevents a resolver from
/// granting execution dependencies while accidentally omitting the matching
/// terminal write deny.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ImmutableExecutable {
    path: AbsolutePath,
}

impl ImmutableExecutable {
    #[must_use]
    pub(crate) fn new(path: AbsolutePath) -> Self {
        Self { path }
    }

    #[must_use]
    pub(crate) fn path(&self) -> &AbsolutePath {
        &self.path
    }

    fn file_grant(&self) -> FileGrant {
        FileGrant {
            path: self.path.clone(),
            access: AccessMode::Read,
            scope: PathScope::Exact,
        }
    }

    fn write_protection(&self) -> WriteProtection {
        WriteProtection {
            path: self.path.clone(),
            scope: PathScope::Exact,
        }
    }
}

/// Capabilities required by one active runtime-control integration.
///
/// Provider-specific discovery must be complete before constructing this type.
#[derive(Clone, Debug, Default)]
pub(crate) struct RuntimeControlCapabilities {
    /// Exact, immutable executables invoked by the agent's hook or plugin.
    pub(crate) executables: Vec<ImmutableExecutable>,
    /// Typed filesystem resources, including exact files and directory trees.
    pub(crate) files: Vec<FileGrant>,
    /// Exact readable paths whose integrity must override broader write grants.
    pub(crate) write_protections: Vec<WriteProtection>,
    /// Exact pathname Unix-socket operations used by an external host service.
    pub(crate) unix_sockets: Vec<UnixSocketGrant>,
}

impl RuntimeControlCapabilities {
    fn validate(&self, service: &'static str) -> Result<(), AppError> {
        let mut paths = BTreeSet::new();
        for executable in &self.executables {
            if !paths.insert(executable.path.clone()) {
                return Err(duplicate_file_intent(service));
            }
        }
        for grant in &self.files {
            if !paths.insert(grant.path.clone()) {
                return Err(duplicate_file_intent(service));
            }
        }

        let mut seen_sockets = BTreeSet::new();
        for grant in &self.unix_sockets {
            if !seen_sockets.insert(grant) {
                return Err(AppError::runtime_control(
                    service,
                    "resolved Unix-socket grants overlap; refusing to broaden the runtime policy",
                ));
            }
            let readable_exact = self.files.iter().any(|file| {
                file.path == grant.path
                    && file.access == AccessMode::Read
                    && file.scope == PathScope::Exact
            });
            if !readable_exact {
                return Err(AppError::runtime_control(
                    service,
                    "a Unix-socket grant is missing its separate exact read-only filesystem intent",
                ));
            }
            if !self.write_protections.iter().any(|protection| {
                protection.path == grant.path && protection.scope == PathScope::Exact
            }) {
                return Err(AppError::runtime_control(
                    service,
                    "a Unix-socket grant is not protected from overlapping filesystem writes",
                ));
            }
        }
        Ok(())
    }
}

/// Ordered collection of independently resolved runtime controls.
///
/// Composition happens once, immediately before core launch validation. This
/// keeps provider resolvers independent while giving policy assembly one place
/// to close the writable-ancestor integrity invariant across base policy and
/// every active integration.
#[derive(Clone, Debug, Default)]
pub(crate) struct RuntimeControls {
    controls: Vec<ResolvedRuntimeControl>,
}

impl RuntimeControls {
    pub(crate) fn new(controls: Vec<ResolvedRuntimeControl>) -> Self {
        Self { controls }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &ResolvedRuntimeControl> {
        self.controls.iter()
    }

    pub(crate) fn apply_to(&self, policy: &mut PolicySpec) -> Result<(), AppError> {
        let mut composed = policy.clone();
        for control in &self.controls {
            let Some(capabilities) = control.capabilities() else {
                continue;
            };
            composed.files.extend(
                capabilities
                    .executables
                    .iter()
                    .map(ImmutableExecutable::file_grant),
            );
            composed.write_protections.extend(
                capabilities
                    .executables
                    .iter()
                    .map(ImmutableExecutable::write_protection),
            );
            composed.files.extend(capabilities.files.iter().cloned());
            composed
                .write_protections
                .extend(capabilities.write_protections.iter().cloned());
            composed
                .unix_sockets
                .extend(capabilities.unix_sockets.iter().cloned());
        }

        for control in &self.controls {
            let Some(capabilities) = control.capabilities() else {
                continue;
            };
            for grant in capabilities
                .executables
                .iter()
                .map(ImmutableExecutable::file_grant)
                .chain(capabilities.files.iter().cloned())
            {
                validate_final_access(control.service(), &grant, &composed)?;
            }
        }

        composed.close_write_protection_ancestors();
        *policy = composed;
        Ok(())
    }
}

fn validate_final_access(
    service: &'static str,
    grant: &FileGrant,
    policy: &PolicySpec,
) -> Result<(), AppError> {
    if policy
        .protected_paths
        .iter()
        .any(|protected| scopes_overlap(&grant.path, grant.scope, protected, PathScope::Subtree))
    {
        return Err(AppError::runtime_control(
            service,
            "a required filesystem resource overlaps a protected path",
        ));
    }

    if grant.access == AccessMode::ReadWrite
        && policy.write_protections.iter().any(|protection| {
            scopes_overlap(&grant.path, grant.scope, &protection.path, protection.scope)
        })
    {
        return Err(AppError::runtime_control(
            service,
            "a required writable filesystem resource overlaps a write protection",
        ));
    }
    Ok(())
}

fn scopes_overlap(
    first_path: &AbsolutePath,
    first_scope: PathScope,
    second_path: &AbsolutePath,
    second_scope: PathScope,
) -> bool {
    match (first_scope, second_scope) {
        (PathScope::Exact, PathScope::Exact) => first_path == second_path,
        (PathScope::Exact, PathScope::Subtree) => {
            first_path.as_path().starts_with(second_path.as_path())
        }
        (PathScope::Subtree, PathScope::Exact) => {
            second_path.as_path().starts_with(first_path.as_path())
        }
        (PathScope::Subtree, PathScope::Subtree) => {
            first_path.as_path().starts_with(second_path.as_path())
                || second_path.as_path().starts_with(first_path.as_path())
        }
    }
}

fn duplicate_file_intent(service: &'static str) -> AppError {
    AppError::runtime_control(
        service,
        "the same path is declared by more than one resolved filesystem intent",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_exact(path: AbsolutePath) -> FileGrant {
        FileGrant {
            path,
            access: AccessMode::Read,
            scope: PathScope::Exact,
        }
    }

    #[test]
    fn rejects_duplicate_file_intents() -> Result<(), Box<dyn std::error::Error>> {
        let executable = AbsolutePath::new("/opt/tool/bin/control")?;
        let result = ResolvedRuntimeControl::active(
            "test",
            None,
            RuntimeControlCapabilities {
                executables: vec![ImmutableExecutable::new(executable.clone())],
                files: vec![read_exact(executable)],
                ..RuntimeControlCapabilities::default()
            },
        );
        assert!(matches!(result, Err(AppError::RuntimeControl { .. })));
        Ok(())
    }

    #[test]
    fn inactive_and_unavailable_runtime_controls_add_nothing() -> Result<(), AppError> {
        let controls = RuntimeControls::new(vec![
            ResolvedRuntimeControl::inactive("inactive"),
            ResolvedRuntimeControl::unavailable("unavailable", "provider is unavailable"),
        ]);
        let mut policy = PolicySpec::default();
        controls.apply_to(&mut policy)?;
        assert!(policy.files.is_empty());
        assert!(policy.write_protections.is_empty());
        assert!(policy.unix_sockets.is_empty());
        assert_eq!(
            controls
                .iter()
                .nth(1)
                .and_then(|item| item.unavailable_reason()),
            Some("provider is unavailable")
        );
        Ok(())
    }

    #[test]
    fn composes_disjoint_scoped_resources() -> Result<(), Box<dyn std::error::Error>> {
        let executable = AbsolutePath::new("/opt/tool/bin/control")?;
        let rules = AbsolutePath::new("/opt/tool/rules")?;
        let socket = AbsolutePath::new("/private/tmp/control.sock")?;
        let first = ResolvedRuntimeControl::active(
            "first",
            Some("1.0.0".to_owned()),
            RuntimeControlCapabilities {
                executables: vec![ImmutableExecutable::new(executable.clone())],
                files: vec![
                    FileGrant {
                        path: rules.clone(),
                        access: AccessMode::Read,
                        scope: PathScope::Subtree,
                    },
                    read_exact(socket.clone()),
                ],
                write_protections: vec![WriteProtection {
                    path: socket.clone(),
                    scope: PathScope::Exact,
                }],
                unix_sockets: vec![UnixSocketGrant {
                    path: socket.clone(),
                    operation: sandy_core::UnixSocketOperation::Connect,
                }],
            },
        )?;
        let output = AbsolutePath::new("/var/log/tool")?;
        let second = ResolvedRuntimeControl::active(
            "second",
            None,
            RuntimeControlCapabilities {
                files: vec![FileGrant {
                    path: output.clone(),
                    access: AccessMode::ReadWrite,
                    scope: PathScope::Subtree,
                }],
                ..RuntimeControlCapabilities::default()
            },
        )?;
        let controls = RuntimeControls::new(vec![first, second]);
        let mut policy = PolicySpec::default();
        controls.apply_to(&mut policy)?;

        assert_eq!(policy.files.len(), 4);
        assert!(policy.files.iter().any(|grant| {
            grant.path == executable
                && grant.access == AccessMode::Read
                && grant.scope == PathScope::Exact
        }));
        assert!(policy.files.iter().any(|grant| {
            grant.path == rules
                && grant.access == AccessMode::Read
                && grant.scope == PathScope::Subtree
        }));
        assert!(policy.files.iter().any(|grant| {
            grant.path == output
                && grant.access == AccessMode::ReadWrite
                && grant.scope == PathScope::Subtree
        }));
        assert!(policy.write_protections.iter().any(|protection| {
            protection.path == executable && protection.scope == PathScope::Exact
        }));
        assert!(policy.write_protections.iter().any(|protection| {
            protection.path == socket && protection.scope == PathScope::Exact
        }));
        assert_eq!(policy.unix_sockets.len(), 1);
        assert_eq!(policy.unix_sockets[0].path, socket);
        Ok(())
    }

    #[test]
    fn rejects_socket_authority_without_separate_file_and_integrity_intents()
    -> Result<(), Box<dyn std::error::Error>> {
        let socket = AbsolutePath::new("/private/tmp/control.sock")?;
        let missing_file = ResolvedRuntimeControl::active(
            "test",
            None,
            RuntimeControlCapabilities {
                unix_sockets: vec![UnixSocketGrant {
                    path: socket.clone(),
                    operation: sandy_core::UnixSocketOperation::Connect,
                }],
                ..RuntimeControlCapabilities::default()
            },
        );
        assert!(matches!(missing_file, Err(AppError::RuntimeControl { .. })));

        let writable_socket = ResolvedRuntimeControl::active(
            "test",
            None,
            RuntimeControlCapabilities {
                files: vec![FileGrant {
                    path: socket.clone(),
                    access: AccessMode::ReadWrite,
                    scope: PathScope::Exact,
                }],
                write_protections: vec![WriteProtection {
                    path: socket.clone(),
                    scope: PathScope::Exact,
                }],
                unix_sockets: vec![UnixSocketGrant {
                    path: socket,
                    operation: sandy_core::UnixSocketOperation::Connect,
                }],
                ..RuntimeControlCapabilities::default()
            },
        );
        assert!(matches!(
            writable_socket,
            Err(AppError::RuntimeControl { .. })
        ));
        Ok(())
    }

    #[test]
    fn pins_immutable_resources_inside_writable_subtrees() -> Result<(), Box<dyn std::error::Error>>
    {
        let executable = AbsolutePath::new("/workspace/plugins/bin/control")?;
        let control = ResolvedRuntimeControl::active(
            "test",
            None,
            RuntimeControlCapabilities {
                executables: vec![ImmutableExecutable::new(executable.clone())],
                ..RuntimeControlCapabilities::default()
            },
        )?;
        let mut policy = PolicySpec {
            files: vec![FileGrant {
                path: AbsolutePath::new("/workspace")?,
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }],
            ..PolicySpec::default()
        };

        RuntimeControls::new(vec![control]).apply_to(&mut policy)?;

        for expected in [
            "/workspace/plugins",
            "/workspace/plugins/bin",
            "/workspace/plugins/bin/control",
        ] {
            assert!(policy.write_protections.iter().any(|protection| {
                protection.path.as_str() == expected && protection.scope == PathScope::Exact
            }));
        }
        Ok(())
    }

    #[test]
    fn rejects_runtime_control_resource_blocked_by_base_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let resource = AbsolutePath::new("/workspace/private/control.json")?;
        let control = ResolvedRuntimeControl::active(
            "first",
            None,
            RuntimeControlCapabilities {
                files: vec![read_exact(resource)],
                ..RuntimeControlCapabilities::default()
            },
        )?;
        let mut policy = PolicySpec {
            protected_paths: vec![AbsolutePath::new("/workspace/private")?],
            ..PolicySpec::default()
        };

        let error = match RuntimeControls::new(vec![control]).apply_to(&mut policy) {
            Ok(()) => return Err("base protection unexpectedly allowed the runtime control".into()),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .starts_with("first runtime control failed:")
        );
        assert!(policy.files.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_writable_resource_blocked_by_another_runtime_control()
    -> Result<(), Box<dyn std::error::Error>> {
        let output = AbsolutePath::new("/workspace/tool/output")?;
        let writer = ResolvedRuntimeControl::active(
            "writer",
            None,
            RuntimeControlCapabilities {
                files: vec![FileGrant {
                    path: output.clone(),
                    access: AccessMode::ReadWrite,
                    scope: PathScope::Subtree,
                }],
                ..RuntimeControlCapabilities::default()
            },
        )?;
        let protector = ResolvedRuntimeControl::active(
            "protector",
            None,
            RuntimeControlCapabilities {
                write_protections: vec![WriteProtection {
                    path: output,
                    scope: PathScope::Exact,
                }],
                ..RuntimeControlCapabilities::default()
            },
        )?;
        let mut policy = PolicySpec::default();

        let error = match RuntimeControls::new(vec![writer, protector]).apply_to(&mut policy) {
            Ok(()) => return Err("runtime-control conflict unexpectedly composed".into()),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .starts_with("writer runtime control failed:")
        );
        assert!(policy.files.is_empty());
        assert!(policy.write_protections.is_empty());
        Ok(())
    }
}
