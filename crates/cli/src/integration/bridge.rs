use std::collections::BTreeSet;

use sandy_core::{AbsolutePath, AccessMode, FileGrant, PathScope, UnixSocketGrant};

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

/// A validated, provider-independent capability contribution for a host
/// service that controls part of the sandboxed runtime.
#[derive(Clone, Debug)]
pub(crate) struct RuntimeControlBridge {
    service: &'static str,
    state: RuntimeControlState,
}

#[derive(Clone, Debug)]
enum RuntimeControlState {
    Inactive,
    Unavailable {
        reason: String,
    },
    Active {
        version: Option<String>,
        files: RuntimeControlFiles,
        unix_sockets: Vec<UnixSocketGrant>,
    },
}

impl RuntimeControlBridge {
    pub(crate) fn inactive(service: &'static str) -> Self {
        Self {
            service,
            state: RuntimeControlState::Inactive,
        }
    }

    pub(crate) fn unavailable(service: &'static str, reason: impl Into<String>) -> Self {
        Self {
            service,
            state: RuntimeControlState::Unavailable {
                reason: reason.into(),
            },
        }
    }

    pub(crate) fn active(
        service: &'static str,
        version: Option<String>,
        files: RuntimeControlFiles,
        unix_sockets: Vec<UnixSocketGrant>,
    ) -> Result<Self, AppError> {
        files.validate(service)?;
        validate_unix_sockets(service, &files, &unix_sockets)?;
        Ok(Self {
            service,
            state: RuntimeControlState::Active {
                version,
                files,
                unix_sockets,
            },
        })
    }

    pub(crate) fn service(&self) -> &'static str {
        self.service
    }

    pub(crate) fn is_active(&self) -> bool {
        matches!(&self.state, RuntimeControlState::Active { .. })
    }

    pub(crate) fn version(&self) -> Option<&str> {
        match &self.state {
            RuntimeControlState::Active { version, .. } => version.as_deref(),
            RuntimeControlState::Inactive | RuntimeControlState::Unavailable { .. } => None,
        }
    }

    pub(crate) fn unavailable_reason(&self) -> Option<&str> {
        match &self.state {
            RuntimeControlState::Unavailable { reason } => Some(reason),
            RuntimeControlState::Inactive | RuntimeControlState::Active { .. } => None,
        }
    }

    pub(crate) fn contribute(
        &self,
        grants: &mut Vec<FileGrant>,
        protected_write_paths: &mut Vec<AbsolutePath>,
        unix_sockets: &mut Vec<UnixSocketGrant>,
    ) {
        let RuntimeControlState::Active {
            files,
            unix_sockets: bridge_sockets,
            ..
        } = &self.state
        else {
            return;
        };
        grants.extend(files.executables.iter().cloned().map(|path| FileGrant {
            path,
            access: AccessMode::Read,
            scope: PathScope::Exact,
        }));
        grants.extend(files.read_only.iter().cloned().map(|path| FileGrant {
            path,
            access: AccessMode::Read,
            scope: PathScope::Exact,
        }));
        grants.extend(files.read_write.iter().cloned().map(|path| FileGrant {
            path,
            access: AccessMode::ReadWrite,
            scope: PathScope::Exact,
        }));
        protected_write_paths.extend(files.protected_from_write.iter().cloned());
        unix_sockets.extend(bridge_sockets.iter().cloned());
    }
}

/// File intents are kept disjoint here and translated into Sandy's existing
/// typed policy only after provider-specific discovery has completed.
#[derive(Clone, Debug)]
pub(crate) struct RuntimeControlFiles {
    pub(crate) executables: Vec<AbsolutePath>,
    pub(crate) read_only: Vec<AbsolutePath>,
    pub(crate) read_write: Vec<AbsolutePath>,
    pub(crate) protected_from_write: Vec<AbsolutePath>,
}

impl RuntimeControlFiles {
    fn validate(&self, service: &'static str) -> Result<(), AppError> {
        let mut intents = BTreeSet::new();
        for path in self
            .executables
            .iter()
            .chain(&self.read_only)
            .chain(&self.read_write)
        {
            if !intents.insert(path.clone()) {
                return Err(overlapping_files(service));
            }
        }
        Ok(())
    }
}

fn overlapping_files(service: &'static str) -> AppError {
    AppError::runtime_control(
        service,
        "resolved file intents overlap; refusing to broaden the runtime policy",
    )
}

fn validate_unix_sockets(
    service: &'static str,
    files: &RuntimeControlFiles,
    unix_sockets: &[UnixSocketGrant],
) -> Result<(), AppError> {
    let mut seen = BTreeSet::new();
    for grant in unix_sockets {
        if !seen.insert(grant) {
            return Err(AppError::runtime_control(
                service,
                "resolved Unix-socket grants overlap; refusing to broaden the runtime policy",
            ));
        }
        if !files.read_only.iter().any(|path| path == &grant.path) {
            return Err(AppError::runtime_control(
                service,
                "a Unix-socket grant is missing its separate read-only filesystem intent",
            ));
        }
        if !files
            .protected_from_write
            .iter()
            .any(|path| path == &grant.path)
        {
            return Err(AppError::runtime_control(
                service,
                "a Unix-socket grant is not protected from overlapping filesystem writes",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_overlapping_file_intents() -> Result<(), Box<dyn std::error::Error>> {
        let executable = AbsolutePath::new("/opt/tool/bin/control")?;
        let result = RuntimeControlBridge::active(
            "test",
            None,
            RuntimeControlFiles {
                executables: vec![executable.clone()],
                read_only: vec![executable],
                read_write: Vec::new(),
                protected_from_write: Vec::new(),
            },
            Vec::new(),
        );
        assert!(matches!(result, Err(AppError::RuntimeControl { .. })));
        Ok(())
    }

    #[test]
    fn inactive_bridge_contributes_nothing() {
        let bridge = RuntimeControlBridge::inactive("test");
        let mut grants = Vec::new();
        let mut protected = Vec::new();
        let mut sockets = Vec::new();
        bridge.contribute(&mut grants, &mut protected, &mut sockets);
        assert!(grants.is_empty());
        assert!(protected.is_empty());
        assert!(sockets.is_empty());
    }

    #[test]
    fn unavailable_bridge_contributes_nothing_and_preserves_reason() {
        let bridge = RuntimeControlBridge::unavailable("test", "provider is unavailable");
        let mut grants = Vec::new();
        let mut protected = Vec::new();
        let mut sockets = Vec::new();
        bridge.contribute(&mut grants, &mut protected, &mut sockets);
        assert!(grants.is_empty());
        assert!(protected.is_empty());
        assert!(sockets.is_empty());
        assert_eq!(bridge.unavailable_reason(), Some("provider is unavailable"));
    }

    #[test]
    fn active_bridge_preserves_disjoint_file_intents() -> Result<(), Box<dyn std::error::Error>> {
        let executable = AbsolutePath::new("/opt/tool/bin/control")?;
        let readable = AbsolutePath::new("/opt/tool/config.json")?;
        let socket = AbsolutePath::new("/private/tmp/control.sock")?;
        let bridge = RuntimeControlBridge::active(
            "test",
            Some("1.0.0".to_owned()),
            RuntimeControlFiles {
                executables: vec![executable.clone()],
                read_only: vec![readable.clone(), socket.clone()],
                read_write: Vec::new(),
                protected_from_write: vec![readable.clone(), socket.clone()],
            },
            vec![UnixSocketGrant {
                path: socket.clone(),
                operation: sandy_core::UnixSocketOperation::Connect,
            }],
        )?;
        let mut grants = Vec::new();
        let mut protected = Vec::new();
        let mut sockets = Vec::new();
        bridge.contribute(&mut grants, &mut protected, &mut sockets);

        assert_eq!(grants.len(), 3);
        assert!(
            grants
                .iter()
                .any(|grant| { grant.path == executable && grant.access == AccessMode::Read })
        );
        assert!(
            grants
                .iter()
                .any(|grant| { grant.path == readable && grant.access == AccessMode::Read })
        );
        assert!(
            grants
                .iter()
                .any(|grant| { grant.path == socket && grant.access == AccessMode::Read })
        );
        assert_eq!(protected, [readable, socket.clone()]);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].path, socket);
        Ok(())
    }

    #[test]
    fn rejects_socket_authority_without_a_separate_file_intent()
    -> Result<(), Box<dyn std::error::Error>> {
        let socket = AbsolutePath::new("/private/tmp/control.sock")?;
        let result = RuntimeControlBridge::active(
            "test",
            None,
            RuntimeControlFiles {
                executables: Vec::new(),
                read_only: Vec::new(),
                read_write: Vec::new(),
                protected_from_write: Vec::new(),
            },
            vec![UnixSocketGrant {
                path: socket,
                operation: sandy_core::UnixSocketOperation::Connect,
            }],
        );
        assert!(matches!(result, Err(AppError::RuntimeControl { .. })));
        Ok(())
    }

    #[test]
    fn rejects_connect_only_socket_with_a_write_file_intent()
    -> Result<(), Box<dyn std::error::Error>> {
        let socket = AbsolutePath::new("/private/tmp/control.sock")?;
        let result = RuntimeControlBridge::active(
            "test",
            None,
            RuntimeControlFiles {
                executables: Vec::new(),
                read_only: Vec::new(),
                read_write: vec![socket.clone()],
                protected_from_write: Vec::new(),
            },
            vec![UnixSocketGrant {
                path: socket,
                operation: sandy_core::UnixSocketOperation::Connect,
            }],
        );
        assert!(matches!(result, Err(AppError::RuntimeControl { .. })));
        Ok(())
    }
}
