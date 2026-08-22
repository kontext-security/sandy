use std::collections::BTreeSet;

use sandy_core::{AbsolutePath, AccessMode, FileGrant, PathScope};

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
    version: Option<String>,
    files: Option<RuntimeControlFiles>,
    requires_network: bool,
}

impl RuntimeControlBridge {
    pub(crate) fn inactive(service: &'static str) -> Self {
        Self {
            service,
            version: None,
            files: None,
            requires_network: false,
        }
    }

    pub(crate) fn active(
        service: &'static str,
        version: Option<String>,
        files: RuntimeControlFiles,
        requires_network: bool,
    ) -> Result<Self, AppError> {
        files.validate(service)?;
        Ok(Self {
            service,
            version,
            files: Some(files),
            requires_network,
        })
    }

    pub(crate) fn service(&self) -> &'static str {
        self.service
    }

    pub(crate) fn is_active(&self) -> bool {
        self.files.is_some()
    }

    pub(crate) fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub(crate) fn requires_network(&self) -> bool {
        self.requires_network
    }

    pub(crate) fn contribute(
        &self,
        grants: &mut Vec<FileGrant>,
        protected_write_paths: &mut Vec<AbsolutePath>,
    ) {
        let Some(files) = &self.files else {
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
            false,
        );
        assert!(matches!(result, Err(AppError::RuntimeControl { .. })));
        Ok(())
    }

    #[test]
    fn inactive_bridge_contributes_nothing() {
        let bridge = RuntimeControlBridge::inactive("test");
        let mut grants = Vec::new();
        let mut protected = Vec::new();
        bridge.contribute(&mut grants, &mut protected);
        assert!(grants.is_empty());
        assert!(protected.is_empty());
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
                read_only: vec![readable.clone()],
                read_write: vec![socket.clone()],
                protected_from_write: vec![readable.clone()],
            },
            true,
        )?;
        let mut grants = Vec::new();
        let mut protected = Vec::new();
        bridge.contribute(&mut grants, &mut protected);

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
                .any(|grant| { grant.path == socket && grant.access == AccessMode::ReadWrite })
        );
        assert_eq!(protected, [readable]);
        assert!(bridge.requires_network());
        Ok(())
    }
}
