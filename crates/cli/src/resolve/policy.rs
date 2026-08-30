//! CLI-owned ambient resolution for shared policy intent.

use std::path::Path;

use sandy_core::{
    AbsolutePath, ExecutableGrant, PathScope, PolicySpec, SandboxPolicy, WriteProtection,
    into_policy_parts,
};

use crate::error::AppError;

use super::{absolute_if_utf8, grant, scoped_write_protections};

pub(crate) fn resolve_policy(
    policy: SandboxPolicy,
    protected: &[AbsolutePath],
) -> Result<PolicySpec, AppError> {
    let parts = into_policy_parts(policy)?;
    let mut files = Vec::with_capacity(parts.grants.len());
    for unresolved in parts.grants {
        files.push(grant(
            &unresolved.path,
            unresolved.access,
            unresolved.scope,
            protected,
        )?);
    }

    let mut protected_paths = Vec::new();
    for path in parts.denied_subtrees {
        if !path.is_absolute() || path == Path::new("/") {
            return Err(AppError::InvalidPolicyPath(path));
        }
        protected_paths.push(absolute_if_utf8(&path)?);
    }

    let mut executables = Vec::with_capacity(parts.executables.len());
    for unresolved in parts.executables {
        let resolved = grant(
            &unresolved.path,
            sandy_core::AccessMode::Read,
            unresolved.scope,
            protected,
        )?;
        executables.push(ExecutableGrant {
            path: resolved.path,
            scope: resolved.scope,
        });
    }

    let mut write_protections = Vec::<WriteProtection>::new();
    for path in parts.write_denied_exact {
        write_protections.extend(scoped_write_protections([path], PathScope::Exact)?);
    }

    let mut resolved = PolicySpec {
        files,
        executables,
        protected_paths,
        write_protections,
        unix_sockets: Vec::new(),
        local_host_tcp: Vec::new(),
        file_metadata: parts.file_metadata,
        allow_subprocesses: parts.allow_subprocesses,
        runtime_compatibility: parts.runtime_compatibility,
        network: parts.network,
    };
    resolved.normalize();
    Ok(resolved)
}
