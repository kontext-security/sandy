//! Semantic validation and trusted-state transitions for a launch manifest.
//!
//! Deserialization proves only that input has the expected shape. This module establishes the
//! boundedness and invariants relied upon by the bootstrap and policy compiler.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::{
    AbsolutePath, CommandSpec, EnvironmentEntry, LaunchManifestV2, MANIFEST_SCHEMA_V2,
    OsValueError, PolicySpec,
};

const MAX_ARGUMENTS: usize = 4_096;
const MAX_ENVIRONMENT_ENTRIES: usize = 4_096;
pub(crate) const MAX_FILE_GRANTS: usize = 1_024;
pub(crate) const MAX_EXECUTABLE_GRANTS: usize = 1_024;
pub(crate) const MAX_UNIX_SOCKET_GRANTS: usize = 128;
pub(crate) const MAX_LOCAL_HOST_TCP_GRANTS: usize = 128;
pub(crate) const MAX_PROTECTED_PATHS: usize = 1_024;

/// Policy that has passed the complete policy-validation transition.
///
/// The tuple field is private so enforcement backends cannot construct this proof from an
/// arbitrary [`PolicySpec`]. A launch validates this policy alongside its command and environment;
/// an embedding boundary may validate it directly before current-process enforcement.
#[derive(Clone, Debug)]
pub struct ValidatedPolicy(PolicySpec);

impl ValidatedPolicy {
    /// Borrows the typed policy proven safe for backend compilation.
    #[must_use]
    pub fn spec(&self) -> &PolicySpec {
        &self.0
    }
}

/// Launch manifest whose schema, native values, bounds, and policy invariants are valid.
#[derive(Clone, Debug)]
pub struct ValidatedLaunch {
    manifest: LaunchManifestV2,
    policy: ValidatedPolicy,
}

impl ValidatedLaunch {
    /// Borrows the validated transport manifest.
    #[must_use]
    pub fn manifest(&self) -> &LaunchManifestV2 {
        &self.manifest
    }

    /// Borrows the policy proof accepted by enforcement backends.
    #[must_use]
    pub fn policy(&self) -> &ValidatedPolicy {
        &self.policy
    }

    /// Consumes the proof while retaining the validated manifest data.
    ///
    /// This is used when the trusted parent serializes a manifest for the bootstrap. The bootstrap
    /// validates the decoded value again and does not trust this prior in-process transition.
    #[must_use]
    pub fn into_manifest(self) -> LaunchManifestV2 {
        self.manifest
    }
}

impl TryFrom<LaunchManifestV2> for ValidatedLaunch {
    type Error = ValidationError;

    fn try_from(manifest: LaunchManifestV2) -> Result<Self, Self::Error> {
        if manifest.schema_version != MANIFEST_SCHEMA_V2 {
            return Err(ValidationError::UnsupportedSchema(manifest.schema_version));
        }
        validate_command(&manifest.command)?;
        validate_environment(&manifest.environment)?;

        // Root is not a useful project boundary: it would turn the normal working-directory
        // grant into host-wide access during CLI resolution.
        if manifest.working_directory.is_root() {
            return Err(ValidationError::RootWorkingDirectory);
        }
        let policy = ValidatedPolicy::try_from(manifest.policy.clone())?;
        Ok(Self { manifest, policy })
    }
}

impl TryFrom<PolicySpec> for ValidatedPolicy {
    type Error = ValidationError;

    fn try_from(policy: PolicySpec) -> Result<Self, Self::Error> {
        validate_policy(&policy)?;
        Ok(Self(policy))
    }
}

fn validate_command(command: &CommandSpec) -> Result<(), ValidationError> {
    command
        .program
        .validate_native()
        .map_err(ValidationError::InvalidProgram)?;
    if command.program.as_bytes().is_empty() {
        return Err(ValidationError::EmptyProgram);
    }
    if command.arguments.len() > MAX_ARGUMENTS {
        return Err(ValidationError::TooManyArguments);
    }
    for argument in &command.arguments {
        argument
            .validate_native()
            .map_err(ValidationError::InvalidArgument)?;
    }
    Ok(())
}

fn validate_environment(environment: &[EnvironmentEntry]) -> Result<(), ValidationError> {
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(ValidationError::TooManyEnvironmentEntries);
    }
    for entry in environment {
        entry
            .key
            .validate_native()
            .map_err(ValidationError::InvalidEnvironment)?;
        entry
            .value
            .validate_native()
            .map_err(ValidationError::InvalidEnvironment)?;
        // `execve` receives `key=value` entries, so an empty key or embedded `=` would change the
        // intended environment structure even though the bytes contain no NUL.
        if entry.key.as_bytes().is_empty() || entry.key.as_bytes().contains(&b'=') {
            return Err(ValidationError::InvalidEnvironmentKey);
        }
    }
    Ok(())
}

fn validate_policy(policy: &PolicySpec) -> Result<(), ValidationError> {
    if policy.runtime_compatibility == crate::RuntimeCompatibility::ForegroundCli
        && !policy.allow_subprocesses
    {
        return Err(ValidationError::ForegroundRequiresSubprocesses);
    }
    validate_policy_bounds(policy)?;
    if policy.network == crate::NetworkPolicy::AllowAll && !policy.local_host_tcp.is_empty() {
        return Err(ValidationError::LocalHostTcpRequiresBlockedNetwork);
    }
    if policy.files.iter().any(|grant| {
        grant.path.is_root()
            && (grant.access != crate::AccessMode::Read || grant.scope != crate::PathScope::Exact)
    }) {
        return Err(ValidationError::RootGrant);
    }
    if policy.executables.iter().any(|grant| grant.path.is_root()) {
        return Err(ValidationError::RootExecutableGrant);
    }
    if policy.unix_sockets.iter().any(|grant| grant.path.is_root()) {
        return Err(ValidationError::RootUnixSocketGrant);
    }
    if policy.protected_paths.iter().any(AbsolutePath::is_root)
        || policy
            .write_protections
            .iter()
            .any(|protection| protection.path.is_root())
    {
        return Err(ValidationError::RootProtectedPath);
    }

    // Preserve access and scope in the identity. Two grants for one path may be intentional when
    // they describe different capabilities; only exact duplicate triples are malformed here.
    let mut seen = BTreeSet::new();
    for grant in &policy.files {
        let identity = (grant.path.clone(), grant.access, grant.scope);
        if !seen.insert(identity) {
            return Err(ValidationError::DuplicateGrant(grant.path.clone()));
        }
    }
    let mut seen_executables = BTreeSet::new();
    for grant in &policy.executables {
        let identity = (grant.path.clone(), grant.scope);
        if !seen_executables.insert(identity) {
            return Err(ValidationError::DuplicateExecutableGrant(
                grant.path.clone(),
            ));
        }
    }
    let mut seen_sockets = BTreeSet::new();
    for grant in &policy.unix_sockets {
        let identity = (grant.path.clone(), grant.operation);
        if !seen_sockets.insert(identity) {
            return Err(ValidationError::DuplicateUnixSocketGrant(
                grant.path.clone(),
            ));
        }
    }
    let mut seen_local_host_tcp = BTreeSet::new();
    for grant in &policy.local_host_tcp {
        if !seen_local_host_tcp.insert(grant) {
            return Err(ValidationError::DuplicateLocalHostTcpGrant(grant.port));
        }
    }
    reject_duplicate_paths(&policy.protected_paths)?;
    let mut seen_write_protections = BTreeSet::new();
    for protection in &policy.write_protections {
        if !seen_write_protections.insert(&protection.path) {
            return Err(ValidationError::DuplicateWriteProtection(
                protection.path.clone(),
            ));
        }
    }
    if let Some((resource, ancestor)) = policy.unprotected_writable_ancestor() {
        return Err(ValidationError::UnprotectedWritableAncestor {
            resource: resource.clone(),
            ancestor,
        });
    }
    Ok(())
}

pub(crate) fn validate_policy_bounds(policy: &PolicySpec) -> Result<(), ValidationError> {
    if policy.files.len() > MAX_FILE_GRANTS {
        return Err(ValidationError::TooManyFileGrants);
    }
    if policy.executables.len() > MAX_EXECUTABLE_GRANTS {
        return Err(ValidationError::TooManyExecutableGrants);
    }
    if policy.unix_sockets.len() > MAX_UNIX_SOCKET_GRANTS {
        return Err(ValidationError::TooManyUnixSocketGrants);
    }
    if policy.local_host_tcp.len() > MAX_LOCAL_HOST_TCP_GRANTS {
        return Err(ValidationError::TooManyLocalHostTcpGrants);
    }
    if policy.protected_paths.len() > MAX_PROTECTED_PATHS
        || policy.write_protections.len() > MAX_PROTECTED_PATHS
    {
        return Err(ValidationError::TooManyProtectedPaths);
    }
    Ok(())
}

fn reject_duplicate_paths(paths: &[AbsolutePath]) -> Result<(), ValidationError> {
    let mut seen = BTreeSet::new();
    for path in paths {
        if !seen.insert(path) {
            return Err(ValidationError::DuplicateProtectedPath(path.clone()));
        }
    }
    Ok(())
}

/// Failure to establish the launch invariants required by the bootstrap or compiler.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// Foreground CLI behavior is defined only for a subprocess-capable policy.
    #[error("foreground compatibility requires subprocess support")]
    ForegroundRequiresSubprocesses,
    /// The bootstrap does not understand the supplied manifest version.
    #[error("unsupported launch manifest schema version {0}")]
    UnsupportedSchema(u32),
    /// No executable was supplied.
    #[error("target program is empty")]
    EmptyProgram,
    /// The executable cannot be represented at the native boundary.
    #[error("target program is invalid: {0}")]
    InvalidProgram(OsValueError),
    /// An argument cannot be represented at the native boundary.
    #[error("target argument is invalid: {0}")]
    InvalidArgument(OsValueError),
    /// An environment name or value cannot be represented at the native boundary.
    #[error("target environment is invalid: {0}")]
    InvalidEnvironment(OsValueError),
    /// An environment key cannot form one unambiguous `key=value` entry.
    #[error("environment key is empty or contains '='")]
    InvalidEnvironmentKey,
    /// The command exceeds the bounded argument count.
    #[error("launch contains too many arguments")]
    TooManyArguments,
    /// The launch exceeds the bounded environment-entry count.
    #[error("launch contains too many environment entries")]
    TooManyEnvironmentEntries,
    /// The policy exceeds the bounded filesystem-grant count.
    #[error("launch contains too many file grants")]
    TooManyFileGrants,
    /// The policy exceeds the bounded executable-mapping count.
    #[error("launch contains too many executable grants")]
    TooManyExecutableGrants,
    /// The policy exceeds the bounded exact Unix-socket grant count.
    #[error("launch contains too many Unix-socket grants")]
    TooManyUnixSocketGrants,
    /// The policy exceeds the bounded exact local-host TCP grant count.
    #[error("launch contains too many local-host TCP grants")]
    TooManyLocalHostTcpGrants,
    /// The policy exceeds the bounded protected-path count.
    #[error("launch contains too many protected paths")]
    TooManyProtectedPaths,
    /// Sandy refuses to treat the filesystem root as a project directory.
    #[error("the filesystem root cannot be used as the working directory")]
    RootWorkingDirectory,
    /// Sandy refuses a recursive or writable root capability.
    #[error("the filesystem root may only be granted exact read access")]
    RootGrant,
    /// Sandy refuses executable mapping across the filesystem root.
    #[error("the filesystem root cannot be granted executable mapping")]
    RootExecutableGrant,
    /// Sandy refuses the filesystem root as an exact Unix-socket pathname.
    #[error("the filesystem root cannot be granted as a Unix socket")]
    RootUnixSocketGrant,
    /// Protecting root is either redundant or evidence of a malformed policy.
    #[error("the filesystem root cannot be protected as a path capability")]
    RootProtectedPath,
    /// The policy contains an exact duplicate filesystem capability.
    #[error("duplicate filesystem grant for {0:?}")]
    DuplicateGrant(AbsolutePath),
    /// The policy contains an exact duplicate executable-mapping capability.
    #[error("duplicate executable grant for {0:?}")]
    DuplicateExecutableGrant(AbsolutePath),
    /// The policy contains an exact duplicate Unix-socket capability.
    #[error("duplicate Unix-socket grant for {0:?}")]
    DuplicateUnixSocketGrant(AbsolutePath),
    /// The policy contains an exact duplicate local-host TCP capability.
    #[error("duplicate local-host TCP grant for port {0}")]
    DuplicateLocalHostTcpGrant(crate::TcpPort),
    /// A local-host exception has no narrow meaning when all networking is allowed.
    #[error("local-host TCP grants require the block-all network policy")]
    LocalHostTcpRequiresBlockedNetwork,
    /// A protected-path list contains the same path more than once.
    #[error("duplicate protected path for {0:?}")]
    DuplicateProtectedPath(AbsolutePath),
    /// A write-protection list contains the same path more than once.
    #[error("duplicate write protection for {0:?}")]
    DuplicateWriteProtection(AbsolutePath),
    /// A protected resource could be relocated through an enclosing writable directory.
    #[error("protected resource {resource:?} has unprotected writable ancestor {ancestor:?}")]
    UnprotectedWritableAncestor {
        /// Resource whose stable pathname is part of the policy invariant.
        resource: AbsolutePath,
        /// Enclosing directory that must be pinned against rename or replacement.
        ancestor: AbsolutePath,
    },
}
