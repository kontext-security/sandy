//! Semantic validation and trusted-state transitions for a launch manifest.
//!
//! Deserialization proves only that input has the expected shape. This module establishes the
//! boundedness and invariants relied upon by the bootstrap and policy compiler.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::{
    AbsolutePath, CommandSpec, EnvironmentEntry, LaunchManifestV1, MANIFEST_SCHEMA_V1,
    OsValueError, PolicySpec,
};

const MAX_ARGUMENTS: usize = 4_096;
const MAX_ENVIRONMENT_ENTRIES: usize = 4_096;
const MAX_FILE_GRANTS: usize = 1_024;
const MAX_UNIX_SOCKET_GRANTS: usize = 128;
const MAX_PROTECTED_PATHS: usize = 1_024;

/// Policy that has passed the complete launch-validation transition.
///
/// The tuple field is private so enforcement backends cannot construct this proof from an
/// arbitrary [`PolicySpec`]. Validation happens at launch level because command, environment, and
/// policy bounds jointly protect the bootstrap protocol.
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
    manifest: LaunchManifestV1,
    policy: ValidatedPolicy,
}

impl ValidatedLaunch {
    /// Borrows the validated transport manifest.
    #[must_use]
    pub fn manifest(&self) -> &LaunchManifestV1 {
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
    pub fn into_manifest(self) -> LaunchManifestV1 {
        self.manifest
    }
}

impl TryFrom<LaunchManifestV1> for ValidatedLaunch {
    type Error = ValidationError;

    fn try_from(manifest: LaunchManifestV1) -> Result<Self, Self::Error> {
        if manifest.schema_version != MANIFEST_SCHEMA_V1 {
            return Err(ValidationError::UnsupportedSchema(manifest.schema_version));
        }
        validate_command(&manifest.command)?;
        validate_environment(&manifest.environment)?;

        // Root is not a useful project boundary: it would turn the normal working-directory
        // grant into host-wide access during CLI resolution.
        if manifest.working_directory.is_root() {
            return Err(ValidationError::RootWorkingDirectory);
        }
        validate_policy(&manifest.policy)?;

        let policy = ValidatedPolicy(manifest.policy.clone());
        Ok(Self { manifest, policy })
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
    if policy.files.len() > MAX_FILE_GRANTS {
        return Err(ValidationError::TooManyFileGrants);
    }
    if policy.unix_sockets.len() > MAX_UNIX_SOCKET_GRANTS {
        return Err(ValidationError::TooManyUnixSocketGrants);
    }
    if policy.protected_paths.len() > MAX_PROTECTED_PATHS
        || policy.protected_write_paths.len() > MAX_PROTECTED_PATHS
    {
        return Err(ValidationError::TooManyProtectedPaths);
    }
    if policy.files.iter().any(|grant| grant.path.is_root()) {
        return Err(ValidationError::RootGrant);
    }
    if policy.unix_sockets.iter().any(|grant| grant.path.is_root()) {
        return Err(ValidationError::RootUnixSocketGrant);
    }
    if policy.protected_paths.iter().any(AbsolutePath::is_root)
        || policy
            .protected_write_paths
            .iter()
            .any(AbsolutePath::is_root)
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
    let mut seen_sockets = BTreeSet::new();
    for grant in &policy.unix_sockets {
        let identity = (grant.path.clone(), grant.operation);
        if !seen_sockets.insert(identity) {
            return Err(ValidationError::DuplicateUnixSocketGrant(
                grant.path.clone(),
            ));
        }
    }
    reject_duplicate_paths(&policy.protected_paths)?;
    reject_duplicate_paths(&policy.protected_write_paths)?;
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
    /// The policy exceeds the bounded exact Unix-socket grant count.
    #[error("launch contains too many Unix-socket grants")]
    TooManyUnixSocketGrants,
    /// The policy exceeds the bounded protected-path count.
    #[error("launch contains too many protected paths")]
    TooManyProtectedPaths,
    /// Sandy refuses to treat the filesystem root as a project directory.
    #[error("the filesystem root cannot be used as the working directory")]
    RootWorkingDirectory,
    /// Sandy refuses a host-wide positive filesystem capability.
    #[error("the filesystem root cannot be granted")]
    RootGrant,
    /// Sandy refuses the filesystem root as an exact Unix-socket pathname.
    #[error("the filesystem root cannot be granted as a Unix socket")]
    RootUnixSocketGrant,
    /// Protecting root is either redundant or evidence of a malformed policy.
    #[error("the filesystem root cannot be protected as a path capability")]
    RootProtectedPath,
    /// The policy contains an exact duplicate filesystem capability.
    #[error("duplicate filesystem grant for {0:?}")]
    DuplicateGrant(AbsolutePath),
    /// The policy contains an exact duplicate Unix-socket capability.
    #[error("duplicate Unix-socket grant for {0:?}")]
    DuplicateUnixSocketGrant(AbsolutePath),
    /// A protected-path list contains the same path more than once.
    #[error("duplicate protected path for {0:?}")]
    DuplicateProtectedPath(AbsolutePath),
}
