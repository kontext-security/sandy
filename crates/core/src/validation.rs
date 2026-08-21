use std::collections::BTreeSet;

use thiserror::Error;

use crate::{AbsolutePath, LaunchManifestV1, MANIFEST_SCHEMA_V1, OsValueError, PolicySpec};

const MAX_ARGUMENTS: usize = 4_096;
const MAX_ENVIRONMENT_ENTRIES: usize = 4_096;
const MAX_FILE_GRANTS: usize = 1_024;
const MAX_PROTECTED_PATHS: usize = 1_024;

#[derive(Clone, Debug)]
pub struct ValidatedPolicy(PolicySpec);

impl ValidatedPolicy {
    #[must_use]
    pub fn spec(&self) -> &PolicySpec {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedLaunch {
    manifest: LaunchManifestV1,
    policy: ValidatedPolicy,
}

impl ValidatedLaunch {
    #[must_use]
    pub fn manifest(&self) -> &LaunchManifestV1 {
        &self.manifest
    }

    #[must_use]
    pub fn policy(&self) -> &ValidatedPolicy {
        &self.policy
    }

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
        manifest
            .command
            .program
            .validate_native()
            .map_err(ValidationError::InvalidProgram)?;
        if manifest.command.program.as_bytes().is_empty() {
            return Err(ValidationError::EmptyProgram);
        }
        if manifest.command.arguments.len() > MAX_ARGUMENTS {
            return Err(ValidationError::TooManyArguments);
        }
        for argument in &manifest.command.arguments {
            argument
                .validate_native()
                .map_err(ValidationError::InvalidArgument)?;
        }
        if manifest.environment.len() > MAX_ENVIRONMENT_ENTRIES {
            return Err(ValidationError::TooManyEnvironmentEntries);
        }
        for entry in &manifest.environment {
            entry
                .key
                .validate_native()
                .map_err(ValidationError::InvalidEnvironment)?;
            entry
                .value
                .validate_native()
                .map_err(ValidationError::InvalidEnvironment)?;
            if entry.key.as_bytes().is_empty() || entry.key.as_bytes().contains(&b'=') {
                return Err(ValidationError::InvalidEnvironmentKey);
            }
        }
        if manifest.policy.files.len() > MAX_FILE_GRANTS {
            return Err(ValidationError::TooManyFileGrants);
        }
        if manifest.policy.protected_paths.len() > MAX_PROTECTED_PATHS {
            return Err(ValidationError::TooManyProtectedPaths);
        }
        if manifest.policy.protected_write_paths.len() > MAX_PROTECTED_PATHS {
            return Err(ValidationError::TooManyProtectedPaths);
        }
        if manifest.working_directory.is_root() {
            return Err(ValidationError::RootWorkingDirectory);
        }
        if manifest
            .policy
            .files
            .iter()
            .any(|grant| grant.path.is_root())
        {
            return Err(ValidationError::RootGrant);
        }

        let mut seen = BTreeSet::new();
        for grant in &manifest.policy.files {
            let identity = (grant.path.clone(), grant.access, grant.scope);
            if !seen.insert(identity) {
                return Err(ValidationError::DuplicateGrant(grant.path.clone()));
            }
        }

        let policy = ValidatedPolicy(manifest.policy.clone());
        Ok(Self { manifest, policy })
    }
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("unsupported launch manifest schema version {0}")]
    UnsupportedSchema(u32),
    #[error("target program is empty")]
    EmptyProgram,
    #[error("target program is invalid: {0}")]
    InvalidProgram(OsValueError),
    #[error("target argument is invalid: {0}")]
    InvalidArgument(OsValueError),
    #[error("target environment is invalid: {0}")]
    InvalidEnvironment(OsValueError),
    #[error("environment key is empty or contains '='")]
    InvalidEnvironmentKey,
    #[error("launch contains too many arguments")]
    TooManyArguments,
    #[error("launch contains too many environment entries")]
    TooManyEnvironmentEntries,
    #[error("launch contains too many file grants")]
    TooManyFileGrants,
    #[error("launch contains too many protected paths")]
    TooManyProtectedPaths,
    #[error("the filesystem root cannot be used as the working directory")]
    RootWorkingDirectory,
    #[error("the filesystem root cannot be granted")]
    RootGrant,
    #[error("duplicate filesystem grant for {0:?}")]
    DuplicateGrant(AbsolutePath),
}
