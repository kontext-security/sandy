use serde::{Deserialize, Serialize};

use crate::{AbsolutePath, CommandSpec, EnvironmentEntry, PolicySpec};

pub const MANIFEST_SCHEMA_V1: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchManifestV1 {
    pub schema_version: u32,
    pub command: CommandSpec,
    pub working_directory: AbsolutePath,
    pub environment: Vec<EnvironmentEntry>,
    pub policy: PolicySpec,
}
