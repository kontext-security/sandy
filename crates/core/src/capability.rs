use serde::{Deserialize, Serialize};

use crate::AbsolutePath;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    Read,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathScope {
    Exact,
    Subtree,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileGrant {
    pub path: AbsolutePath,
    pub access: AccessMode,
    pub scope: PathScope,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    #[default]
    AllowAll,
    BlockAll,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicySpec {
    pub files: Vec<FileGrant>,
    pub protected_paths: Vec<AbsolutePath>,
    pub protected_write_paths: Vec<AbsolutePath>,
    pub network: NetworkPolicy,
}
