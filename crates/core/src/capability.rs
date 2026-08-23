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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnixSocketOperation {
    Connect,
}

/// Authority for one operation on one exact pathname Unix socket.
///
/// This is deliberately independent from [`FileGrant`]. Filesystem access to
/// a socket path never implies permission to connect to the service behind it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct UnixSocketGrant {
    pub path: AbsolutePath,
    pub operation: UnixSocketOperation,
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
    /// Additive in manifest schema v1: an omitted list grants no socket
    /// authority, so older manifests remain fail-closed without a version bump.
    #[serde(default)]
    pub unix_sockets: Vec<UnixSocketGrant>,
    pub network: NetworkPolicy,
}
