//! Typed, platform-neutral vocabulary for kernel-enforced launch policy.
//!
//! This module describes intent only. It does not discover paths or contain Seatbelt source;
//! platform backends are responsible for lowering a validated policy into native rules.

use serde::{Deserialize, Serialize};

use crate::AbsolutePath;

/// Filesystem operations granted for a path.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    /// Permit reads but no mutations.
    Read,
    /// Permit reads and mutations.
    ReadWrite,
}

/// Whether a filesystem rule addresses one node or a complete hierarchy.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathScope {
    /// Match only the named filesystem node.
    Exact,
    /// Match the named directory and everything beneath it.
    Subtree,
}

/// One filesystem capability in the resolved launch policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileGrant {
    /// Absolute, CLI-resolved path supplied to the enforcement backend.
    pub path: AbsolutePath,
    /// Operations allowed at the path.
    pub access: AccessMode,
    /// Exact-node or recursive matching semantics.
    pub scope: PathScope,
}

/// Operation authorized for an exact pathname Unix socket.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnixSocketOperation {
    /// Connect to an existing socket without authorizing bind or filesystem mutation.
    Connect,
}

/// Authority for one operation on one exact pathname Unix socket.
///
/// This is deliberately independent from [`FileGrant`]. Filesystem access to
/// a socket path never implies permission to connect to the service behind it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct UnixSocketGrant {
    /// Exact absolute socket pathname accepted by the enforcement backend.
    pub path: AbsolutePath,
    /// Socket operation authorized at the path.
    pub operation: UnixSocketOperation,
}

/// Network policy for the complete sandboxed process tree.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// Permit network operations for agent compatibility.
    #[default]
    AllowAll,
    /// Emit no network allow rule, leaving the deny-first backend baseline in force.
    BlockAll,
}

/// Complete typed policy accepted by launch validation.
///
/// Protected paths are explicit terminal denies. They remain separate from grants because the
/// current macOS backend can enforce a narrow deny inside a broader allowed subtree. Future
/// backends must demonstrate equivalent semantics rather than silently dropping them.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicySpec {
    /// Positive filesystem capabilities.
    pub files: Vec<FileGrant>,
    /// Subtrees from which both reads and writes are denied.
    pub protected_paths: Vec<AbsolutePath>,
    /// Exact paths that remain readable but cannot be mutated, replaced, or removed.
    pub protected_write_paths: Vec<AbsolutePath>,
    /// Additive in manifest schema v1: an omitted list grants no socket
    /// authority, so older manifests remain fail-closed without a version bump.
    #[serde(default)]
    pub unix_sockets: Vec<UnixSocketGrant>,
    /// Network access for the sandboxed process tree.
    pub network: NetworkPolicy,
}
