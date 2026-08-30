//! Typed, platform-neutral vocabulary for kernel-enforced launch policy.
//!
//! This module describes intent only. It does not discover paths or contain Seatbelt source;
//! platform backends are responsible for lowering a validated policy into native rules.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    num::NonZeroU16,
};

use serde::{Deserialize, Serialize};

use crate::AbsolutePath;

/// Filesystem operations granted for a path.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    /// Permit reads but no mutations.
    Read,
    /// Permit reads and mutations.
    ReadWrite,
}

/// Whether a filesystem rule addresses one node or a complete hierarchy.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathScope {
    /// Match only the named filesystem node.
    Exact,
    /// Match the named directory and everything beneath it.
    Subtree,
}

/// One filesystem capability in the resolved launch policy.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct FileGrant {
    /// Absolute, CLI-resolved path supplied to the enforcement backend.
    pub path: AbsolutePath,
    /// Operations allowed at the path.
    pub access: AccessMode,
    /// Exact-node or recursive matching semantics.
    pub scope: PathScope,
}

/// Authority to map executable code from one exact path or subtree.
///
/// This remains independent from [`FileGrant`]: reading a file never silently
/// makes it executable.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ExecutableGrant {
    /// Absolute path accepted by the enforcement backend.
    pub path: AbsolutePath,
    /// Exact-node or recursive matching semantics.
    pub scope: PathScope,
}

/// One readable filesystem path whose contents cannot be mutated.
///
/// Write protection is separate from [`FileGrant`] because it is a terminal
/// restriction: it must override any broader read/write grant that overlaps
/// the same path.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct WriteProtection {
    /// Absolute path protected from mutation.
    pub path: AbsolutePath,
    /// Exact-node or recursive protection semantics.
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

/// A validated nonzero TCP port.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TcpPort(NonZeroU16);

impl TcpPort {
    /// Constructs a port, rejecting zero because it means an ephemeral bind
    /// request rather than one exact remote endpoint.
    #[must_use]
    pub fn new(port: u16) -> Option<Self> {
        NonZeroU16::new(port).map(Self)
    }

    /// Returns the validated native port number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl fmt::Display for TcpPort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Operation authorized for an IPv4 TCP endpoint on the local Mac.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalHostTcpOperation {
    /// Connect to one port on an IPv4 address belonging to the local Mac,
    /// without authorizing bind.
    Connect,
}

/// Authority for one operation on one IPv4 TCP port on the local Mac.
///
/// Seatbelt's `localhost` remote filter covers the selected port on IPv4
/// addresses belonging to the Mac, including loopback and other local
/// interfaces. The address is intentionally not caller-controlled.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct LocalHostTcpGrant {
    /// Exact nonzero remote port.
    pub port: TcpPort,
    /// Operation authorized at the endpoint.
    pub operation: LocalHostTcpOperation,
}

/// Network policy for the complete sandboxed process tree.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// Permit network operations for agent compatibility.
    AllowAll,
    /// Emit no network allow rule, leaving the deny-first backend baseline in force.
    BlockAll,
}

/// Whether filesystem metadata may be queried independently of content access.
///
/// The macOS CLI requests this explicitly for system path aliases. The
/// supported Rust facade does not enable it implicitly.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileMetadataPolicy {
    /// Do not add global metadata lookup authority.
    #[default]
    Deny,
    /// Permit metadata lookup without granting file-content reads or writes.
    Allow,
}

/// Product-owned foreground compatibility behavior outside subprocess policy.
///
/// This is an implementation handoff. The supported Rust facade always uses
/// [`RuntimeCompatibility::Minimal`].
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCompatibility {
    /// Add no foreground command compatibility rules.
    #[default]
    Minimal,
    /// Permit the CLI's foreground terminal behavior.
    ForegroundCli,
}

/// Complete typed policy accepted by launch validation.
///
/// Protected paths are explicit terminal denies. They remain separate from grants because the
/// current macOS backend can enforce a narrow deny inside a broader allowed subtree. Future
/// backends must demonstrate equivalent semantics rather than silently dropping them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicySpec {
    /// Positive filesystem capabilities.
    pub files: Vec<FileGrant>,
    /// Executable mappings, independent from ordinary file reads.
    #[serde(default)]
    pub executables: Vec<ExecutableGrant>,
    /// Subtrees from which both reads and writes are denied.
    pub protected_paths: Vec<AbsolutePath>,
    /// Readable paths that cannot be mutated, replaced, or removed.
    pub write_protections: Vec<WriteProtection>,
    /// Additive in manifest schema v2: an omitted list grants no socket
    /// authority, so decoding a document without this field remains fail-closed.
    #[serde(default)]
    pub unix_sockets: Vec<UnixSocketGrant>,
    /// Additive in manifest schema v2: omission grants no local-host endpoint
    /// authority, preserving fail-closed decoding for existing manifests.
    #[serde(default)]
    pub local_host_tcp: Vec<LocalHostTcpGrant>,
    /// Filesystem metadata behavior, separate from content grants.
    #[serde(default)]
    pub file_metadata: FileMetadataPolicy,
    /// Whether the policy permits ordinary descendant process startup.
    #[serde(default)]
    pub allow_subprocesses: bool,
    /// Explicit product runtime behavior outside modeled path and network policy.
    #[serde(default)]
    pub runtime_compatibility: RuntimeCompatibility,
    /// Network access for the sandboxed process tree.
    pub network: NetworkPolicy,
}

impl Default for PolicySpec {
    fn default() -> Self {
        Self {
            files: Vec::new(),
            executables: Vec::new(),
            protected_paths: Vec::new(),
            write_protections: Vec::new(),
            unix_sockets: Vec::new(),
            local_host_tcp: Vec::new(),
            file_metadata: FileMetadataPolicy::Deny,
            allow_subprocesses: false,
            runtime_compatibility: RuntimeCompatibility::Minimal,
            network: NetworkPolicy::BlockAll,
        }
    }
}

impl PolicySpec {
    /// Deterministically removes redundant capabilities without broadening them.
    ///
    /// Exact and subtree rules remain distinct. For an identical path and scope,
    /// read/write subsumes read. Recursive write protection subsumes exact write
    /// protection at the same path. No other overlapping paths are merged.
    pub fn normalize(&mut self) {
        let mut files = BTreeMap::new();
        for grant in self.files.drain(..) {
            files
                .entry((grant.path, grant.scope))
                .and_modify(|access| {
                    if grant.access == AccessMode::ReadWrite {
                        *access = AccessMode::ReadWrite;
                    }
                })
                .or_insert(grant.access);
        }
        self.files = files
            .into_iter()
            .map(|((path, scope), access)| FileGrant {
                path,
                access,
                scope,
            })
            .collect();

        self.executables.sort();
        self.executables.dedup();

        self.protected_paths.sort();
        self.protected_paths.dedup();

        let mut write_protections = BTreeMap::new();
        for protection in self.write_protections.drain(..) {
            write_protections
                .entry(protection.path)
                .and_modify(|scope| {
                    if protection.scope == PathScope::Subtree {
                        *scope = PathScope::Subtree;
                    }
                })
                .or_insert(protection.scope);
        }
        self.write_protections = write_protections
            .into_iter()
            .map(|(path, scope)| WriteProtection { path, scope })
            .collect();

        self.unix_sockets.sort();
        self.unix_sockets.dedup();
        self.local_host_tcp.sort();
        self.local_host_tcp.dedup();
    }

    /// Pins every writable ancestor of a protected resource.
    ///
    /// A terminal deny on `/workspace/config/hooks.json` does not by itself
    /// prevent an actor with recursive write access to `/workspace` from
    /// renaming `/workspace/config`. Moving that ancestor would relocate the
    /// protected leaf outside the denied pathname. This deterministic closure
    /// adds exact write protections for each intermediate ancestor, stopping
    /// at the enclosing read/write grant because renaming that grant requires
    /// authority over its parent.
    ///
    /// Both confidential [`PolicySpec::protected_paths`] and readable
    /// [`PolicySpec::write_protections`] participate. The method performs no
    /// filesystem access and intentionally leaves duplicate caller input for
    /// launch validation to reject.
    pub fn close_write_protection_ancestors(&mut self) {
        let writable_roots = self
            .files
            .iter()
            .filter(|grant| {
                grant.access == AccessMode::ReadWrite && grant.scope == PathScope::Subtree
            })
            .map(|grant| grant.path.clone())
            .collect::<Vec<_>>();
        let protected_resources = self
            .protected_paths
            .iter()
            .cloned()
            .chain(
                self.write_protections
                    .iter()
                    .map(|protection| protection.path.clone()),
            )
            .collect::<Vec<_>>();
        let mut additions = BTreeSet::new();

        for resource in protected_resources {
            for writable_root in &writable_roots {
                if resource == *writable_root
                    || !resource.as_path().starts_with(writable_root.as_path())
                {
                    continue;
                }

                let mut ancestor = resource.parent();
                while let Some(path) = ancestor {
                    if path == *writable_root {
                        break;
                    }
                    if !self.write_denied_at(&path) {
                        additions.insert(path.clone());
                    }
                    ancestor = path.parent();
                }
            }
        }

        self.write_protections
            .extend(additions.into_iter().map(|path| WriteProtection {
                path,
                scope: PathScope::Exact,
            }));
    }

    /// Returns the first unpinned writable ancestor, if any.
    ///
    /// Launch validation uses this independently of closure so a malformed or
    /// hand-crafted bootstrap manifest cannot bypass the parent-side assembly
    /// step.
    pub(crate) fn unprotected_writable_ancestor(&self) -> Option<(&AbsolutePath, AbsolutePath)> {
        let protected_resources = self.protected_paths.iter().chain(
            self.write_protections
                .iter()
                .map(|protection| &protection.path),
        );

        for resource in protected_resources {
            for grant in self.files.iter().filter(|grant| {
                grant.access == AccessMode::ReadWrite && grant.scope == PathScope::Subtree
            }) {
                if resource == &grant.path || !resource.as_path().starts_with(grant.path.as_path())
                {
                    continue;
                }

                let mut ancestor = resource.parent();
                while let Some(path) = ancestor {
                    if path == grant.path {
                        break;
                    }
                    if !self.write_denied_at(&path) {
                        return Some((resource, path));
                    }
                    ancestor = path.parent();
                }
            }
        }
        None
    }

    fn write_denied_at(&self, path: &AbsolutePath) -> bool {
        self.protected_paths
            .iter()
            .any(|protected| path.as_path().starts_with(protected.as_path()))
            || self.write_protections.iter().any(|protection| {
                protection.path == *path
                    || (protection.scope == PathScope::Subtree
                        && path.as_path().starts_with(protection.path.as_path()))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> Result<AbsolutePath, crate::PathValidationError> {
        AbsolutePath::new(value)
    }

    #[test]
    fn normalization_removes_only_semantically_redundant_rules()
    -> Result<(), crate::PathValidationError> {
        let root = path("/workspace")?;
        let settings = path("/workspace/settings.json")?;
        let mut policy = PolicySpec {
            files: vec![
                FileGrant {
                    path: root.clone(),
                    access: AccessMode::Read,
                    scope: PathScope::Subtree,
                },
                FileGrant {
                    path: root.clone(),
                    access: AccessMode::ReadWrite,
                    scope: PathScope::Subtree,
                },
                FileGrant {
                    path: root.clone(),
                    access: AccessMode::Read,
                    scope: PathScope::Exact,
                },
            ],
            executables: vec![
                ExecutableGrant {
                    path: root.clone(),
                    scope: PathScope::Subtree,
                },
                ExecutableGrant {
                    path: root.clone(),
                    scope: PathScope::Subtree,
                },
            ],
            protected_paths: vec![settings.clone(), settings.clone()],
            write_protections: vec![
                WriteProtection {
                    path: settings.clone(),
                    scope: PathScope::Exact,
                },
                WriteProtection {
                    path: settings.clone(),
                    scope: PathScope::Subtree,
                },
            ],
            ..PolicySpec::default()
        };

        policy.normalize();

        assert_eq!(
            policy.files,
            [
                FileGrant {
                    path: root.clone(),
                    access: AccessMode::Read,
                    scope: PathScope::Exact,
                },
                FileGrant {
                    path: root.clone(),
                    access: AccessMode::ReadWrite,
                    scope: PathScope::Subtree,
                },
            ]
        );
        assert_eq!(policy.protected_paths, std::slice::from_ref(&settings));
        assert_eq!(
            policy.executables,
            [ExecutableGrant {
                path: root.clone(),
                scope: PathScope::Subtree,
            }]
        );
        assert_eq!(
            policy.write_protections,
            [WriteProtection {
                path: settings,
                scope: PathScope::Subtree,
            }]
        );
        Ok(())
    }

    #[test]
    fn closes_every_ancestor_below_a_writable_subtree() -> Result<(), crate::PathValidationError> {
        let mut policy = PolicySpec {
            files: vec![FileGrant {
                path: path("/workspace")?,
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }],
            write_protections: vec![WriteProtection {
                path: path("/workspace/config/hooks/managed.json")?,
                scope: PathScope::Exact,
            }],
            ..PolicySpec::default()
        };

        policy.close_write_protection_ancestors();

        let protected = policy
            .write_protections
            .iter()
            .map(|protection| protection.path.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            protected,
            BTreeSet::from([
                "/workspace/config",
                "/workspace/config/hooks",
                "/workspace/config/hooks/managed.json",
            ])
        );
        assert!(!protected.contains("/workspace"));
        assert!(policy.unprotected_writable_ancestor().is_none());
        Ok(())
    }

    #[test]
    fn closes_ancestors_for_confidential_protected_paths() -> Result<(), crate::PathValidationError>
    {
        let mut policy = PolicySpec {
            files: vec![FileGrant {
                path: path("/users/example")?,
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }],
            protected_paths: vec![path("/users/example/library/keys")?],
            ..PolicySpec::default()
        };

        policy.close_write_protection_ancestors();

        assert!(policy.write_protections.iter().any(|protection| {
            protection.path.as_str() == "/users/example/library"
                && protection.scope == PathScope::Exact
        }));
        assert!(policy.unprotected_writable_ancestor().is_none());
        Ok(())
    }

    #[test]
    fn leaves_adjacent_mutable_paths_unprotected() -> Result<(), crate::PathValidationError> {
        let mut policy = PolicySpec {
            files: vec![FileGrant {
                path: path("/workspace")?,
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }],
            write_protections: vec![WriteProtection {
                path: path("/workspace/config/hooks.json")?,
                scope: PathScope::Exact,
            }],
            ..PolicySpec::default()
        };

        policy.close_write_protection_ancestors();

        assert!(!policy.write_denied_at(&path("/workspace/output")?));
        Ok(())
    }
}
