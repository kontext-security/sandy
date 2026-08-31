use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    os::unix::fs::{FileTypeExt, OpenOptionsExt},
};

use sandy_core::{AbsolutePath, AccessMode, PathScope};

use crate::{LinuxError, LinuxErrorKind, LinuxPolicyPlan, landlock, namespace, seccomp};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum PinnedKind {
    Directory,
    Regular,
    Socket,
    Device,
    Other,
}

pub(crate) struct PinnedPath {
    pub(crate) file: File,
    pub(crate) kind: PinnedKind,
}

pub(crate) struct MountRequirement {
    pub(crate) path: AbsolutePath,
    pub(crate) recursive: bool,
    pub(crate) writable: bool,
}

pub(crate) struct ProtectionRequirement {
    pub(crate) path: AbsolutePath,
    pub(crate) recursive: bool,
    pub(crate) read_only: bool,
}

pub(crate) struct MountPreparation {
    pub(crate) pinned: BTreeMap<AbsolutePath, PinnedPath>,
    pub(crate) mounts: Vec<MountRequirement>,
    pub(crate) protections: Vec<ProtectionRequirement>,
    pub(crate) working_directory: Option<AbsolutePath>,
}

/// Fully prepared Linux sandbox whose remaining operations are irreversible.
///
/// This value owns all pinned path descriptors, the already-created Landlock
/// ruleset, compiled seccomp programs, and namespace inputs. Dropping it before
/// [`crate::apply`] leaves the process unrestricted.
#[must_use]
pub struct PreparedLinuxSandbox {
    pub(crate) mount: MountPreparation,
    pub(crate) landlock: landlock::PreparedLandlock,
    pub(crate) seccomp: seccomp::SeccompPrograms,
    pub(crate) namespace: namespace::NamespacePreparation,
    pub(crate) block_network: bool,
}

/// Pins every ambient resource and prepares native enforcement without
/// restricting the current process.
pub fn prepare(
    plan: LinuxPolicyPlan,
    working_directory: &AbsolutePath,
) -> Result<PreparedLinuxSandbox, LinuxError> {
    let namespace = namespace::prepare()?;
    let mount = prepare_mounts(&plan, working_directory)?;
    let landlock = landlock::prepare(plan.policy.spec(), &mount.pinned)?;
    let block_network = plan.blocks_network();
    let seccomp = seccomp::compile(
        plan.allows_subprocesses(),
        block_network,
        !plan.policy.spec().unix_sockets.is_empty(),
    )?;
    Ok(PreparedLinuxSandbox {
        mount,
        landlock,
        seccomp,
        namespace,
        block_network,
    })
}

fn prepare_mounts(
    plan: &LinuxPolicyPlan,
    working_directory: &AbsolutePath,
) -> Result<MountPreparation, LinuxError> {
    let spec = plan.policy.spec();
    let mut requested = BTreeMap::<AbsolutePath, MountRequirement>::new();

    for grant in &spec.files {
        if denied(&grant.path, &spec.protected_paths) {
            continue;
        }
        let entry = requested
            .entry(grant.path.clone())
            .or_insert_with(|| MountRequirement {
                path: grant.path.clone(),
                recursive: false,
                writable: false,
            });
        entry.recursive |= grant.scope == PathScope::Subtree;
        entry.writable |= grant.access == AccessMode::ReadWrite;
    }
    for grant in &spec.executables {
        if denied(&grant.path, &spec.protected_paths) {
            continue;
        }
        let entry = requested
            .entry(grant.path.clone())
            .or_insert_with(|| MountRequirement {
                path: grant.path.clone(),
                recursive: false,
                writable: false,
            });
        entry.recursive |= grant.scope == PathScope::Subtree;
    }
    for grant in &spec.unix_sockets {
        if !denied(&grant.path, &spec.protected_paths) {
            requested
                .entry(grant.path.clone())
                .or_insert_with(|| MountRequirement {
                    path: grant.path.clone(),
                    recursive: false,
                    writable: false,
                });
        }
    }

    let mut pinned = BTreeMap::new();
    for path in requested.keys().chain(
        spec.write_protections
            .iter()
            .filter(|protection| visible(&protection.path, requested.values()))
            .map(|protection| &protection.path),
    ) {
        if !pinned.contains_key(path) {
            pinned.insert(path.clone(), pin(path)?);
        }
    }

    for grant in &spec.files {
        if denied(&grant.path, &spec.protected_paths) {
            continue;
        }
        let pinned_path = pinned
            .get(&grant.path)
            .ok_or_else(|| preparation("path pinning"))?;
        let exact_directory =
            grant.scope == PathScope::Exact && pinned_path.kind == PinnedKind::Directory;
        let subtree_non_directory =
            grant.scope == PathScope::Subtree && pinned_path.kind != PinnedKind::Directory;
        let exact_read_write =
            grant.scope == PathScope::Exact && grant.access == AccessMode::ReadWrite;
        if exact_directory || subtree_non_directory || exact_read_write {
            return Err(unsupported("filesystem grant shape"));
        }
    }
    for grant in &spec.executables {
        if denied(&grant.path, &spec.protected_paths) {
            continue;
        }
        let kind = pinned
            .get(&grant.path)
            .ok_or_else(|| preparation("executable pinning"))?
            .kind;
        if (grant.scope == PathScope::Exact && kind == PinnedKind::Directory)
            || (grant.scope == PathScope::Subtree && kind != PinnedKind::Directory)
        {
            return Err(unsupported("executable grant shape"));
        }
    }
    for grant in &spec.unix_sockets {
        if denied(&grant.path, &spec.protected_paths) {
            continue;
        }
        if pinned
            .get(&grant.path)
            .ok_or_else(|| preparation("socket pinning"))?
            .kind
            != PinnedKind::Socket
        {
            return Err(unsupported("pathname socket type"));
        }
    }

    let mut mounts = requested.into_values().collect::<Vec<_>>();
    mounts.sort_by_key(|entry| entry.path.as_path().components().count());
    let mut effective = Vec::<MountRequirement>::new();
    for mount in mounts {
        let covered = effective.iter().any(|parent| {
            parent.recursive
                && mount.path.as_path().starts_with(parent.path.as_path())
                && (!mount.writable || parent.writable)
        });
        if !covered {
            effective.push(mount);
        }
    }

    let protections = spec
        .write_protections
        .iter()
        .filter(|protection| visible(&protection.path, effective.iter()))
        .map(|protection| {
            let kind = pinned
                .get(&protection.path)
                .ok_or_else(|| preparation("write-protection pinning"))?
                .kind;
            if kind == PinnedKind::Directory && protection.scope == PathScope::Exact {
                return Err(unsupported("exact directory write protection"));
            }
            Ok(ProtectionRequirement {
                path: protection.path.clone(),
                recursive: protection.scope == PathScope::Subtree,
                read_only: true,
            })
        })
        .collect::<Result<Vec<_>, LinuxError>>()?;

    let working_directory =
        visible(working_directory, effective.iter()).then(|| working_directory.clone());

    Ok(MountPreparation {
        pinned,
        mounts: effective,
        protections,
        working_directory,
    })
}

fn pin(path: &AbsolutePath) -> Result<PinnedPath, LinuxError> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open("/")
        .map_err(|_| preparation("root pinning"))?;
    let relative = path.as_str().strip_prefix('/').unwrap_or(path.as_str());
    let relative = if relative.is_empty() { "." } else { relative };
    let relative = crate::ffi::c_string(relative).map_err(|_| preparation("path pinning"))?;
    let owned = crate::ffi::open_path_at(std::os::fd::AsRawFd::as_raw_fd(&root), &relative)
        .map_err(|_| preparation("path pinning"))?;
    let file = crate::ffi::file_from_owned(owned);
    let file_type = file
        .metadata()
        .map_err(|_| preparation("path inspection"))?
        .file_type();
    let kind = if file_type.is_dir() {
        PinnedKind::Directory
    } else if file_type.is_file() {
        PinnedKind::Regular
    } else if file_type.is_socket() {
        PinnedKind::Socket
    } else if file_type.is_char_device() || file_type.is_block_device() {
        PinnedKind::Device
    } else {
        PinnedKind::Other
    };
    Ok(PinnedPath { file, kind })
}

pub(crate) fn denied(path: &AbsolutePath, protected_paths: &[AbsolutePath]) -> bool {
    protected_paths
        .iter()
        .any(|protected| path.as_path().starts_with(protected.as_path()))
}

fn visible<'a>(
    path: &AbsolutePath,
    mounts: impl IntoIterator<Item = &'a MountRequirement>,
) -> bool {
    mounts.into_iter().any(|mount| {
        path == &mount.path || (mount.recursive && path.as_path().starts_with(mount.path.as_path()))
    })
}

fn preparation(phase: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::PreparationFailed, phase)
}

fn unsupported(phase: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::Unsupported, phase)
}
