use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    os::{
        fd::AsFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::PathBuf,
};

use sandy_core::{AbsolutePath, AccessMode, PathScope, RuntimeCompatibility};

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
    device: u64,
    inode: u64,
    link_count: u64,
}

pub(crate) struct MountRequirement {
    pub(crate) path: AbsolutePath,
    pub(crate) recursive: bool,
    pub(crate) writable: bool,
    pub(crate) executable: bool,
}

pub(crate) struct ProtectionRequirement {
    pub(crate) path: AbsolutePath,
    pub(crate) recursive: bool,
    pub(crate) executable: bool,
}

pub(crate) struct MountPreparation {
    pub(crate) pinned: BTreeMap<AbsolutePath, PinnedPath>,
    pub(crate) mounts: Vec<MountRequirement>,
    pub(crate) protections: Vec<ProtectionRequirement>,
    pub(crate) aliases: Vec<RuntimeAlias>,
    pub(crate) working_directory: AbsolutePath,
}

pub(crate) struct RuntimeAlias {
    pub(crate) path: AbsolutePath,
    pub(crate) target: PathBuf,
}

/// Fully prepared Linux sandbox whose remaining operations are irreversible.
///
/// This value owns all pinned path descriptors, the already-created Landlock
/// ruleset, compiled seccomp programs, and namespace inputs. Dropping it before
/// [`crate::apply`] leaves the process unrestricted.
#[must_use = "the sandbox is not enforced until this value is passed to sandy_linux::apply"]
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
    prepare_with_primary_executable(plan, working_directory, None)
}

/// Prepares the Linux sandbox for a foreground CLI launch.
///
/// `primary_executable` is already part of the caller's explicit executable
/// policy. Sandy uses it only to recreate the bounded `/proc/self/exe`
/// spelling needed by programs that identify or re-execute their own image;
/// procfs itself remains unmounted.
#[doc(hidden)]
pub fn prepare_foreground_launch(
    plan: LinuxPolicyPlan,
    working_directory: &AbsolutePath,
    primary_executable: &AbsolutePath,
) -> Result<PreparedLinuxSandbox, LinuxError> {
    prepare_with_primary_executable(plan, working_directory, Some(primary_executable))
}

fn prepare_with_primary_executable(
    plan: LinuxPolicyPlan,
    working_directory: &AbsolutePath,
    primary_executable: Option<&AbsolutePath>,
) -> Result<PreparedLinuxSandbox, LinuxError> {
    let block_network = plan.blocks_network();
    let namespace = namespace::prepare(block_network)?;
    let mount = prepare_mounts(&plan, working_directory, primary_executable)?;
    let landlock = landlock::prepare(plan.policy.spec(), &mount.pinned)?;
    let seccomp = seccomp::compile(plan.allows_subprocesses(), block_network)?;
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
    primary_executable: Option<&AbsolutePath>,
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
                executable: false,
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
                executable: false,
            });
        entry.recursive |= grant.scope == PathScope::Subtree;
        entry.executable = true;
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
        // Landlock can constrain file-like write operations on one exact
        // object. Directory mutation rights apply beneath directories, so an
        // exact read-write directory would silently imply subtree authority.
        // A typed exact device grant does not carry that ambiguity.
        let unsupported_exact_read_write = grant.scope == PathScope::Exact
            && grant.access == AccessMode::ReadWrite
            && pinned_path.kind != PinnedKind::Device;
        if exact_directory || subtree_non_directory || unsupported_exact_read_write {
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
    let mut mounts = requested.into_values().collect::<Vec<_>>();
    mounts.sort_by_key(|entry| entry.path.as_path().components().count());
    let mut effective = Vec::<MountRequirement>::new();
    for mount in mounts {
        let covered = effective.iter().any(|parent| {
            parent.recursive
                && mount.path.as_path().starts_with(parent.path.as_path())
                && (!mount.writable || parent.writable)
                && (!mount.executable || parent.executable)
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
            let pinned_path = pinned
                .get(&protection.path)
                .ok_or_else(|| preparation("write-protection pinning"))?;
            let kind = pinned_path.kind;
            if kind == PinnedKind::Directory && protection.scope == PathScope::Exact {
                return Err(unsupported("exact directory write protection"));
            }
            if kind == PinnedKind::Regular && pinned_path.link_count != 1 {
                return Err(unsupported("write-protected hard-link alias"));
            }
            Ok(ProtectionRequirement {
                path: protection.path.clone(),
                recursive: protection.scope == PathScope::Subtree,
                executable: executable(&protection.path, &spec.executables),
            })
        })
        .collect::<Result<Vec<_>, LinuxError>>()?;

    for requirement in effective
        .iter()
        .filter(|requirement| requirement.executable)
    {
        reject_host_noexec(&requirement.path, &pinned)?;
    }
    for requirement in protections
        .iter()
        .filter(|requirement| requirement.executable)
    {
        reject_host_noexec(&requirement.path, &pinned)?;
    }

    if !visible(working_directory, effective.iter()) {
        return Err(unsupported("working directory visibility"));
    }
    let working_directory = working_directory.clone();
    let aliases = prepare_runtime_aliases(
        spec.runtime_compatibility,
        &effective,
        &spec.protected_paths,
        primary_executable,
    )?;

    Ok(MountPreparation {
        pinned,
        mounts: effective,
        protections,
        aliases,
        working_directory,
    })
}

fn reject_host_noexec(
    path: &AbsolutePath,
    pinned: &BTreeMap<AbsolutePath, PinnedPath>,
) -> Result<(), LinuxError> {
    let source = pinned
        .get(path)
        .ok_or_else(|| preparation("executable mount lookup"))?;
    if crate::ffi::mount_is_noexec(source.file.as_fd())
        .map_err(|_| preparation("host mount inspection"))?
    {
        return Err(unsupported("host noexec restriction"));
    }
    Ok(())
}

fn executable(path: &AbsolutePath, grants: &[sandy_core::ExecutableGrant]) -> bool {
    grants.iter().any(|grant| {
        path == &grant.path
            || (grant.scope == PathScope::Subtree
                && path.as_path().starts_with(grant.path.as_path()))
    })
}

fn prepare_runtime_aliases(
    compatibility: RuntimeCompatibility,
    mounts: &[MountRequirement],
    protected_paths: &[AbsolutePath],
    primary_executable: Option<&AbsolutePath>,
) -> Result<Vec<RuntimeAlias>, LinuxError> {
    if compatibility != RuntimeCompatibility::ForegroundCli {
        return Ok(Vec::new());
    }

    let mut aliases = Vec::new();
    for requested in [
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/etc/resolv.conf",
        "/etc/localtime",
        "/etc/ssl/cert.pem",
    ] {
        let metadata = match std::fs::symlink_metadata(requested) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(preparation("runtime alias inspection")),
        };
        if !metadata.file_type().is_symlink() {
            continue;
        }
        let canonical = std::fs::canonicalize(requested)
            .map_err(|_| preparation("runtime alias resolution"))?;
        let canonical = AbsolutePath::new(
            canonical
                .to_str()
                .ok_or_else(|| preparation("runtime alias representation"))?
                .to_owned(),
        )
        .map_err(|_| preparation("runtime alias representation"))?;
        let path = AbsolutePath::new(requested.to_owned())
            .map_err(|_| preparation("runtime alias representation"))?;
        if !should_materialize_runtime_alias(&path, &canonical, mounts, protected_paths) {
            continue;
        }
        let target =
            std::fs::read_link(requested).map_err(|_| preparation("runtime alias resolution"))?;
        aliases.push(RuntimeAlias { path, target });
    }
    if let Some(alias) =
        prepare_primary_executable_alias(primary_executable, mounts, protected_paths)?
    {
        aliases.push(alias);
    }
    Ok(aliases)
}

fn prepare_primary_executable_alias(
    primary_executable: Option<&AbsolutePath>,
    mounts: &[MountRequirement],
    protected_paths: &[AbsolutePath],
) -> Result<Option<RuntimeAlias>, LinuxError> {
    let Some(primary_executable) = primary_executable else {
        return Ok(None);
    };
    let path = AbsolutePath::new("/proc/self/exe".to_owned())
        .map_err(|_| preparation("primary executable alias"))?;
    if denied(&path, protected_paths)
        || visible(&path, mounts.iter())
        || !visible(primary_executable, mounts.iter())
        || !mounts.iter().any(|mount| {
            mount.executable
                && (primary_executable == &mount.path
                    || (mount.recursive
                        && primary_executable
                            .as_path()
                            .starts_with(mount.path.as_path())))
        })
    {
        return Err(unsupported("primary executable alias"));
    }
    Ok(Some(RuntimeAlias {
        path,
        target: primary_executable.as_path().to_path_buf(),
    }))
}

fn should_materialize_runtime_alias(
    path: &AbsolutePath,
    canonical: &AbsolutePath,
    mounts: &[MountRequirement],
    protected_paths: &[AbsolutePath],
) -> bool {
    !denied(path, protected_paths)
        && !visible(path, mounts.iter())
        && visible(canonical, mounts.iter())
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
    let owned = crate::ffi::open_path_at(root.as_fd(), &relative)
        .map_err(|_| preparation("path pinning"))?;
    let file = crate::ffi::file_from_owned(owned);
    let metadata = file
        .metadata()
        .map_err(|_| preparation("path inspection"))?;
    let kind = classify(&metadata);
    Ok(PinnedPath {
        file,
        kind,
        device: metadata.dev(),
        inode: metadata.ino(),
        link_count: metadata.nlink(),
    })
}

pub(crate) fn repin_after_namespace(preparation: &mut MountPreparation) -> Result<(), LinuxError> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open("/")
        .map_err(|_| enforcement("namespace root pinning"))?;

    for (path, pinned) in &mut preparation.pinned {
        let relative = path.as_str().strip_prefix('/').unwrap_or(path.as_str());
        let relative = if relative.is_empty() { "." } else { relative };
        let relative =
            crate::ffi::c_string(relative).map_err(|_| enforcement("mount source repinning"))?;
        let owned = crate::ffi::open_path_at(root.as_fd(), &relative)
            .map_err(|_| enforcement("mount source repinning"))?;
        let file = crate::ffi::file_from_owned(owned);
        let metadata = file
            .metadata()
            .map_err(|_| enforcement("mount source verification"))?;
        if metadata.dev() != pinned.device
            || metadata.ino() != pinned.inode
            || classify(&metadata) != pinned.kind
            || metadata.nlink() != pinned.link_count
        {
            return Err(enforcement("mount source verification"));
        }
        pinned.file = file;
    }
    Ok(())
}

fn classify(metadata: &std::fs::Metadata) -> PinnedKind {
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        PinnedKind::Directory
    } else if file_type.is_file() {
        PinnedKind::Regular
    } else if file_type.is_socket() {
        PinnedKind::Socket
    } else if file_type.is_char_device() || file_type.is_block_device() {
        PinnedKind::Device
    } else {
        PinnedKind::Other
    }
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

fn enforcement(phase: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::EnforcementFailed, phase)
}

fn unsupported(phase: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::Unsupported, phase)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> Result<AbsolutePath, Box<dyn std::error::Error>> {
        Ok(AbsolutePath::new(value.to_owned())?)
    }

    #[test]
    fn protected_runtime_alias_is_not_materialized() -> Result<(), Box<dyn std::error::Error>> {
        let alias = path("/bin")?;
        let canonical = path("/usr/bin")?;
        let mounts = [MountRequirement {
            path: canonical.clone(),
            recursive: true,
            writable: false,
            executable: true,
        }];

        assert!(should_materialize_runtime_alias(
            &alias,
            &canonical,
            &mounts,
            &[],
        ));
        assert!(!should_materialize_runtime_alias(
            &alias,
            &canonical,
            &mounts,
            std::slice::from_ref(&alias),
        ));
        Ok(())
    }

    #[test]
    fn primary_executable_alias_requires_existing_execute_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let executable = path("/opt/agent/bin/codex")?;
        let executable_mount = MountRequirement {
            path: path("/opt/agent/bin")?,
            recursive: true,
            writable: false,
            executable: true,
        };
        let data_mount = MountRequirement {
            path: path("/opt/agent/bin")?,
            recursive: true,
            writable: false,
            executable: false,
        };

        let alias = prepare_primary_executable_alias(
            Some(&executable),
            std::slice::from_ref(&executable_mount),
            &[],
        )?
        .ok_or("missing primary executable alias")?;
        assert_eq!(alias.path.as_str(), "/proc/self/exe");
        assert_eq!(alias.target, executable.as_path());
        assert!(prepare_primary_executable_alias(Some(&executable), &[data_mount], &[]).is_err());
        assert!(
            prepare_primary_executable_alias(
                Some(&executable),
                &[executable_mount],
                &[path("/proc")?],
            )
            .is_err()
        );
        Ok(())
    }
}
