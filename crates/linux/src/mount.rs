use std::{
    fs::{self, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

use sandy_core::AbsolutePath;

use crate::{
    LinuxError, LinuxErrorKind, ffi,
    prepare::{MountPreparation, PinnedKind},
};

const STAGING_ROOT: &str = "/tmp/.sandy-root";

pub(crate) fn construct_and_enter(preparation: &MountPreparation) -> Result<(), LinuxError> {
    let tmp = ffi::c_string("/tmp").map_err(|_| enforcement("root construction"))?;
    ffi::mount_tmpfs(&tmp).map_err(|_| enforcement("temporary root isolation"))?;
    fs::create_dir(STAGING_ROOT).map_err(|_| enforcement("root construction"))?;
    fs::set_permissions(STAGING_ROOT, fs::Permissions::from_mode(0o700))
        .map_err(|_| enforcement("root permissions"))?;
    let staging = ffi::c_string(STAGING_ROOT).map_err(|_| enforcement("root construction"))?;
    ffi::mount_tmpfs(&staging).map_err(|_| enforcement("private root mount"))?;
    fs::create_dir(format!("{STAGING_ROOT}/.old_root"))
        .map_err(|_| enforcement("root construction"))?;

    for requirement in &preparation.mounts {
        create_target(&requirement.path, preparation)?;
    }
    for protection in &preparation.protections {
        create_target(&protection.path, preparation)?;
    }

    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(STAGING_ROOT)
        .map_err(|_| enforcement("private root pinning"))?;

    for requirement in &preparation.mounts {
        let source = preparation
            .pinned
            .get(&requirement.path)
            .ok_or_else(|| enforcement("mount source lookup"))?;
        attach(
            &root,
            &requirement.path,
            &source.file,
            requirement.recursive,
            !requirement.writable,
            source.kind == PinnedKind::Device,
        )?;
    }
    for protection in &preparation.protections {
        let source = preparation
            .pinned
            .get(&protection.path)
            .ok_or_else(|| enforcement("write-protection lookup"))?;
        attach(
            &root,
            &protection.path,
            &source.file,
            protection.recursive,
            protection.read_only,
            source.kind == PinnedKind::Device,
        )?;
    }
    for alias in &preparation.aliases {
        let path = target_path(&alias.path);
        let parent = path
            .parent()
            .ok_or_else(|| enforcement("runtime alias creation"))?;
        fs::create_dir_all(parent).map_err(|_| enforcement("runtime alias creation"))?;
        std::os::unix::fs::symlink(&alias.target, &path)
            .map_err(|_| enforcement("runtime alias creation"))?;
    }

    std::env::set_current_dir(STAGING_ROOT).map_err(|_| enforcement("root entry"))?;
    ffi::pivot_root(c".", c".old_root").map_err(|_| enforcement("root entry"))?;
    std::env::set_current_dir("/").map_err(|_| enforcement("root entry"))?;
    ffi::detach_mount(c"/.old_root").map_err(|_| enforcement("old root detachment"))?;
    fs::remove_dir("/.old_root").map_err(|_| enforcement("old root cleanup"))?;

    std::env::set_current_dir(preparation.working_directory.as_path())
        .map_err(|_| enforcement("working directory restoration"))?;
    Ok(())
}

fn create_target(path: &AbsolutePath, preparation: &MountPreparation) -> Result<(), LinuxError> {
    let source = preparation
        .pinned
        .get(path)
        .ok_or_else(|| enforcement("mount target lookup"))?;
    let target = target_path(path);
    if source.kind == PinnedKind::Directory {
        fs::create_dir_all(&target).map_err(|_| enforcement("mount target creation"))?;
    } else {
        let parent = target
            .parent()
            .ok_or_else(|| enforcement("mount target creation"))?;
        fs::create_dir_all(parent).map_err(|_| enforcement("mount target creation"))?;
        if !target.exists() {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
                .map_err(|_| enforcement("mount target creation"))?;
        }
    }
    Ok(())
}

fn attach(
    root: &std::fs::File,
    path: &AbsolutePath,
    source: &std::fs::File,
    recursive: bool,
    read_only: bool,
    allow_device: bool,
) -> Result<(), LinuxError> {
    let relative = path.as_str().strip_prefix('/').unwrap_or(path.as_str());
    let relative = ffi::c_string(relative).map_err(|_| enforcement("mount target pinning"))?;
    let target = ffi::open_path_at(root.as_raw_fd(), &relative)
        .map_err(|_| enforcement("mount target pinning"))?;
    let detached = ffi::clone_mount(source.as_raw_fd(), recursive)
        .map_err(|_| enforcement("detached mount creation"))?;
    ffi::restrict_mount(detached.as_raw_fd(), recursive, read_only, allow_device)
        .map_err(|_| enforcement("detached mount restriction"))?;
    ffi::attach_mount(detached.as_raw_fd(), target.as_raw_fd())
        .map_err(|_| enforcement("mount attachment"))
}

fn target_path(path: &AbsolutePath) -> PathBuf {
    let relative = path.as_str().strip_prefix('/').unwrap_or(path.as_str());
    Path::new(STAGING_ROOT).join(relative)
}

fn enforcement(phase: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::EnforcementFailed, phase)
}
