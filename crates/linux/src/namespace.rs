use std::{fs, io};

use crate::{LinuxError, LinuxErrorKind, ffi};

pub(crate) struct NamespacePreparation {
    effective_uid: u32,
    effective_gid: u32,
    pub(crate) last_capability: u32,
}

pub(crate) fn prepare() -> Result<NamespacePreparation, LinuxError> {
    ensure_single_threaded()?;
    let (effective_uid, effective_gid) = ffi::effective_ids();
    let raw_last_capability = fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(|_| preparation("capability discovery"))?;
    if raw_last_capability.len() > 16 {
        return Err(preparation("capability discovery"));
    }
    let last_capability = raw_last_capability
        .trim()
        .parse::<u32>()
        .map_err(|_| preparation("capability discovery"))?;
    if last_capability >= 64 {
        return Err(LinuxError::new(
            LinuxErrorKind::Unsupported,
            "capability ABI",
        ));
    }

    Ok(NamespacePreparation {
        effective_uid,
        effective_gid,
        last_capability,
    })
}

pub(crate) fn enter(
    preparation: &NamespacePreparation,
    block_network: bool,
) -> Result<(), LinuxError> {
    ffi::unshare_namespaces(block_network).map_err(|_| enforcement("namespace creation"))?;

    match fs::write("/proc/self/setgroups", b"deny") {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(enforcement("group mapping")),
    }
    fs::write(
        "/proc/self/uid_map",
        format!("0 {} 1\n", preparation.effective_uid),
    )
    .map_err(|_| enforcement("user mapping"))?;
    fs::write(
        "/proc/self/gid_map",
        format!("0 {} 1\n", preparation.effective_gid),
    )
    .map_err(|_| enforcement("group mapping"))?;

    ffi::make_mounts_private().map_err(|_| enforcement("mount propagation"))
}

fn ensure_single_threaded() -> Result<(), LinuxError> {
    let mut entries = fs::read_dir("/proc/self/task")
        .map_err(|_| LinuxError::new(LinuxErrorKind::Unsupported, "thread inspection"))?;
    let first = entries
        .next()
        .transpose()
        .map_err(|_| preparation("thread inspection"))?;
    let second = entries
        .next()
        .transpose()
        .map_err(|_| preparation("thread inspection"))?;
    if first.is_none() || second.is_some() {
        Err(LinuxError::new(
            LinuxErrorKind::Unsupported,
            "single-threaded precondition",
        ))
    } else {
        Ok(())
    }
}

fn preparation(phase: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::PreparationFailed, phase)
}

fn enforcement(phase: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::EnforcementFailed, phase)
}
