use std::{collections::BTreeMap, convert::TryFrom};

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::{LinuxError, LinuxErrorKind};

pub(crate) struct SeccompPrograms {
    clone3: BpfProgram,
    topology: BpfProgram,
}

pub(crate) fn compile(
    allow_subprocesses: bool,
    block_network: bool,
    allow_pathname_unix: bool,
) -> Result<SeccompPrograms, LinuxError> {
    let architecture = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|_| unsupported("seccomp architecture"))?;

    let clone3 = compile_filter(
        BTreeMap::from([(libc::SYS_clone3, Vec::new())]),
        SeccompAction::Errno(libc::ENOSYS as u32),
        architecture,
    )?;

    let mut denied = BTreeMap::from([
        (libc::SYS_unshare, Vec::new()),
        (libc::SYS_setns, Vec::new()),
        (libc::SYS_mount, Vec::new()),
        (libc::SYS_umount2, Vec::new()),
        (libc::SYS_pivot_root, Vec::new()),
        (libc::SYS_chroot, Vec::new()),
        (libc::SYS_open_tree, Vec::new()),
        (libc::SYS_move_mount, Vec::new()),
        (libc::SYS_mount_setattr, Vec::new()),
        (libc::SYS_fsopen, Vec::new()),
        (libc::SYS_fsconfig, Vec::new()),
        (libc::SYS_fsmount, Vec::new()),
        (libc::SYS_fspick, Vec::new()),
    ]);

    let namespace_flags = [
        libc::CLONE_NEWCGROUP,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWNS,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWTIME,
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWUTS,
    ];
    let mut clone_rules = namespace_flags
        .into_iter()
        .map(|flag| masked_clone_rule(flag as u64, flag as u64))
        .collect::<Result<Vec<_>, _>>()?;
    if !allow_subprocesses {
        clone_rules.push(masked_clone_rule(libc::CLONE_THREAD as u64, 0)?);
        denied.insert(libc::SYS_fork, Vec::new());
        denied.insert(libc::SYS_vfork, Vec::new());
        denied.insert(libc::SYS_execve, Vec::new());
        denied.insert(libc::SYS_execveat, Vec::new());
    }
    denied.insert(libc::SYS_clone, clone_rules);

    if block_network {
        let socket_rules = if allow_pathname_unix {
            vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        0,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Ne,
                        libc::AF_UNIX as u64,
                    )
                    .map_err(|_| preparation("seccomp compilation"))?,
                ])
                .map_err(|_| preparation("seccomp compilation"))?,
            ]
        } else {
            Vec::new()
        };
        denied.insert(libc::SYS_socket, socket_rules);
    }

    let topology = compile_filter(
        denied,
        SeccompAction::Errno(libc::EPERM as u32),
        architecture,
    )?;
    Ok(SeccompPrograms { clone3, topology })
}

pub(crate) fn apply(programs: &SeccompPrograms) -> Result<(), LinuxError> {
    seccompiler::apply_filter(&programs.clone3)
        .and_then(|()| seccompiler::apply_filter(&programs.topology))
        .map_err(|_| LinuxError::new(LinuxErrorKind::EnforcementFailed, "seccomp application"))
}

fn compile_filter(
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    match_action: SeccompAction,
    architecture: TargetArch,
) -> Result<BpfProgram, LinuxError> {
    SeccompFilter::new(rules, SeccompAction::Allow, match_action, architecture)
        .and_then(BpfProgram::try_from)
        .map_err(|_| preparation("seccomp compilation"))
}

fn masked_clone_rule(mask: u64, value: u64) -> Result<SeccompRule, LinuxError> {
    let condition = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Qword,
        SeccompCmpOp::MaskedEq(mask),
        value,
    )
    .map_err(|_| preparation("seccomp compilation"))?;
    SeccompRule::new(vec![condition]).map_err(|_| preparation("seccomp compilation"))
}

fn preparation(phase: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::PreparationFailed, phase)
}

fn unsupported(phase: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::Unsupported, phase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_both_process_modes() {
        assert!(compile(false, true, false).is_ok());
        assert!(compile(true, false, true).is_ok());
    }
}
