use std::{collections::BTreeMap, fs::File};

use landlock::{
    ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope,
};
use sandy_core::{AccessMode, PathScope, PolicySpec};

use crate::{
    LinuxError, LinuxErrorKind,
    prepare::{PinnedKind, PinnedPath, denied},
};

pub(crate) struct PreparedLandlock {
    ruleset: RulesetCreated,
}

pub(crate) fn prepare(
    policy: &PolicySpec,
    pinned: &BTreeMap<sandy_core::AbsolutePath, PinnedPath>,
) -> Result<PreparedLandlock, LinuxError> {
    let builder = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V8))
        .and_then(|builder| builder.scope(Scope::Signal))
        .map_err(|_| unsupported("Landlock ABI or signal scope"))?;
    let mut ruleset = builder
        .create()
        .map_err(|_| unsupported("Landlock ruleset creation"))?;

    for grant in &policy.files {
        if denied(&grant.path, &policy.protected_paths) {
            continue;
        }
        let pinned_path = pinned
            .get(&grant.path)
            .ok_or_else(|| preparation("Landlock path lookup"))?;
        let mut rights = read_rights(pinned_path.kind);
        if grant.access == AccessMode::ReadWrite {
            rights |= write_rights(pinned_path.kind);
        }
        ruleset = add_rule(ruleset, &pinned_path.file, rights)?;
    }
    for grant in &policy.executables {
        if denied(&grant.path, &policy.protected_paths) {
            continue;
        }
        let file = &pinned
            .get(&grant.path)
            .ok_or_else(|| preparation("Landlock executable lookup"))?
            .file;
        ruleset = add_rule(ruleset, file, AccessFs::Execute.into())?;
    }
    // The shape checks in preparation ensure all directory rules are subtree
    // rules. PathBeneath is therefore an exact rule for files and a recursive
    // rule only where the typed policy requested one.
    let _ = PathScope::Subtree;
    Ok(PreparedLandlock { ruleset })
}

pub(crate) fn apply(prepared: PreparedLandlock) -> Result<(), LinuxError> {
    let status = prepared
        .ruleset
        .set_compatibility(CompatLevel::HardRequirement)
        .restrict_self()
        .map_err(|_| enforcement("Landlock application"))?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(enforcement("Landlock completeness"));
    }
    Ok(())
}

fn add_rule(
    ruleset: RulesetCreated,
    file: &File,
    rights: BitFlags<AccessFs>,
) -> Result<RulesetCreated, LinuxError> {
    ruleset
        .add_rule(PathBeneath::new(file, rights))
        .map_err(|_| preparation("Landlock rule addition"))
}

fn read_rights(kind: PinnedKind) -> BitFlags<AccessFs> {
    if kind == PinnedKind::Directory {
        AccessFs::ReadFile | AccessFs::ReadDir
    } else {
        AccessFs::ReadFile.into()
    }
}

fn write_rights(kind: PinnedKind) -> BitFlags<AccessFs> {
    // Keep the fixed filesystem mutation set independent from future rights.
    let rights = AccessFs::from_write(ABI::V8);
    if kind == PinnedKind::Directory {
        rights
    } else {
        // Never attach directory-mutation rights to an exact file-like rule.
        rights & AccessFs::from_file(ABI::V8)
    }
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
