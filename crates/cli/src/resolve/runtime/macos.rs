//! Explicit macOS runtime capabilities required by the Sandy CLI launcher.

use std::path::Path;

use sandy_core::{
    AccessMode, PathScope, SandboxPolicy, allow_file_metadata, allow_foreground_cli_compatibility,
};

use crate::resolve::CliPolicyIntent;

const READ_EXECUTE_SUBTREES: &[&str] = &[
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/Library/Apple",
    "/private/var/db/dyld",
];

const READ_ONLY_DATA_SUBTREES: &[&str] = &["/private/etc", "/private/var/db/timezone"];

const READ_WRITE_LITERALS: &[&str] = &[
    "/dev/null",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/ptmx",
];

/// Adds the CLI's ordinary command-runtime permissions through the shared
/// policy builder. These entries have no privileged precedence over caller
/// policy, and terminal denies still override them.
pub(crate) fn intent(policy: SandboxPolicy) -> CliPolicyIntent {
    add_matching(policy, |path| Path::new(path).exists())
}

fn add_matching(
    mut policy: SandboxPolicy,
    mut include: impl FnMut(&str) -> bool,
) -> CliPolicyIntent {
    policy = allow_file_metadata(policy);
    policy = allow_foreground_cli_compatibility(policy);
    let mut intent =
        CliPolicyIntent::new(policy).grant_file("/", AccessMode::Read, PathScope::Exact);
    for path in READ_EXECUTE_SUBTREES {
        if include(path) {
            intent = intent.grant_file_and_execute(path, AccessMode::Read, PathScope::Subtree);
        }
    }
    for path in READ_ONLY_DATA_SUBTREES {
        if include(path) {
            intent = intent.grant_file(path, AccessMode::Read, PathScope::Subtree);
        }
    }
    for path in READ_WRITE_LITERALS {
        if include(path) {
            intent = intent.grant_file(path, AccessMode::ReadWrite, PathScope::Exact);
        }
    }
    intent
}

#[cfg(test)]
mod tests {
    use sandy_core::NetworkPolicy;

    use crate::resolve::resolve_policy;

    use super::*;

    #[test]
    fn baseline_is_only_explicit_policy_input() -> Result<(), Box<dyn std::error::Error>> {
        let policy = resolve_policy(
            add_matching(
                SandboxPolicy::new(NetworkPolicy::BlockAll).allow_subprocesses(),
                |_| false,
            ),
            &[],
        )?
        .finish()?
        .into_spec();

        assert!(policy.files.iter().any(|grant| {
            grant.path.as_path() == std::path::Path::new("/")
                && grant.access == AccessMode::Read
                && grant.scope == PathScope::Exact
        }));
        assert!(policy.protected_paths.is_empty());
        assert!(policy.write_protections.is_empty());
        assert_eq!(policy.file_metadata, sandy_core::FileMetadataPolicy::Allow);
        assert!(policy.allow_subprocesses);
        assert!(policy.executables.is_empty());
        assert_eq!(
            policy.runtime_compatibility,
            sandy_core::RuntimeCompatibility::ForegroundCli
        );
        Ok(())
    }

    #[test]
    fn data_and_device_paths_do_not_gain_executable_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = resolve_policy(
            add_matching(
                SandboxPolicy::new(NetworkPolicy::BlockAll).allow_subprocesses(),
                |path| {
                    READ_ONLY_DATA_SUBTREES.contains(&path) || READ_WRITE_LITERALS.contains(&path)
                },
            ),
            &[],
        )?
        .finish()?
        .into_spec();

        for path in READ_ONLY_DATA_SUBTREES
            .iter()
            .chain(READ_WRITE_LITERALS)
            .filter_map(|path| std::fs::canonicalize(path).ok())
        {
            assert!(
                policy
                    .files
                    .iter()
                    .any(|grant| grant.path.as_path() == path)
            );
            assert!(
                !policy
                    .executables
                    .iter()
                    .any(|grant| grant.path.as_path() == path)
            );
        }
        Ok(())
    }
}
