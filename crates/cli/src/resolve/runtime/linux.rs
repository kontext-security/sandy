//! Explicit Linux runtime capabilities required by the Sandy CLI launcher.

use std::path::Path;

use sandy_core::{
    AccessMode, NetworkPolicy, PathScope, SandboxPolicy, allow_foreground_cli_compatibility,
};

use crate::resolve::CliPolicyIntent;

const READ_EXECUTE_SUBTREES: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/libexec",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
];

const READ_ONLY_DATA_SUBTREES: &[&str] = &[
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
    "/usr/share",
    "/usr/share/ca-certificates",
    "/usr/share/zoneinfo",
];

const READ_ONLY_DEVICE_FILES: &[&str] = &["/dev/random", "/dev/urandom"];

const READ_WRITE_DEVICE_FILES: &[&str] = &["/dev/null", "/dev/zero", "/dev/tty"];

const READ_ONLY_DATA_FILES: &[&str] = &[
    "/etc/ld.so.cache",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/host.conf",
    "/etc/gai.conf",
    "/etc/localtime",
    "/etc/ssl/openssl.cnf",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/stat",
    "/proc/version",
    "/proc/sys/kernel/osrelease",
];

/// Adds only the ordinary Linux loader and public runtime data selected by the
/// CLI product. Only named runtime devices are exposed; the rest of `/dev` and
/// the host process tree remain absent. Inherited standard streams and their
/// controlling terminal remain caller-held capabilities.
pub(crate) fn intent(network: NetworkPolicy) -> CliPolicyIntent {
    add_matching(network, |path| Path::new(path).exists())
}

fn add_matching(network: NetworkPolicy, mut include: impl FnMut(&str) -> bool) -> CliPolicyIntent {
    let policy = allow_foreground_cli_compatibility(SandboxPolicy::new(network));
    let mut intent = CliPolicyIntent::new(policy);
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
    for path in READ_ONLY_DATA_FILES {
        if include(path) {
            intent = intent.grant_file(path, AccessMode::Read, PathScope::Exact);
        }
    }
    for path in READ_ONLY_DEVICE_FILES {
        if include(path) {
            intent = intent.grant_file(path, AccessMode::Read, PathScope::Exact);
        }
    }
    for path in READ_WRITE_DEVICE_FILES {
        if include(path) {
            intent = intent.grant_file(path, AccessMode::ReadWrite, PathScope::Exact);
        }
    }
    intent
}

#[cfg(test)]
mod tests {
    use sandy_core::{FileMetadataPolicy, RuntimeCompatibility};

    use crate::resolve::resolve_policy;

    use super::*;

    #[test]
    fn baseline_is_explicit_and_contains_only_named_devices()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = resolve_policy(add_matching(NetworkPolicy::BlockAll, |_| true), &[])?
            .finish()?
            .into_spec();

        assert_eq!(policy.file_metadata, FileMetadataPolicy::Deny);
        assert!(policy.allow_subprocesses);
        assert_eq!(
            policy.runtime_compatibility,
            RuntimeCompatibility::ForegroundCli
        );
        assert!(
            policy
                .files
                .iter()
                .all(|grant| grant.path.as_str() != "/dev")
        );
        assert!(
            policy
                .files
                .iter()
                .all(|grant| grant.path.as_str() != "/proc")
        );
        assert!(policy.files.iter().any(|grant| {
            grant.path.as_str() == "/dev/null"
                && grant.access == AccessMode::ReadWrite
                && grant.scope == PathScope::Exact
        }));
        assert!(policy.files.iter().all(|grant| {
            !grant.path.as_str().starts_with("/proc/") || grant.scope == PathScope::Exact
        }));
        assert!(policy.files.iter().any(|grant| {
            grant.path.as_str() == "/usr/bin"
                && grant.access == AccessMode::Read
                && grant.scope == PathScope::Subtree
        }));
        assert!(policy.executables.iter().any(|grant| {
            grant.path.as_str() == "/usr/bin" && grant.scope == PathScope::Subtree
        }));
        assert!(
            policy.executables.iter().all(|grant| {
                grant.path.as_str() != "/usr" && grant.path.as_str() != "/usr/share"
            })
        );
        Ok(())
    }

    #[test]
    fn data_paths_never_gain_executable_authority() -> Result<(), Box<dyn std::error::Error>> {
        let policy = resolve_policy(
            add_matching(NetworkPolicy::BlockAll, |path| {
                READ_ONLY_DATA_SUBTREES.contains(&path) || READ_ONLY_DATA_FILES.contains(&path)
            }),
            &[],
        )?
        .finish()?
        .into_spec();

        for grant in &policy.files {
            assert!(
                !policy
                    .executables
                    .iter()
                    .any(|executable| executable.path == grant.path)
            );
        }
        Ok(())
    }
}
