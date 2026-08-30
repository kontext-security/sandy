//! Explicit macOS runtime capabilities required by the Sandy CLI launcher.

use std::path::Path;

use sandy_core::{AccessMode, PathScope, SandboxPolicy, allow_file_metadata};

const READ_ONLY_SUBTREES: &[&str] = &[
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/Library/Apple",
    "/private/etc",
    "/private/var/db/dyld",
    "/private/var/db/timezone",
];

const READ_WRITE_LITERALS: &[&str] = &[
    "/dev/null",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/ptmx",
];

/// Adds the CLI's ordinary command-runtime permissions through the shared
/// policy builder. These entries have no privileged precedence over profile or
/// user policy, and terminal denies still override them.
pub(crate) fn add_to(policy: SandboxPolicy) -> SandboxPolicy {
    add_matching(policy, |path| Path::new(path).exists())
}

fn add_matching(mut policy: SandboxPolicy, mut include: impl FnMut(&str) -> bool) -> SandboxPolicy {
    policy = allow_file_metadata(policy);
    policy = policy.grant("/", AccessMode::Read, PathScope::Exact);
    for path in READ_ONLY_SUBTREES {
        if include(path) {
            policy = policy.grant(path, AccessMode::Read, PathScope::Subtree);
        }
    }
    for path in READ_WRITE_LITERALS {
        if include(path) {
            policy = policy.grant(path, AccessMode::ReadWrite, PathScope::Exact);
        }
    }
    policy
}

#[cfg(test)]
mod tests {
    use sandy_core::{NetworkPolicy, into_policy_parts};

    use super::*;

    #[test]
    fn baseline_is_only_explicit_policy_input() -> Result<(), Box<dyn std::error::Error>> {
        let parts = into_policy_parts(add_matching(
            SandboxPolicy::new(NetworkPolicy::BlockAll),
            |_| true,
        ))?;

        assert!(parts.grants.iter().any(|grant| {
            grant.path == std::path::Path::new("/")
                && grant.access == AccessMode::Read
                && grant.scope == PathScope::Exact
        }));
        assert!(parts.grants.iter().any(|grant| {
            grant.path == std::path::Path::new("/System")
                && grant.access == AccessMode::Read
                && grant.scope == PathScope::Subtree
        }));
        assert!(parts.denied_subtrees.is_empty());
        assert!(parts.write_denied_exact.is_empty());
        assert_eq!(parts.file_metadata, sandy_core::FileMetadataPolicy::Allow);
        Ok(())
    }
}
