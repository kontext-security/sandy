//! Pure lowering from Sandy's validated capability vocabulary to SBPL source.
//!
//! Every policy value interpolated into SBPL passes through the single escaping path in
//! [`crate::escape`]. This module never accepts caller-provided SBPL fragments.

use std::fmt::Write as _;

use sandy_core::{
    AccessMode, FileGrant, NetworkPolicy, PathScope, UnixSocketGrant, UnixSocketOperation,
    ValidatedPolicy,
};

use crate::{SeatbeltError, escape::quoted};

// These are runtime files shipped by macOS and required to resolve and load ordinary executables.
// They are a backend compatibility baseline, not user grants, and remain read-only.
const SYSTEM_READ_SUBPATHS: &[&str] = &[
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/Library/Apple",
    "/private/etc",
    "/private/var/db/dyld",
];

// Character devices needed by ordinary command-line programs. Granting the node itself does not
// grant a subtree beneath `/dev`.
const SYSTEM_READ_LITERALS: &[&str] = &[
    "/dev/null",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/ptmx",
];

// Terminal attribute and window-size operations are separate from file reads/writes in Seatbelt.
// Keep this list device-shaped and narrow; the adjacent-negative live test proves unrelated
// device ioctls remain denied. Issue #4 will replace the device pattern with an exact typed device.
const FOREGROUND_TERMINAL_RULES: &str = "\
(allow pseudo-tty)\n\
(allow file-ioctl\n\
    (literal \"/dev/tty\")\n\
    (literal \"/dev/ptmx\")\n\
    (regex #\"^/dev/ttys[0-9]+$\"))\n";

const UNIX_STREAM_SOCKET_SETUP: &str =
    "(allow system-socket (socket-domain AF_UNIX) (socket-type SOCK_STREAM))\n";

/// SBPL source produced exclusively from a [`ValidatedPolicy`].
///
/// The source is readable for dry-run diagnostics, but the private field prevents callers from
/// constructing an unchecked profile and passing it to [`crate::apply`].
#[derive(Clone, Debug)]
pub struct CompiledProfile {
    source: String,
}

impl CompiledProfile {
    /// Returns the generated SBPL for diagnostics and tests.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// Deterministically compiles a validated platform-neutral policy into SBPL.
///
/// This function performs no filesystem access and has no unrestricted fallback. Rendering errors
/// are returned before the bootstrap attempts to apply the sandbox or execute the target.
pub fn compile(policy: &ValidatedPolicy) -> Result<CompiledProfile, SeatbeltError> {
    // Start deny-first, then add the process operations required for an agent to execute tools and
    // supervise descendants inside the same inherited sandbox domain.
    let mut source = String::from(
        "(version 1)\n\
         (deny default)\n\
         (allow process-exec*)\n\
         (allow process-fork)\n\
         (allow process-info* (target self))\n\
         (allow process-info* (target same-sandbox))\n\
         (allow signal (target self))\n\
         (allow signal (target same-sandbox))\n\
         (allow sysctl-read)\n\
         (allow file-read-metadata)\n\
         (allow mach-lookup)\n",
    );
    // Broad Mach lookup is a documented compatibility tradeoff. Explicit security-service denies
    // prevent common Keychain APIs from turning an allowed host daemon into a credential deputy.
    source.push_str(
        "(deny mach-lookup (global-name \"com.apple.SecurityServer\"))\n\
         (deny mach-lookup (global-name \"com.apple.securityd\"))\n\
         (deny mach-lookup (global-name \"com.apple.securityd.xpc\"))\n\
         (deny mach-lookup (global-name \"com.apple.securityd.general\"))\n\
         (deny mach-lookup (global-name \"com.apple.securityd.systemkeychain\"))\n\
         (deny mach-lookup (global-name \"com.apple.security.keychaind\"))\n\
         (deny mach-lookup (global-name \"com.apple.secd\"))\n\
         (deny mach-lookup (global-name \"com.apple.security.agent\"))\n\
         (allow mach-per-user-lookup)\n\
         (allow mach-task-name)\n\
         (deny mach-priv*)\n\
         (allow ipc-posix-shm-read-data)\n\
         (allow ipc-posix-shm-write-data)\n\
         (allow ipc-posix-shm-write-create)\n\
         (allow system-fsctl)\n\
         (allow system-info)\n",
    );
    source.push_str(FOREGROUND_TERMINAL_RULES);
    // Literal root metadata is needed to begin absolute path traversal; it does not grant subtree
    // contents because the filter is `literal`, not `subpath`.
    source.push_str("(allow file-read* (literal \"/\"))\n");

    for path in SYSTEM_READ_SUBPATHS {
        write_rule(&mut source, "allow", "file-read*", PathScope::Subtree, path)?;
    }
    for path in SYSTEM_READ_LITERALS {
        write_rule(&mut source, "allow", "file-read*", PathScope::Exact, path)?;
        write_rule(&mut source, "allow", "file-write*", PathScope::Exact, path)?;
    }

    for grant in &policy.spec().files {
        render_grant(&mut source, grant)?;
    }

    match policy.spec().network {
        NetworkPolicy::AllowAll => source.push_str("(allow network*)\n"),
        NetworkPolicy::BlockAll if !policy.spec().unix_sockets.is_empty() => {
            source.push_str(UNIX_STREAM_SOCKET_SETUP);
            for grant in &policy.spec().unix_sockets {
                render_unix_socket_grant(&mut source, grant)?;
            }
        }
        NetworkPolicy::BlockAll => {}
    }

    // Terminal denies are emitted after positive grants. Renderer and live tests pin their ability
    // to protect narrow paths even when a broader parent directory was granted.
    for path in &policy.spec().protected_paths {
        write_rule(
            &mut source,
            "deny",
            "file-read* file-write*",
            PathScope::Subtree,
            path.as_str(),
        )?;
    }
    for path in &policy.spec().protected_write_paths {
        write_rule(
            &mut source,
            "deny",
            "file-write*",
            PathScope::Exact,
            path.as_str(),
        )?;
    }

    Ok(CompiledProfile { source })
}

fn render_grant(source: &mut String, grant: &FileGrant) -> Result<(), SeatbeltError> {
    // Mapping an executable is a distinct Seatbelt operation from reading its bytes. Restrict it
    // to the same exact/subtree boundary instead of granting executable mapping globally.
    write_rule(
        source,
        "allow",
        "file-map-executable",
        grant.scope,
        grant.path.as_str(),
    )?;
    write_rule(
        source,
        "allow",
        "file-read*",
        grant.scope,
        grant.path.as_str(),
    )?;
    if grant.access == AccessMode::ReadWrite {
        write_rule(
            source,
            "allow",
            "file-write*",
            grant.scope,
            grant.path.as_str(),
        )?;
    }
    Ok(())
}

fn render_unix_socket_grant(
    source: &mut String,
    grant: &UnixSocketGrant,
) -> Result<(), SeatbeltError> {
    match grant.operation {
        UnixSocketOperation::Connect => {
            // Seatbelt classifies connect(2) to a pathname AF_UNIX endpoint as
            // network-outbound. Its `path` filter is exact; filesystem
            // `literal` rules remain a separate policy layer.
            let path = quoted(grant.path.as_str())?;
            let _ = writeln!(source, "(allow network-outbound (path {path}))");
        }
    }
    Ok(())
}

fn write_rule(
    output: &mut String,
    decision: &str,
    operations: &str,
    scope: PathScope,
    path: &str,
) -> Result<(), SeatbeltError> {
    // Keep filter selection and value escaping centralized. Adding another renderer-side path
    // interpolation would create a second policy-injection boundary.
    let filter = match scope {
        PathScope::Exact => "literal",
        PathScope::Subtree => "subpath",
    };
    let path = quoted(path)?;
    let _ = writeln!(output, "({decision} {operations} ({filter} {path}))");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use sandy_core::{
        AbsolutePath, AccessMode, CommandSpec, FileGrant, LaunchManifestV1, MANIFEST_SCHEMA_V1,
        NetworkPolicy, OsValue, PathScope, PolicySpec, UnixSocketGrant, UnixSocketOperation,
        ValidatedLaunch,
    };

    use super::*;

    fn policy(network: NetworkPolicy) -> Result<ValidatedLaunch, Box<dyn std::error::Error>> {
        policy_with_sockets(network, Vec::new())
    }

    fn policy_with_sockets(
        network: NetworkPolicy,
        unix_sockets: Vec<UnixSocketGrant>,
    ) -> Result<ValidatedLaunch, Box<dyn std::error::Error>> {
        let manifest = LaunchManifestV1 {
            schema_version: MANIFEST_SCHEMA_V1,
            command: CommandSpec {
                program: OsValue::from_os_str(OsStr::new("/bin/echo")),
                arguments: Vec::new(),
            },
            working_directory: AbsolutePath::new("/tmp/project")?,
            environment: Vec::new(),
            policy: PolicySpec {
                files: vec![FileGrant {
                    path: AbsolutePath::new("/tmp/project")?,
                    access: AccessMode::ReadWrite,
                    scope: PathScope::Subtree,
                }],
                protected_paths: vec![AbsolutePath::new("/tmp/project/.secret")?],
                protected_write_paths: vec![AbsolutePath::new("/tmp/project/config.toml")?],
                unix_sockets,
                network,
            },
        };
        Ok(ValidatedLaunch::try_from(manifest)?)
    }

    #[test]
    fn renders_typed_grants_and_protected_denies() -> Result<(), Box<dyn std::error::Error>> {
        let launch = policy(NetworkPolicy::BlockAll)?;
        let profile = compile(launch.policy())?;
        assert!(
            profile
                .source()
                .contains(r#"(allow file-write* (subpath "/tmp/project"))"#)
        );
        assert!(
            profile
                .source()
                .contains(r#"(deny file-read* file-write* (subpath "/tmp/project/.secret"))"#)
        );
        assert!(
            profile
                .source()
                .contains(r#"(deny file-write* (literal "/tmp/project/config.toml"))"#)
        );
        assert!(!profile.source().contains("(allow network*)"));
        Ok(())
    }

    #[test]
    fn renders_network_only_when_allowed() -> Result<(), Box<dyn std::error::Error>> {
        let launch = policy(NetworkPolicy::AllowAll)?;
        assert!(
            compile(launch.policy())?
                .source()
                .contains("(allow network*)")
        );
        Ok(())
    }

    #[test]
    fn terminally_denies_current_and_legacy_keychain_services()
    -> Result<(), Box<dyn std::error::Error>> {
        let profile = compile(policy(NetworkPolicy::AllowAll)?.policy())?;
        for service in [
            "com.apple.SecurityServer",
            "com.apple.securityd",
            "com.apple.securityd.xpc",
            "com.apple.securityd.general",
            "com.apple.securityd.systemkeychain",
            "com.apple.security.keychaind",
            "com.apple.secd",
            "com.apple.security.agent",
        ] {
            assert!(
                profile
                    .source()
                    .contains(&format!("(deny mach-lookup (global-name \"{service}\"))"))
            );
        }
        Ok(())
    }

    #[test]
    fn renders_only_exact_connect_authority_when_network_is_blocked()
    -> Result<(), Box<dyn std::error::Error>> {
        let socket = UnixSocketGrant {
            path: AbsolutePath::new("/private/tmp/control.sock")?,
            operation: UnixSocketOperation::Connect,
        };
        let launch = policy_with_sockets(NetworkPolicy::BlockAll, vec![socket])?;
        let source = compile(launch.policy())?;

        assert!(source.source().contains(UNIX_STREAM_SOCKET_SETUP));
        assert!(
            source
                .source()
                .contains(r#"(allow network-outbound (path "/private/tmp/control.sock"))"#)
        );
        assert!(
            !source
                .source()
                .lines()
                .any(|line| line == "(allow network*)")
        );
        assert!(!source.source().contains("(allow network-bind"));
        assert!(!source.source().contains("/private/tmp/sibling.sock"));
        assert!(!source.source().contains("mDNSResponder"));
        Ok(())
    }

    #[test]
    fn filesystem_access_does_not_imply_socket_connect_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = compile(policy(NetworkPolicy::BlockAll)?.policy())?;
        assert!(!source.source().contains("(allow network-outbound"));
        assert!(!source.source().contains(UNIX_STREAM_SOCKET_SETUP));
        Ok(())
    }

    #[test]
    fn escapes_unix_socket_paths_through_the_central_renderer()
    -> Result<(), Box<dyn std::error::Error>> {
        let socket = UnixSocketGrant {
            path: AbsolutePath::new(r#"/private/tmp/control\") (allow network*) ("#)?,
            operation: UnixSocketOperation::Connect,
        };
        let expected_path = quoted(socket.path.as_str())?;
        let launch = policy_with_sockets(NetworkPolicy::BlockAll, vec![socket])?;
        let source = compile(launch.policy())?;

        assert!(
            source
                .source()
                .contains(&format!("(allow network-outbound (path {expected_path}))"))
        );
        assert!(
            !source
                .source()
                .lines()
                .any(|line| line == "(allow network*)")
        );
        Ok(())
    }

    #[test]
    fn scopes_foreground_terminal_ioctls_to_tty_devices() -> Result<(), Box<dyn std::error::Error>>
    {
        let source = compile(policy(NetworkPolicy::BlockAll)?.policy())?;
        assert!(source.source().contains(FOREGROUND_TERMINAL_RULES));
        assert!(!source.source().contains("(allow file-ioctl)"));
        assert!(!source.source().contains("file-ioctl (subpath \"/dev\")"));
        Ok(())
    }
}
