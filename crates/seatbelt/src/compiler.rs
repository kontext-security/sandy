//! Pure composition of Sandy's fixed macOS baseline and validated capabilities into SBPL source.
//!
//! Every policy value interpolated into SBPL passes through the single escaping path in
//! [`crate::escape`]. This module never accepts caller-provided SBPL fragments.

use std::fmt::Write as _;

use sandy_core::{
    AccessMode, FileGrant, FileMetadataPolicy, LocalHostTcpGrant, LocalHostTcpOperation,
    NetworkPolicy, PathScope, UnixSocketGrant, UnixSocketOperation, ValidatedPolicy,
};

use crate::{SeatbeltError, baseline, escape::quoted};

const UNIX_STREAM_SOCKET_SETUP: &str =
    "(allow system-socket (socket-domain AF_UNIX) (socket-type SOCK_STREAM))\n";
const IPV4_STREAM_SOCKET_SETUP: &str =
    "(allow system-socket (socket-domain AF_INET) (socket-type SOCK_STREAM))\n";

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

/// Deterministically compiles the fixed backend baseline and a validated policy into SBPL.
///
/// This function performs no filesystem access and has no unrestricted fallback. Rendering errors
/// are returned before the bootstrap attempts to apply the sandbox or execute the target.
pub fn compile(policy: &ValidatedPolicy) -> Result<CompiledProfile, SeatbeltError> {
    let mut source = String::from(baseline::STATIC_RULES);
    source.push_str(baseline::FOREGROUND_TERMINAL_RULES);

    if policy.spec().file_metadata == FileMetadataPolicy::Allow {
        source.push_str("(allow file-read-metadata)\n");
    }

    for grant in &policy.spec().files {
        render_grant(&mut source, grant)?;
    }

    match policy.spec().network {
        NetworkPolicy::AllowAll => source.push_str("(allow network*)\n"),
        NetworkPolicy::BlockAll => {
            if !policy.spec().unix_sockets.is_empty() {
                source.push_str(UNIX_STREAM_SOCKET_SETUP);
                for grant in &policy.spec().unix_sockets {
                    render_unix_socket_grant(&mut source, grant)?;
                }
            }
            if !policy.spec().local_host_tcp.is_empty() {
                source.push_str(IPV4_STREAM_SOCKET_SETUP);
                for grant in &policy.spec().local_host_tcp {
                    render_local_host_tcp_grant(&mut source, grant)?;
                }
            }
        }
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
    for protection in &policy.spec().write_protections {
        write_rule(
            &mut source,
            "deny",
            "file-write*",
            protection.scope,
            protection.path.as_str(),
        )?;
    }

    Ok(CompiledProfile { source })
}

fn render_local_host_tcp_grant(
    source: &mut String,
    grant: &LocalHostTcpGrant,
) -> Result<(), SeatbeltError> {
    match grant.operation {
        LocalHostTcpOperation::Connect => {
            // Seatbelt rejects numeric addresses in this filter and requires
            // its special `localhost` token. On macOS that token covers the
            // selected port on IPv4 addresses belonging to this Mac, not only
            // 127.0.0.1. AF_INET setup above excludes IPv6.
            let endpoint = quoted(&format!("localhost:{}", grant.port.get()))?;
            let _ = writeln!(source, "(allow network-outbound (remote tcp {endpoint}))");
        }
    }
    Ok(())
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
        AbsolutePath, AccessMode, CommandSpec, FileGrant, LaunchManifestV2, LocalHostTcpGrant,
        LocalHostTcpOperation, MANIFEST_SCHEMA_V2, NetworkPolicy, OsValue, PathScope, PolicySpec,
        TcpPort, UnixSocketGrant, UnixSocketOperation, ValidatedLaunch, WriteProtection,
    };

    use super::*;

    fn policy(network: NetworkPolicy) -> Result<ValidatedLaunch, Box<dyn std::error::Error>> {
        policy_with_sockets(network, Vec::new())
    }

    fn policy_with_sockets(
        network: NetworkPolicy,
        unix_sockets: Vec<UnixSocketGrant>,
    ) -> Result<ValidatedLaunch, Box<dyn std::error::Error>> {
        let manifest = LaunchManifestV2 {
            schema_version: MANIFEST_SCHEMA_V2,
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
                write_protections: vec![
                    WriteProtection {
                        path: AbsolutePath::new("/tmp/project/config.toml")?,
                        scope: PathScope::Exact,
                    },
                    WriteProtection {
                        path: AbsolutePath::new("/tmp/project/operator-rules")?,
                        scope: PathScope::Subtree,
                    },
                ],
                unix_sockets,
                local_host_tcp: Vec::new(),
                file_metadata: FileMetadataPolicy::Deny,
                network,
            },
        };
        Ok(ValidatedLaunch::try_from(manifest)?)
    }

    fn policy_with_local_host_tcp(
        network: NetworkPolicy,
        port: u16,
    ) -> Result<ValidatedLaunch, Box<dyn std::error::Error>> {
        let mut launch = policy(network)?.into_manifest();
        launch.policy.local_host_tcp.push(LocalHostTcpGrant {
            port: TcpPort::new(port).ok_or("test port must be nonzero")?,
            operation: LocalHostTcpOperation::Connect,
        });
        Ok(ValidatedLaunch::try_from(launch)?)
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
        assert!(
            profile
                .source()
                .contains(r#"(deny file-write* (subpath "/tmp/project/operator-rules"))"#)
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
    fn does_not_add_implicit_filesystem_runtime_grants() -> Result<(), Box<dyn std::error::Error>> {
        let source = compile(policy(NetworkPolicy::BlockAll)?.policy())?;
        assert!(!source.source().contains("file-read-metadata"));
        assert!(!source.source().contains(r#"(subpath "/System")"#));
        assert!(!source.source().contains(r#"(literal "/dev/null")"#));
        assert!(!source.source().contains(r#"(literal "/")"#));
        Ok(())
    }

    #[test]
    fn renders_metadata_only_when_typed_policy_allows_it() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut manifest = policy(NetworkPolicy::BlockAll)?.into_manifest();
        manifest.policy.file_metadata = FileMetadataPolicy::Allow;
        let launch = ValidatedLaunch::try_from(manifest)?;
        assert!(
            compile(launch.policy())?
                .source()
                .contains("(allow file-read-metadata)")
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
        assert!(!source.source().contains(IPV4_STREAM_SOCKET_SETUP));
        Ok(())
    }

    #[test]
    fn renders_only_one_ipv4_local_host_port_when_network_is_blocked()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = compile(policy_with_local_host_tcp(NetworkPolicy::BlockAll, 4318)?.policy())?;

        assert!(source.source().contains(IPV4_STREAM_SOCKET_SETUP));
        assert!(
            source
                .source()
                .contains(r#"(allow network-outbound (remote tcp "localhost:4318"))"#)
        );
        assert!(!source.source().contains("localhost:4317"));
        assert!(!source.source().contains("*:4318"));
        assert!(!source.source().contains("(allow network-bind"));
        assert!(
            !source
                .source()
                .lines()
                .any(|line| line == "(allow network*)")
        );
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
        assert!(
            source
                .source()
                .contains(baseline::FOREGROUND_TERMINAL_RULES)
        );
        assert!(!source.source().contains("(allow file-ioctl)"));
        assert!(!source.source().contains("file-ioctl (subpath \"/dev\")"));
        Ok(())
    }
}
