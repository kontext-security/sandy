use std::fmt::Write as _;

use sandy_core::{AccessMode, FileGrant, NetworkPolicy, PathScope, ValidatedPolicy};

use crate::{SeatbeltError, escape::quoted};

const SYSTEM_READ_SUBPATHS: &[&str] = &[
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/Library/Apple",
    "/private/etc",
    "/private/var/db/dyld",
];

const SYSTEM_READ_LITERALS: &[&str] = &[
    "/dev/null",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/ptmx",
];

#[derive(Clone, Debug)]
pub struct CompiledProfile {
    source: String,
}

impl CompiledProfile {
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

pub fn compile(policy: &ValidatedPolicy) -> Result<CompiledProfile, SeatbeltError> {
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
    source.push_str(
        "(deny mach-lookup (global-name \"com.apple.SecurityServer\"))\n\
         (deny mach-lookup (global-name \"com.apple.securityd\"))\n\
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
         (allow system-info)\n\
         (allow pseudo-tty)\n\
         (allow file-read* (literal \"/\"))\n",
    );

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

    if policy.spec().network == NetworkPolicy::AllowAll {
        source.push_str("(allow network*)\n");
    }

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

fn write_rule(
    output: &mut String,
    decision: &str,
    operations: &str,
    scope: PathScope,
    path: &str,
) -> Result<(), SeatbeltError> {
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
        NetworkPolicy, OsValue, PathScope, PolicySpec, ValidatedLaunch,
    };

    use super::*;

    fn policy(network: NetworkPolicy) -> Result<ValidatedLaunch, Box<dyn std::error::Error>> {
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
}
