use std::{
    fs::OpenOptions,
    io::Write as _,
    os::unix::{fs::OpenOptionsExt as _, process::ExitStatusExt as _},
    process::{Command, Stdio},
};

use sandy_core::{
    AccessMode, CommandSpec, FileGrant, LaunchManifestV1, MANIFEST_SCHEMA_V1, NetworkPolicy,
    OsValue, PathScope, PolicySpec, ValidatedLaunch, encode_launch,
};
use serde_json::json;
use tempfile::Builder;

use crate::{
    cli::RunArgs,
    error::AppError,
    integration::{IntegrationMode, kontext},
    profile,
    resolve::{grant, resolve_command, resolve_paths, sanitized_environment},
};

pub(crate) fn run(arguments: RunArgs) -> Result<i32, AppError> {
    if !cfg!(target_os = "macos") {
        return Err(AppError::UnsupportedPlatform);
    }
    let command = resolve_command(&arguments.target)?;
    let selected = profile::select(arguments.profile.as_ref(), &command.requested_name)?;
    if selected.detected() {
        eprintln!(
            "sandy: applying detected agent profile '{}' (override with --profile)",
            selected.name()
        );
    }
    let paths = resolve_paths(selected.protected_templates())?;
    let session = Builder::new()
        .prefix("sandy-")
        .tempdir()
        .map_err(|error| AppError::io("create private Sandy session", error))?;

    let mut files = vec![FileGrant {
        path: paths.working_directory.clone(),
        access: AccessMode::ReadWrite,
        scope: PathScope::Subtree,
    }];
    files.push(grant(
        &command.program,
        AccessMode::Read,
        PathScope::Exact,
        &paths.protected,
    )?);
    if let Some(parent) = command.program.parent() {
        files.push(grant(
            parent,
            AccessMode::Read,
            PathScope::Subtree,
            &paths.protected,
        )?);
    }
    files.push(grant(
        session.path(),
        AccessMode::ReadWrite,
        PathScope::Subtree,
        &paths.protected,
    )?);
    files.extend(selected.grants(&paths)?);
    for path in &arguments.read {
        files.push(grant(
            path,
            AccessMode::Read,
            PathScope::Subtree,
            &paths.protected,
        )?);
    }
    for path in &arguments.read_write {
        files.push(grant(
            path,
            AccessMode::ReadWrite,
            PathScope::Subtree,
            &paths.protected,
        )?);
    }

    let integration_mode = if arguments.kontext {
        IntegrationMode::Required
    } else {
        IntegrationMode::Detect
    };
    let kontext = kontext::resolve(&selected.hook_sources(&paths), integration_mode, &paths)?;
    if let Some(reason) = kontext.unavailable_reason() {
        eprintln!(
            "sandy: optional {} runtime control unavailable; continuing without it: {reason}",
            kontext.service()
        );
    }
    let mut protected_write_paths = selected.protected_write_paths(&paths)?;
    let mut unix_sockets = Vec::new();
    kontext.contribute(&mut files, &mut protected_write_paths, &mut unix_sockets);
    deduplicate_grants(&mut files);
    unix_sockets.sort();
    unix_sockets.dedup();
    protected_write_paths.sort();
    protected_write_paths.dedup();
    let protected_paths = selected.protected_paths(&paths);

    let manifest = LaunchManifestV1 {
        schema_version: MANIFEST_SCHEMA_V1,
        command: CommandSpec {
            program: OsValue::from_os_str(command.program.as_os_str()),
            arguments: command
                .arguments
                .iter()
                .map(|value| OsValue::from_os_str(value))
                .collect(),
        },
        working_directory: paths.working_directory,
        environment: sanitized_environment(session.path()),
        policy: PolicySpec {
            files,
            protected_paths,
            protected_write_paths,
            unix_sockets,
            network: if arguments.block_net {
                NetworkPolicy::BlockAll
            } else {
                NetworkPolicy::AllowAll
            },
        },
    };
    let validated = ValidatedLaunch::try_from(manifest.clone())?;

    #[cfg(target_os = "macos")]
    let profile_source = sandy_seatbelt::compile(validated.policy())?
        .source()
        .to_owned();
    #[cfg(not(target_os = "macos"))]
    let profile_source = String::new();

    if arguments.dry_run {
        let output = json!({
            "schema_version": MANIFEST_SCHEMA_V1,
            "command": command.program.to_string_lossy(),
            "arguments": command.arguments.iter().map(|value| value.to_string_lossy()).collect::<Vec<_>>(),
            "working_directory": validated.manifest().working_directory.as_str(),
            "profile": {
                "name": selected.name(),
                "detected": selected.detected(),
            },
            "network": validated.manifest().policy.network,
            "file_grants": validated.manifest().policy.files,
            "unix_socket_grants": validated.manifest().policy.unix_sockets,
            "kontext": {
                "enabled": kontext.is_active(),
                "version": kontext.version(),
            },
            "seatbelt_profile": profile_source,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|error| AppError::Launch(format!("encode dry-run output: {error}")))?
        );
        return Ok(0);
    }

    let manifest_path = session.path().join("launch.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&manifest_path)
        .map_err(|error| AppError::io("create launch manifest", error))?;
    file.write_all(&encode_launch(&manifest)?)
        .map_err(|error| AppError::io("write launch manifest", error))?;
    file.sync_all()
        .map_err(|error| AppError::io("sync launch manifest", error))?;
    drop(file);

    let executable =
        std::env::current_exe().map_err(|error| AppError::io("resolve Sandy executable", error))?;
    let status = Command::new(executable)
        .arg("__bootstrap")
        .arg("--manifest")
        .arg(&manifest_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| AppError::io("start Sandy bootstrap", error))?;

    if let Some(code) = status.code() {
        return Ok(code);
    }
    Ok(status.signal().map_or(1, |signal| 128 + signal))
}

fn deduplicate_grants(grants: &mut Vec<FileGrant>) {
    grants.sort_by(|left, right| {
        (left.path.as_str(), left.scope, left.access).cmp(&(
            right.path.as_str(),
            right.scope,
            right.access,
        ))
    });
    grants.dedup_by(|left, right| left == right);
}
