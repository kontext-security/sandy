use std::{
    fs::OpenOptions,
    io::Write as _,
    os::unix::{fs::OpenOptionsExt as _, process::ExitStatusExt as _},
    process::{Command, Stdio},
};

use sandy_core::{
    AccessMode, CommandSpec, FileGrant, LaunchManifestV2, MANIFEST_SCHEMA_V2, NetworkPolicy,
    OsValue, PathScope, PolicySpec, ValidatedLaunch, encode_launch,
};
use serde_json::json;
use tempfile::Builder;

const DRY_RUN_SCHEMA_VERSION: u32 = 2;

use crate::{
    cli::RunArgs,
    error::AppError,
    integration::{IntegrationMode, RuntimeControls, kontext, numbat},
    profile,
    resolve::{default_ca_bundle, grant, resolve_command, resolve_paths, sanitized_environment},
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
    let ca_bundle = if arguments.block_net {
        None
    } else {
        default_ca_bundle()
    };
    let ca_bundle = ca_bundle
        .map(|path| grant(path, AccessMode::Read, PathScope::Exact, &paths.protected))
        .transpose()?;
    if let Some(bundle) = &ca_bundle {
        files.push(bundle.clone());
    }
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

    let kontext_mode = if arguments.kontext {
        IntegrationMode::Required
    } else {
        IntegrationMode::Detect
    };
    let numbat_mode = if arguments.numbat {
        IntegrationMode::Required
    } else {
        IntegrationMode::Detect
    };
    let hook_sources = selected.hook_sources(&paths)?;
    let (hook_source_grants, hook_source_protections) =
        selected.hook_source_policy(&hook_sources, &paths)?;
    files.extend(hook_source_grants);
    let mut controls = vec![
        kontext::resolve(&hook_sources, kontext_mode, &paths)?,
        numbat::resolve(&hook_sources, numbat_mode, &paths)?,
    ];
    if let Some(port) = arguments.numbat_collector {
        controls.push(numbat::collector(port)?);
    }
    let runtime_controls = RuntimeControls::new(controls);
    for control in runtime_controls.iter() {
        if let Some(reason) = control.unavailable_reason() {
            eprintln!(
                "sandy: optional {} runtime control unavailable; continuing without it: {reason}",
                control.service()
            );
        }
    }
    let mut write_protections = selected.protected_write_paths(&paths)?;
    write_protections.extend(hook_source_protections);
    let network = if arguments.block_net {
        NetworkPolicy::BlockAll
    } else {
        NetworkPolicy::AllowAll
    };
    write_protections.sort();
    write_protections.dedup();
    let protected_paths = selected.protected_paths(&paths);
    let mut policy = PolicySpec {
        files,
        protected_paths,
        write_protections,
        unix_sockets: Vec::new(),
        local_host_tcp: Vec::new(),
        network,
    };
    runtime_controls.apply_to(&mut policy)?;
    normalize_policy(&mut policy);

    let manifest = LaunchManifestV2 {
        schema_version: MANIFEST_SCHEMA_V2,
        command: CommandSpec {
            program: OsValue::from_os_str(command.program.as_os_str()),
            arguments: command
                .arguments
                .iter()
                .map(|value| OsValue::from_os_str(value))
                .collect(),
        },
        working_directory: paths.working_directory,
        environment: sanitized_environment(
            session.path(),
            ca_bundle.as_ref().map(|bundle| bundle.path.as_path()),
        ),
        policy,
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
            "dry_run_schema_version": DRY_RUN_SCHEMA_VERSION,
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
            "local_host_tcp_grants": validated.manifest().policy.local_host_tcp,
            "runtime_controls": runtime_controls
                .iter()
                .map(|control| json!({
                    "service": control.service(),
                    "enabled": control.is_active(),
                    "version": control.version(),
                }))
                .collect::<Vec<_>>(),
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

fn normalize_policy(policy: &mut PolicySpec) {
    policy.files.sort();
    policy.files.dedup();
    policy.unix_sockets.sort();
    policy.unix_sockets.dedup();
    policy.local_host_tcp.sort();
    policy.local_host_tcp.dedup();
    policy.write_protections.sort();
    policy.write_protections.dedup();
}
