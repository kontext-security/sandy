use std::{
    fs::OpenOptions,
    io::Write as _,
    os::unix::{fs::OpenOptionsExt as _, process::ExitStatusExt as _},
    process::{Command, Stdio},
};

use sandy_core::{
    AccessMode, CommandSpec, ExecutableGrant, FileGrant, LaunchManifestV2, MANIFEST_SCHEMA_V2,
    NetworkPolicy, OsValue, PathScope, SandboxPolicy, ValidatedLaunch, encode_launch,
};
use serde_json::json;
use tempfile::Builder;

const DRY_RUN_SCHEMA_VERSION: u32 = 4;

use crate::{
    cli::RunArgs,
    error::AppError,
    integration::{IntegrationMode, RuntimeControls, kontext, numbat},
    profile,
    resolve::{
        default_ca_bundle, grant, resolve_command, resolve_paths, resolve_policy, runtime,
        sanitized_environment,
    },
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
        &paths.user.protected,
    )?);
    if let Some(parent) = command.program.parent() {
        files.push(grant(
            parent,
            AccessMode::Read,
            PathScope::Subtree,
            &paths.user.protected,
        )?);
    }
    files.push(grant(
        session.path(),
        AccessMode::ReadWrite,
        PathScope::Subtree,
        &paths.user.protected,
    )?);
    let ca_bundle = if arguments.block_net {
        None
    } else {
        default_ca_bundle()
    };
    let ca_bundle = ca_bundle
        .map(|path| {
            grant(
                path,
                AccessMode::Read,
                PathScope::Exact,
                &paths.user.protected,
            )
        })
        .transpose()?;
    if let Some(bundle) = &ca_bundle {
        files.push(bundle.clone());
    }
    files.extend(selected.grants(&paths.user)?);
    for path in &arguments.read {
        files.push(grant(
            path,
            AccessMode::Read,
            PathScope::Subtree,
            &paths.user.protected,
        )?);
    }
    for path in &arguments.read_write {
        files.push(grant(
            path,
            AccessMode::ReadWrite,
            PathScope::Subtree,
            &paths.user.protected,
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
    let hook_sources = selected.hook_sources(&paths.user)?;
    let (hook_source_grants, hook_source_protections) =
        selected.hook_source_policy(&hook_sources, &paths.user)?;
    files.extend(hook_source_grants);
    let mut controls = vec![
        kontext::resolve(&hook_sources, kontext_mode, &paths.user)?,
        numbat::resolve(&hook_sources, numbat_mode, &paths.user)?,
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
    let mut write_protections = selected.protected_write_paths(&paths.user)?;
    write_protections.extend(hook_source_protections);
    let network = if arguments.block_net {
        NetworkPolicy::BlockAll
    } else {
        NetworkPolicy::AllowAll
    };
    let mut intent = runtime::macos::add_to(SandboxPolicy::new(network));
    for file in files {
        intent = intent.grant(file.path.as_path(), file.access, file.scope);
    }
    for path in selected.protected_paths(&paths.user) {
        intent = intent.deny_subtree(path.as_path());
    }
    for protection in write_protections {
        if protection.scope != PathScope::Exact {
            return Err(AppError::Launch(
                "base policy contains an unsupported recursive write protection".to_owned(),
            ));
        }
        intent = intent.deny_write_exact(protection.path.as_path());
    }
    let mut policy = resolve_policy(intent, &paths.user.protected)?;
    runtime_controls.apply_to(&mut policy)?;
    policy.executables.extend(
        policy
            .files
            .iter()
            .filter(|grant| !grant.path.is_root())
            .map(|grant| ExecutableGrant {
                path: grant.path.clone(),
                scope: grant.scope,
            }),
    );
    policy.normalize();

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
            "allow_subprocesses": validated.manifest().policy.allow_subprocesses,
            "file_metadata": validated.manifest().policy.file_metadata,
            "runtime_compatibility": validated.manifest().policy.runtime_compatibility,
            "file_grants": validated.manifest().policy.files,
            "executable_grants": validated.manifest().policy.executables,
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
