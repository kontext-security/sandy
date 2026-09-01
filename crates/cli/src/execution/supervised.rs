use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::{fs::OpenOptionsExt as _, process::ExitStatusExt as _},
    process::{Command, Stdio},
};

use sandy_core::{
    AccessMode, CommandSpec, LaunchManifestV2, MANIFEST_SCHEMA_V2, NetworkPolicy, OsValue,
    PathScope, ValidatedLaunch, encode_launch,
};
use serde_json::json;
use tempfile::Builder;

const DRY_RUN_SCHEMA_VERSION: u32 = 7;

use crate::{
    agent,
    cli::RunArgs,
    error::AppError,
    integration::RuntimeControls,
    policy_file,
    resolve::{
        default_ca_bundle, grant, resolve_command, resolve_paths, resolve_policy_at, runtime,
        sanitized_environment,
    },
};

#[cfg(target_os = "macos")]
use crate::integration::{IntegrationMode, kontext, numbat};

pub(crate) fn run(arguments: RunArgs) -> Result<i32, AppError> {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return Err(AppError::UnsupportedPlatform);
    }
    #[cfg(target_os = "linux")]
    if arguments.kontext || arguments.numbat {
        return Err(AppError::Launch(
            "runtime-control integrations are not supported by the Linux CLI".to_owned(),
        ));
    }
    #[cfg(target_os = "linux")]
    if arguments.numbat_collector.is_some() {
        return Err(AppError::Launch(
            "local-host TCP exceptions are not supported by the Linux backend".to_owned(),
        ));
    }
    let command = resolve_command(&arguments.target)?;
    let uses_policy_file = arguments.policy_file.is_some();
    let selected = agent::select(arguments.agent.as_deref(), &command.requested_name)?;
    if !uses_policy_file && selected.detected() {
        eprintln!(
            "sandy: applying detected agent preset '{}' (override with --agent)",
            selected.name()
        );
    }
    let protected_templates = if uses_policy_file {
        &[]
    } else {
        selected.protected_templates()
    };
    let mut paths = resolve_paths(protected_templates)?;
    let loaded_policy = arguments
        .policy_file
        .as_deref()
        .map(|path| policy_file::load(path, paths.working_directory.as_path()))
        .transpose()?;
    let preset_protected_paths = if uses_policy_file {
        Vec::new()
    } else {
        selected.protected_paths(&paths.user)?
    };
    for protected in preset_protected_paths {
        if !paths.user.protected.contains(&protected) {
            paths.user.protected.push(protected);
        }
    }
    let session = Builder::new()
        .prefix("sandy-")
        .tempdir()
        .map_err(|error| AppError::io("create private Sandy session", error))?;

    let (policy, policy_source_paths, network) = match loaded_policy {
        Some(loaded) => {
            let network = loaded.network();
            let (policy, source_paths) = loaded.into_parts();
            if !sandy_core::policy_allows_subprocesses(&policy) {
                return Err(AppError::PolicyFile(
                    "CLI execution requires allow_subprocesses to be true; use the Rust API for a current-process policy that disables execution"
                        .to_owned(),
                ));
            }
            (policy, source_paths, network)
        }
        None => {
            let network = if arguments.block_net {
                NetworkPolicy::BlockAll
            } else {
                NetworkPolicy::AllowAll
            };
            (selected.policy(network, &paths.user)?, Vec::new(), network)
        }
    };
    let mut intent = runtime::intent(policy);
    intent = intent.grant_file_and_execute(
        paths.working_directory.as_path(),
        AccessMode::ReadWrite,
        PathScope::Subtree,
    );
    intent =
        intent.grant_file_and_execute(command.program.clone(), AccessMode::Read, PathScope::Exact);
    if let Some(parent) = command.program.parent() {
        intent = intent.grant_file_and_execute(parent, AccessMode::Read, PathScope::Subtree);
    }
    intent =
        intent.grant_file_and_execute(session.path(), AccessMode::ReadWrite, PathScope::Subtree);
    let ca_bundle = if network == NetworkPolicy::BlockAll {
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
        intent = intent.grant_resolved_file(bundle.clone());
    }
    for path in &arguments.read {
        intent = intent.grant_file(path, AccessMode::Read, grant_scope(path)?);
    }
    for path in &arguments.read_write {
        intent = intent.grant_file(path, AccessMode::ReadWrite, read_write_grant_scope(path)?);
    }
    for path in &arguments.execute {
        intent = intent.allow_execute(path, grant_scope(path)?);
    }

    #[cfg(target_os = "macos")]
    let (mut intent, hook_source_protections, runtime_controls) = {
        let kontext_mode = if arguments.kontext {
            IntegrationMode::Required
        } else if uses_policy_file {
            IntegrationMode::Disabled
        } else {
            IntegrationMode::Detect
        };
        let numbat_mode = if arguments.numbat {
            IntegrationMode::Required
        } else if uses_policy_file {
            IntegrationMode::Disabled
        } else {
            IntegrationMode::Detect
        };
        let hook_sources = if kontext_mode.is_disabled() && numbat_mode.is_disabled() {
            Vec::new()
        } else {
            selected.hook_sources(&paths.user)?
        };
        let (next_intent, hook_source_protections) = if hook_sources.is_empty() {
            (intent, Vec::new())
        } else {
            selected.contribute_hook_source_policy(intent, &hook_sources, &paths.user)?
        };
        let mut controls = vec![
            kontext::resolve(&hook_sources, kontext_mode, &paths.user)?,
            numbat::resolve(&hook_sources, numbat_mode, &paths.user)?,
        ];
        if let Some(port) = arguments.numbat_collector {
            controls.push(numbat::collector(port)?);
        }
        (
            next_intent,
            hook_source_protections,
            RuntimeControls::new(controls),
        )
    };
    #[cfg(not(target_os = "macos"))]
    let (mut intent, hook_source_protections, runtime_controls) = (
        intent,
        Vec::<sandy_core::WriteProtection>::new(),
        RuntimeControls::default(),
    );
    for control in runtime_controls.iter() {
        if let Some(reason) = control.unavailable_reason() {
            eprintln!(
                "sandy: optional {} runtime control unavailable; continuing without it: {reason}",
                control.service()
            );
        }
    }
    if uses_policy_file {
        intent = policy_file::protect_source(intent, &policy_source_paths);
    }
    for protection in hook_source_protections {
        if protection.scope != PathScope::Exact {
            return Err(AppError::Launch(
                "base policy contains an unsupported recursive write protection".to_owned(),
            ));
        }
        intent = intent.deny_resolved_write(protection);
    }
    let draft = resolve_policy_at(intent, &paths.user.protected, &paths.working_directory)?;
    let draft = runtime_controls.contribute(draft)?;
    let policy = draft.finish()?.into_spec();
    #[cfg(target_os = "linux")]
    if !policy.unix_sockets.is_empty() {
        return Err(AppError::Launch(
            "exact external Unix-socket grants are not enabled for the Linux CLI".to_owned(),
        ));
    }

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
    let native_policy = json!({
        "backend": "seatbelt",
        "details": sandy_seatbelt::compile(validated.policy())?.source(),
    });
    #[cfg(target_os = "linux")]
    let native_policy = {
        let plan = sandy_linux::plan(validated.policy())?;
        let landlock_abi = plan.required_landlock_abi();
        json!({
            "backend": "linux",
            "landlock_abi": landlock_abi,
        })
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let native_policy = json!({"backend": "unsupported"});

    if arguments.dry_run {
        let policy_source = if uses_policy_file {
            json!({ "kind": "policy_file" })
        } else {
            json!({ "kind": "agent_default" })
        };
        let output = json!({
            "dry_run_schema_version": DRY_RUN_SCHEMA_VERSION,
            "command": command.program.to_string_lossy(),
            "arguments": command.arguments.iter().map(|value| value.to_string_lossy()).collect::<Vec<_>>(),
            "working_directory": validated.manifest().working_directory.as_str(),
            "agent": {
                "name": selected.name(),
                "detected": selected.detected(),
            },
            "policy_source": policy_source,
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
            "native_policy": native_policy,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|error| AppError::Launch(format!("encode dry-run output: {error}")))?
        );
        return Ok(0);
    }

    #[cfg(target_os = "linux")]
    validate_linux_write_protections(validated.policy(), selected.name())?;

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
        .env_clear()
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

fn grant_scope(path: &std::path::Path) -> Result<PathScope, AppError> {
    let metadata =
        fs::metadata(path).map_err(|error| AppError::io("inspect command-line grant", error))?;
    Ok(if metadata.is_dir() {
        PathScope::Subtree
    } else {
        PathScope::Exact
    })
}

fn read_write_grant_scope(path: &std::path::Path) -> Result<PathScope, AppError> {
    let scope = grant_scope(path)?;
    #[cfg(target_os = "linux")]
    if scope == PathScope::Exact {
        return Err(AppError::Launch(
            "--read-write on Linux requires an existing directory; grant the containing directory instead"
                .to_owned(),
        ));
    }
    Ok(scope)
}

#[cfg(target_os = "linux")]
fn validate_linux_write_protections(
    policy: &sandy_core::ValidatedPolicy,
    agent_name: &str,
) -> Result<(), AppError> {
    let spec = policy.spec();
    for protection in &spec.write_protections {
        let visible_writable = spec.files.iter().any(|grant| {
            grant.access == AccessMode::ReadWrite
                && (grant.path == protection.path
                    || (grant.scope == PathScope::Subtree
                        && protection.path.as_path().starts_with(grant.path.as_path())))
        });
        if !visible_writable {
            continue;
        }
        match fs::symlink_metadata(protection.path.as_path()) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(AppError::Launch(format!(
                    "Linux agent preset {agent_name:?} requires its write-protected files to exist before launch; initialize the agent configuration outside Sandy and retry"
                )));
            }
            Err(error) => {
                return Err(AppError::io(
                    "inspect Linux write-protected agent path",
                    error,
                ));
            }
        }
    }
    Ok(())
}
