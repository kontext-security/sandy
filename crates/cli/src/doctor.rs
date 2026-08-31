use std::{
    env,
    process::{Command, Stdio},
};

use crate::{
    cli::DoctorArgs,
    error::AppError,
    integration::{IntegrationMode, kontext, numbat},
    profile,
    resolve::resolve_user_paths,
};

pub(crate) fn run(arguments: DoctorArgs) -> Result<i32, AppError> {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return Err(AppError::UnsupportedPlatform);
    }
    #[cfg(target_os = "linux")]
    if arguments.kontext || arguments.numbat {
        return Err(AppError::Launch(
            "runtime-control integrations are not supported by the Linux CLI".to_owned(),
        ));
    }

    let executable =
        env::current_exe().map_err(|error| AppError::io("resolve Sandy executable", error))?;
    let status = Command::new(executable)
        .arg("__probe")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .map_err(|error| AppError::io("run native sandbox support probe", error))?;
    if !status.success() {
        return Err(AppError::Probe(
            "the native runtime probe failed; Sandy cannot enforce a sandbox here".to_owned(),
        ));
    }
    #[cfg(target_os = "macos")]
    println!("macOS enforcement: available");
    #[cfg(target_os = "linux")]
    println!("Linux enforcement: available");

    let resolved = if arguments.kontext || arguments.numbat {
        let selected = profile::select(Some(&"claude".to_owned()), std::ffi::OsStr::new("claude"))?;
        let protected_templates = selected.inherited_protected_templates();
        let paths = resolve_user_paths(&protected_templates)?;
        Some((selected, paths))
    } else {
        None
    };

    if arguments.kontext {
        let (selected, paths) = resolved.as_ref().ok_or_else(|| {
            AppError::Launch("doctor integration paths were not resolved".to_owned())
        })?;
        let integration = kontext::resolve(
            &selected.hook_sources(paths)?,
            IntegrationMode::Required,
            paths,
        )?;
        let version = integration.version().unwrap_or("unknown");
        println!("Kontext integration: available ({version})");
    } else {
        println!("Kontext integration: not checked (optional)");
    }

    if arguments.numbat {
        let (claude, paths) = resolved.as_ref().ok_or_else(|| {
            AppError::Launch("doctor integration paths were not resolved".to_owned())
        })?;
        let mut hook_sources = claude.hook_sources(paths)?;
        for name in ["codex", "opencode"] {
            let selected = profile::select(Some(&name.to_owned()), std::ffi::OsStr::new(name))?;
            hook_sources.extend(selected.hook_sources(paths)?);
        }
        let integration = numbat::resolve(&hook_sources, IntegrationMode::Required, paths)?;
        println!("Numbat integration: available");
        debug_assert!(integration.is_active());
    } else {
        println!("Numbat integration: not checked (optional)");
    }
    Ok(0)
}

pub(crate) fn probe_child() -> Result<i32, AppError> {
    #[cfg(target_os = "macos")]
    {
        sandy_seatbelt::probe()?;
        Ok(0)
    }
    #[cfg(target_os = "linux")]
    {
        use std::fs;

        use sandy_core::{
            AbsolutePath, AccessMode, FileGrant, NetworkPolicy, PathScope, PolicySpec,
            ValidatedPolicy,
        };

        let working_directory = env::current_dir()
            .and_then(fs::canonicalize)
            .map_err(|error| AppError::io("resolve probe working directory", error))?;
        let working_directory = AbsolutePath::new(
            working_directory
                .to_str()
                .ok_or_else(|| AppError::NonUtf8Path(working_directory.clone()))?
                .to_owned(),
        )
        .map_err(|_| AppError::Launch("probe working directory is invalid".to_owned()))?;
        let policy = ValidatedPolicy::try_from(PolicySpec {
            files: vec![FileGrant {
                path: working_directory.clone(),
                access: AccessMode::Read,
                scope: PathScope::Subtree,
            }],
            network: NetworkPolicy::BlockAll,
            ..PolicySpec::default()
        })?;
        let plan = sandy_linux::plan(&policy)?;
        let prepared = sandy_linux::prepare(plan, &working_directory)?;
        sandy_linux::apply(prepared)?;
        Ok(0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(AppError::UnsupportedPlatform)
    }
}
