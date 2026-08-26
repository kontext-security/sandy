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
    if !cfg!(target_os = "macos") {
        return Err(AppError::UnsupportedPlatform);
    }

    let executable =
        env::current_exe().map_err(|error| AppError::io("resolve Sandy executable", error))?;
    let status = Command::new(executable)
        .arg("__probe")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .map_err(|error| AppError::io("run Seatbelt support probe", error))?;
    if !status.success() {
        return Err(AppError::Probe(
            "the macOS Seatbelt runtime probe failed; Sandy cannot enforce a sandbox here"
                .to_owned(),
        ));
    }
    println!("Seatbelt enforcement: available");

    let resolved = if arguments.kontext || arguments.numbat {
        let selected = profile::select(Some(&"claude".to_owned()), std::ffi::OsStr::new("claude"))?;
        let paths = resolve_user_paths(selected.protected_templates())?;
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
    #[cfg(not(target_os = "macos"))]
    {
        Err(AppError::UnsupportedPlatform)
    }
}
