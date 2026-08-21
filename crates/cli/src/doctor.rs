use std::{
    env,
    process::{Command, Stdio},
};

use crate::{
    cli::DoctorArgs, error::AppError, integration::kontext, profile::Preset, resolve::resolve_paths,
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
        return Err(AppError::Kontext(
            "the macOS Seatbelt runtime probe failed; Sandy cannot enforce a sandbox here"
                .to_owned(),
        ));
    }
    println!("Seatbelt enforcement: available");

    if arguments.kontext {
        let paths = resolve_paths()?;
        let integration = kontext::resolve(Preset::Claude, true, &paths)?;
        let version = integration.version.as_deref().unwrap_or("unknown");
        println!("Kontext integration: available ({version})");
    } else {
        println!("Kontext integration: not checked (optional)");
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
