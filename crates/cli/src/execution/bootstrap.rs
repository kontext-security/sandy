use std::{fs, os::unix::process::CommandExt as _, process::Command};

use sandy_core::{MAX_WIRE_BYTES, decode_launch};

use crate::{cli::BootstrapArgs, error::AppError};

pub(crate) fn run(arguments: BootstrapArgs) -> Result<i32, AppError> {
    let metadata = fs::metadata(&arguments.manifest)
        .map_err(|error| AppError::io("inspect launch manifest", error))?;
    if metadata.len() > MAX_WIRE_BYTES as u64 {
        return Err(AppError::Launch(
            "launch manifest exceeds the bootstrap limit".to_owned(),
        ));
    }
    let encoded = fs::read(&arguments.manifest)
        .map_err(|error| AppError::io("read launch manifest", error))?;
    let launch = decode_launch(&encoded)?;
    fs::remove_file(&arguments.manifest)
        .map_err(|error| AppError::io("remove consumed launch manifest", error))?;

    // Build every owned command/environment value before sandboxing. The
    // post-apply path is intentionally limited to the native apply call and
    // exec so allocator, filesystem, and environment discovery cannot occur
    // in the restricted bootstrap.
    let manifest = launch.manifest();
    let program = manifest.command.program.to_os_string();
    let mut command = Command::new(&program);
    command.args(
        manifest
            .command
            .arguments
            .iter()
            .map(sandy_core::OsValue::to_os_string),
    );
    command.current_dir(manifest.working_directory.as_path());
    command.env_clear();
    for entry in &manifest.environment {
        command.env(entry.key.to_os_string(), entry.value.to_os_string());
    }

    #[cfg(target_os = "macos")]
    {
        let profile = sandy_seatbelt::compile(launch.policy())?;
        sandy_seatbelt::apply(&profile)?;
    }
    #[cfg(target_os = "linux")]
    {
        let primary_executable = crate::resolve::absolute_if_utf8(std::path::Path::new(&program))?;
        let plan = sandy_linux::plan(launch.policy())?;
        let prepared = sandy_linux::prepare_foreground_launch(
            plan,
            &manifest.working_directory,
            &primary_executable,
        )?;
        sandy_linux::apply(prepared)?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        return Err(AppError::UnsupportedPlatform);
    }

    Err(AppError::Exec(command.exec()))
}
