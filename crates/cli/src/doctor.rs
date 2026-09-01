use std::{
    env,
    process::{Command, Stdio},
};

use crate::{
    agent,
    cli::DoctorArgs,
    error::AppError,
    integration::{IntegrationMode, kontext, numbat},
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
        #[cfg(target_os = "linux")]
        let message = linux_probe_failure_message();
        #[cfg(not(target_os = "linux"))]
        let message =
            "the native runtime probe failed; Sandy cannot enforce a sandbox here".to_owned();
        return Err(AppError::Probe(message));
    }
    #[cfg(target_os = "macos")]
    println!("macOS enforcement: available");
    #[cfg(target_os = "linux")]
    println!("Linux enforcement: available");

    let resolved = if arguments.kontext || arguments.numbat {
        let selected = agent::select(Some("claude"), std::ffi::OsStr::new("claude"))?;
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
            let selected = agent::select(Some(name), std::ffi::OsStr::new(name))?;
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

#[cfg(target_os = "linux")]
fn linux_probe_failure_message() -> String {
    let apparmor_restricts_user_namespaces =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .is_ok_and(|value| value.trim() == "1");
    if apparmor_restricts_user_namespaces {
        return "the native runtime probe may have failed because AppArmor restricts unprivileged user namespaces; ask the host administrator to authorize user namespaces for the Sandy executable (the CI-only fallback of setting kernel.apparmor_restrict_unprivileged_userns=0 weakens this restriction system-wide)"
            .to_owned();
    }
    "the native runtime probe failed; Sandy requires Linux 6.12 or a vendor kernel with Landlock ABI 6, unprivileged user/mount/IPC namespaces, and the modern mount API"
        .to_owned()
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
