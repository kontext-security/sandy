#[cfg(target_os = "linux")]
mod linux {
    use std::{
        env, fs,
        net::{TcpListener, TcpStream, UdpSocket},
        os::{
            unix::fs::PermissionsExt as _,
            unix::net::{UnixListener, UnixStream},
        },
        process::{Child, Command, ExitStatus},
        thread,
        time::{Duration, Instant},
    };

    use sandy_core::{
        AbsolutePath, AccessMode, ExecutableGrant, FileGrant, NetworkPolicy, PathScope, PolicySpec,
        RuntimeCompatibility, ValidatedPolicy, WriteProtection,
    };

    const CHILD_MODE: &str = "SANDY_LINUX_LIVE_CHILD";
    const DEVICE_CHILD: &str = "SANDY_LINUX_DEVICE_CHILD";
    const PROCESS_CHILD: &str = "SANDY_LINUX_PROCESS_CHILD";
    const REPLACEMENT_CHILD: &str = "SANDY_LINUX_REPLACEMENT_CHILD";
    const EXPECT_UNSUPPORTED: &str = "SANDY_LINUX_EXPECT_UNSUPPORTED";
    const HOST_IPC_ID: &str = "SANDY_LINUX_HOST_IPC_ID";
    const HOST_KEY_ID: &str = "SANDY_LINUX_HOST_KEY_ID";
    const WORKSPACE: &str = "SANDY_LINUX_LIVE_WORKSPACE";
    const TEST_KEY_PAYLOAD: &[u8] = b"host-session-key";

    pub(super) fn run() -> Result<(), Box<dyn std::error::Error>> {
        if env::var_os(CHILD_MODE).is_some() {
            return child_checks();
        }
        if env::var_os(DEVICE_CHILD).is_some() {
            return exact_device_child();
        }
        if env::var_os(PROCESS_CHILD).is_some() {
            return disabled_process_child();
        }
        if env::var_os(REPLACEMENT_CHILD).is_some() {
            return replacement_child();
        }
        if env::var_os(EXPECT_UNSUPPORTED).is_some() {
            return restricted_host_is_rejected_before_enforcement();
        }

        exact_directory_grants_are_rejected_before_enforcement()?;
        exact_device_grants_do_not_expose_adjacent_devices()?;
        host_noexec_is_never_weakened()?;
        write_protected_hard_link_aliases_are_rejected()?;
        mount_source_replacement_is_rejected()?;
        disabled_process_mode_preserves_threads_only()?;

        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace)?;
        fs::write(workspace.join("readable.txt"), "visible")?;
        fs::write(workspace.join("locked.txt"), "locked")?;
        for name in ["allowed-true", "data-true", "allowed-sleep"] {
            let path = workspace.join(name);
            let source = if name == "allowed-sleep" {
                "/bin/sleep"
            } else {
                "/bin/true"
            };
            fs::copy(source, &path)?;
            let mut permissions = fs::metadata(&path)?.permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions)?;
        }
        fs::write(root.path().join("outside.txt"), "hidden")?;

        let host_ipc = sandy_linux::live_test_support::create_private_message_queue()?;
        let host_key = sandy_linux::live_test_support::create_session_test_key(TEST_KEY_PAYLOAD)?;
        let mut command = Command::new(env::current_exe()?);
        command
            .env(CHILD_MODE, "1")
            .env(WORKSPACE, &workspace)
            .env(HOST_IPC_ID, host_ipc.to_string())
            .env(HOST_KEY_ID, host_key.to_string());
        let status = status_with_timeout(&mut command);
        let cleanup = sandy_linux::live_test_support::remove_message_queue(host_ipc);
        let status = status?;
        cleanup?;
        if !status.success() {
            return Err("sacrificial sandbox child failed".into());
        }
        Ok(())
    }

    fn exact_device_grants_do_not_expose_adjacent_devices() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace)?;
        let mut command = Command::new(env::current_exe()?);
        command.env(DEVICE_CHILD, "1").env(WORKSPACE, &workspace);
        let status = status_with_timeout(&mut command)?;
        if !status.success() {
            return Err("exact device child failed".into());
        }
        Ok(())
    }

    fn exact_device_child() -> Result<(), Box<dyn std::error::Error>> {
        let workspace = absolute_from_environment(WORKSPACE)?;
        let null_device = absolute(std::path::Path::new("/dev/null"))?;
        let policy = ValidatedPolicy::try_from(PolicySpec {
            files: vec![
                FileGrant {
                    path: workspace.clone(),
                    access: AccessMode::ReadWrite,
                    scope: PathScope::Subtree,
                },
                FileGrant {
                    path: null_device,
                    access: AccessMode::ReadWrite,
                    scope: PathScope::Exact,
                },
            ],
            network: NetworkPolicy::AllowAll,
            ..PolicySpec::default()
        })?;
        let prepared = sandy_linux::prepare(sandy_linux::plan(&policy)?, &workspace)?;
        sandy_linux::apply(prepared)?;

        fs::write("/dev/null", b"discarded")?;
        if fs::metadata("/dev/zero").is_ok() {
            return Err("adjacent device remained visible".into());
        }
        Ok(())
    }

    fn mount_source_replacement_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new(env::current_exe()?);
        command.env(REPLACEMENT_CHILD, "1");
        let status = status_with_timeout(&mut command)?;
        if !status.success() {
            return Err("mount source replacement child failed".into());
        }
        Ok(())
    }

    fn replacement_child() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace_path = root.path().join("workspace");
        fs::create_dir(&workspace_path)?;
        let workspace = absolute(&workspace_path)?;
        let policy = ValidatedPolicy::try_from(PolicySpec {
            files: vec![FileGrant {
                path: workspace.clone(),
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }],
            network: NetworkPolicy::BlockAll,
            ..PolicySpec::default()
        })?;
        let prepared = sandy_linux::prepare(sandy_linux::plan(&policy)?, &workspace)?;

        fs::rename(&workspace_path, root.path().join("replaced"))?;
        fs::create_dir(&workspace_path)?;
        let error = sandy_linux::apply(prepared)
            .err()
            .ok_or("replaced mount source unexpectedly applied")?;
        if error.kind() != sandy_linux::LinuxErrorKind::EnforcementFailed {
            return Err("mount replacement returned the wrong error class".into());
        }
        Ok(())
    }

    fn host_noexec_is_never_weakened() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let executable = std::path::Path::new("/proc/version");
        if !executable.is_file() {
            return Err("host procfs has no regular version file".into());
        }
        let workspace = absolute(root.path())?;
        let policy = ValidatedPolicy::try_from(PolicySpec {
            files: vec![
                FileGrant {
                    path: workspace.clone(),
                    access: AccessMode::Read,
                    scope: PathScope::Subtree,
                },
                FileGrant {
                    path: absolute(executable)?,
                    access: AccessMode::Read,
                    scope: PathScope::Exact,
                },
            ],
            executables: vec![ExecutableGrant {
                path: absolute(executable)?,
                scope: PathScope::Exact,
            }],
            ..PolicySpec::default()
        })?;
        let error = sandy_linux::prepare(sandy_linux::plan(&policy)?, &workspace)
            .err()
            .ok_or("executable grant on a host noexec mount was unexpectedly accepted")?;
        if error.kind() != sandy_linux::LinuxErrorKind::Unsupported {
            return Err("host noexec restriction returned the wrong error class".into());
        }
        Ok(())
    }

    fn disabled_process_mode_preserves_threads_only() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace)?;
        let mut command = Command::new(env::current_exe()?);
        command.env(PROCESS_CHILD, "1").env(WORKSPACE, &workspace);
        let status = status_with_timeout(&mut command)?;
        if !status.success() {
            return Err("disabled process-mode child failed".into());
        }
        Ok(())
    }

    fn write_protected_hard_link_aliases_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace_path = root.path().join("workspace");
        fs::create_dir(&workspace_path)?;
        let protected_path = workspace_path.join("protected.txt");
        fs::write(&protected_path, "protected")?;
        fs::hard_link(&protected_path, workspace_path.join("alias.txt"))?;
        let workspace = absolute(&workspace_path)?;
        let policy = ValidatedPolicy::try_from(PolicySpec {
            files: vec![FileGrant {
                path: workspace.clone(),
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }],
            write_protections: vec![WriteProtection {
                path: absolute(&protected_path)?,
                scope: PathScope::Exact,
            }],
            ..PolicySpec::default()
        })?;
        let error = sandy_linux::prepare(sandy_linux::plan(&policy)?, &workspace)
            .err()
            .ok_or("write-protected hard-link alias was unexpectedly accepted")?;
        if error.kind() != sandy_linux::LinuxErrorKind::Unsupported {
            return Err("hard-link alias returned the wrong error class".into());
        }
        Ok(())
    }

    fn disabled_process_child() -> Result<(), Box<dyn std::error::Error>> {
        let workspace = absolute_from_environment(WORKSPACE)?;
        let policy = ValidatedPolicy::try_from(PolicySpec {
            files: vec![FileGrant {
                path: workspace.clone(),
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }],
            allow_subprocesses: false,
            ..PolicySpec::default()
        })?;
        let prepared = sandy_linux::prepare(sandy_linux::plan(&policy)?, &workspace)?;
        sandy_linux::apply(prepared)?;

        if !matches!(thread::spawn(|| 23).join(), Ok(23)) {
            return Err("thread creation was not preserved".into());
        }
        if Command::new("/bin/true").spawn().is_ok() {
            return Err("process creation remained available".into());
        }
        Ok(())
    }

    fn absolute_from_environment(name: &str) -> Result<AbsolutePath, Box<dyn std::error::Error>> {
        let path = fs::canonicalize(env::var_os(name).ok_or("missing test path")?)?;
        absolute(&path)
    }

    fn absolute(path: &std::path::Path) -> Result<AbsolutePath, Box<dyn std::error::Error>> {
        Ok(AbsolutePath::new(
            path.to_str().ok_or("test path is not UTF-8")?.to_owned(),
        )?)
    }

    fn restricted_host_is_rejected_before_enforcement() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = AbsolutePath::new(
            fs::canonicalize(root.path())?
                .to_str()
                .ok_or("path is not UTF-8")?
                .to_owned(),
        )?;
        let policy = ValidatedPolicy::try_from(PolicySpec {
            files: vec![FileGrant {
                path: path.clone(),
                access: AccessMode::Read,
                scope: PathScope::Subtree,
            }],
            network: NetworkPolicy::BlockAll,
            ..PolicySpec::default()
        })?;
        let error = sandy_linux::prepare(sandy_linux::plan(&policy)?, &path)
            .err()
            .ok_or("restricted host unexpectedly passed preparation")?;
        if error.kind() != sandy_linux::LinuxErrorKind::Unsupported {
            return Err("restricted host returned the wrong error class".into());
        }
        Ok(())
    }

    fn child_checks() -> Result<(), Box<dyn std::error::Error>> {
        let workspace = fs::canonicalize(env::var_os(WORKSPACE).ok_or("missing workspace")?)?;
        let workspace = AbsolutePath::new(
            workspace
                .to_str()
                .ok_or("workspace path is not UTF-8")?
                .to_owned(),
        )?;
        let locked = AbsolutePath::new(format!("{}/locked.txt", workspace.as_str()))?;
        let allowed_true = AbsolutePath::new(format!("{}/allowed-true", workspace.as_str()))?;
        let allowed_sleep = AbsolutePath::new(format!("{}/allowed-sleep", workspace.as_str()))?;
        let data_true = AbsolutePath::new(format!("{}/data-true", workspace.as_str()))?;
        let system_libraries = absolute(std::path::Path::new("/usr/lib"))?;
        let loader = absolute(&fs::canonicalize(dynamic_loader())?)?;
        let primary_executable = absolute(&env::current_exe()?)?;
        let host_ipc = env::var(HOST_IPC_ID)?.parse::<i32>()?;
        let host_key = env::var(HOST_KEY_ID)?.parse::<i32>()?;
        if !sandy_linux::live_test_support::message_queue_is_visible(host_ipc)? {
            return Err("host IPC fixture was not inherited before enforcement".into());
        }
        if sandy_linux::live_test_support::read_test_key(host_key)? != TEST_KEY_PAYLOAD {
            return Err("host session key fixture was not inherited before enforcement".into());
        }
        // This child starts before Landlock creates the sandbox signal domain.
        // It therefore represents an unrelated host process even though this
        // sacrificial process owns the handle needed for deterministic cleanup.
        let mut outside_signal_target = Command::new("/bin/sleep").arg("2").spawn()?;
        let mut files = vec![
            FileGrant {
                path: workspace.clone(),
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            },
            FileGrant {
                path: system_libraries.clone(),
                access: AccessMode::Read,
                scope: PathScope::Subtree,
            },
            FileGrant {
                path: primary_executable.clone(),
                access: AccessMode::Read,
                scope: PathScope::Exact,
            },
        ];
        if let Ok(cache) = fs::canonicalize("/etc/ld.so.cache") {
            files.push(FileGrant {
                path: absolute(&cache)?,
                access: AccessMode::Read,
                scope: PathScope::Exact,
            });
        }
        let policy = ValidatedPolicy::try_from(PolicySpec {
            files,
            executables: vec![
                ExecutableGrant {
                    path: system_libraries,
                    scope: PathScope::Subtree,
                },
                ExecutableGrant {
                    path: allowed_true.clone(),
                    scope: PathScope::Exact,
                },
                ExecutableGrant {
                    path: allowed_sleep.clone(),
                    scope: PathScope::Exact,
                },
                ExecutableGrant {
                    path: primary_executable.clone(),
                    scope: PathScope::Exact,
                },
            ],
            write_protections: vec![WriteProtection {
                path: locked,
                scope: PathScope::Exact,
            }],
            network: NetworkPolicy::BlockAll,
            allow_subprocesses: true,
            runtime_compatibility: RuntimeCompatibility::ForegroundCli,
            ..PolicySpec::default()
        })?;

        let prepared = sandy_linux::prepare_foreground_launch(
            sandy_linux::plan(&policy)?,
            &workspace,
            &primary_executable,
        )?;
        sandy_linux::apply(prepared)?;

        if env::current_exe()? != primary_executable.as_path()
            || !std::path::Path::new("/proc/self/exe").exists()
            || std::path::Path::new("/proc/self/fd").exists()
            || std::path::Path::new("/proc/1").exists()
        {
            return Err("bounded primary executable alias was not preserved".into());
        }

        if sandy_linux::live_test_support::message_queue_is_visible(host_ipc)? {
            return Err("host System V IPC remained visible after enforcement".into());
        }
        match sandy_linux::live_test_support::read_test_key(host_key) {
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Ok(_) => return Err("inherited host session key remained readable".into()),
            Err(error) => return Err(error.into()),
        }

        match outside_signal_target.kill() {
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Ok(()) => {
                let _ = outside_signal_target.wait();
                return Err("sandbox signaled a process outside its signal domain".into());
            }
            Err(error) => return Err(error.into()),
        }
        let _ = wait_child_with_timeout(&mut outside_signal_target)?;

        let mut same_domain = Command::new(loader.as_path())
            .arg(allowed_sleep.as_path())
            .arg("30")
            .spawn()?;
        same_domain.kill()?;
        let _ = wait_child_with_timeout(&mut same_domain)?;

        if fs::read_to_string("readable.txt")? != "visible" {
            return Err("granted file contents changed".into());
        }
        fs::write("created.txt", "created")?;
        if fs::write("locked.txt", "changed").is_ok() {
            return Err("write-protected file was mutable".into());
        }
        if fs::metadata("/etc/passwd").is_ok() || fs::metadata("../outside.txt").is_ok() {
            return Err("non-granted filesystem data remained visible".into());
        }
        let mut allowed_command = Command::new(loader.as_path());
        allowed_command.arg(allowed_true.as_path());
        if !status_with_timeout(&mut allowed_command)?.success() {
            return Err("explicit executable mapping was not preserved".into());
        }
        let mut denied_command = Command::new(loader.as_path());
        denied_command.arg(data_true.as_path());
        if status_with_timeout(&mut denied_command)?.success() {
            return Err("readable data was mapped executable".into());
        }
        if TcpStream::connect_timeout(&"1.1.1.1:80".parse()?, Duration::from_millis(100)).is_ok() {
            return Err("blocked network connection succeeded".into());
        }
        if TcpListener::bind("127.0.0.1:0").is_ok()
            || UdpSocket::bind("127.0.0.1:0").is_ok()
            || UnixListener::bind("server.sock").is_ok()
        {
            return Err("addressable socket creation succeeded".into());
        }
        let _local_pair = UnixStream::pair()?;
        Ok(())
    }

    fn dynamic_loader() -> &'static std::path::Path {
        #[cfg(target_arch = "x86_64")]
        {
            std::path::Path::new("/lib64/ld-linux-x86-64.so.2")
        }
        #[cfg(target_arch = "aarch64")]
        {
            std::path::Path::new("/lib/ld-linux-aarch64.so.1")
        }
    }

    fn exact_directory_grants_are_rejected_before_enforcement()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = AbsolutePath::new(
            fs::canonicalize(root.path())?
                .to_str()
                .ok_or("path is not UTF-8")?
                .to_owned(),
        )?;
        let policy = ValidatedPolicy::try_from(PolicySpec {
            files: vec![FileGrant {
                path: path.clone(),
                access: AccessMode::Read,
                scope: PathScope::Exact,
            }],
            ..PolicySpec::default()
        })?;

        let error = sandy_linux::prepare(sandy_linux::plan(&policy)?, &path)
            .err()
            .ok_or("exact directory unexpectedly supported")?;
        if error.kind() != sandy_linux::LinuxErrorKind::Unsupported {
            return Err("exact directory returned the wrong error class".into());
        }
        Ok(())
    }

    fn status_with_timeout(
        command: &mut Command,
    ) -> Result<ExitStatus, Box<dyn std::error::Error>> {
        let mut child = command.spawn()?;
        wait_child_with_timeout(&mut child)
    }

    fn wait_child_with_timeout(
        child: &mut Child,
    ) -> Result<ExitStatus, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                child.kill()?;
                let _ = child.wait();
                return Err("live Linux fixture exceeded its hard timeout".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {}
