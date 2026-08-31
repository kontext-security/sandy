#[cfg(target_os = "linux")]
mod linux {
    use std::{
        env, fs,
        net::{TcpListener, TcpStream, UdpSocket},
        os::{
            linux::net::SocketAddrExt,
            unix::fs::PermissionsExt as _,
            unix::net::{SocketAddr, UnixListener, UnixStream},
        },
        process::Command,
        time::Duration,
    };

    use sandy_core::{
        AbsolutePath, AccessMode, ExecutableGrant, FileGrant, NetworkPolicy, PathScope, PolicySpec,
        RuntimeCompatibility, UnixSocketGrant, UnixSocketOperation, ValidatedPolicy,
        WriteProtection,
    };

    const CHILD_MODE: &str = "SANDY_LINUX_LIVE_CHILD";
    const ALLOW_SOCKET_CHILD: &str = "SANDY_LINUX_ALLOW_SOCKET_CHILD";
    const BLOCK_SOCKET_CHILD: &str = "SANDY_LINUX_BLOCK_SOCKET_CHILD";
    const DENIED_SOCKET_PATH: &str = "SANDY_LINUX_DENIED_SOCKET";
    const DEVICE_CHILD: &str = "SANDY_LINUX_DEVICE_CHILD";
    const ABSTRACT_SOCKET_NAME: &str = "SANDY_LINUX_ABSTRACT_SOCKET";
    const REPLACEMENT_CHILD: &str = "SANDY_LINUX_REPLACEMENT_CHILD";
    const SOCKET_PATH: &str = "SANDY_LINUX_LIVE_SOCKET";
    const EXPECT_UNSUPPORTED: &str = "SANDY_LINUX_EXPECT_UNSUPPORTED";
    const WORKSPACE: &str = "SANDY_LINUX_LIVE_WORKSPACE";

    pub(super) fn run() -> Result<(), Box<dyn std::error::Error>> {
        if env::var_os(CHILD_MODE).is_some() {
            return child_checks();
        }
        if env::var_os(ALLOW_SOCKET_CHILD).is_some() {
            return allow_socket_child();
        }
        if env::var_os(BLOCK_SOCKET_CHILD).is_some() {
            return block_socket_child();
        }
        if env::var_os(DEVICE_CHILD).is_some() {
            return exact_device_child();
        }
        if env::var_os(REPLACEMENT_CHILD).is_some() {
            return replacement_child();
        }
        if env::var_os(EXPECT_UNSUPPORTED).is_some() {
            return restricted_host_is_rejected_before_enforcement();
        }

        exact_directory_grants_are_rejected_before_enforcement()?;
        exact_device_grants_do_not_expose_adjacent_devices()?;
        mount_source_replacement_is_rejected()?;

        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace)?;
        fs::write(workspace.join("readable.txt"), "visible")?;
        fs::write(workspace.join("locked.txt"), "locked")?;
        for name in ["allowed-true", "data-true"] {
            let path = workspace.join(name);
            fs::copy("/bin/true", &path)?;
            let mut permissions = fs::metadata(&path)?.permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions)?;
        }
        fs::write(root.path().join("outside.txt"), "hidden")?;

        let status = Command::new(env::current_exe()?)
            .env(CHILD_MODE, "1")
            .env(WORKSPACE, &workspace)
            .status()?;
        if !status.success() {
            return Err("sacrificial sandbox child failed".into());
        }
        allow_all_preserves_pathname_socket_connections(root.path(), &workspace)?;
        block_all_preserves_only_typed_endpoint_authority(root.path(), &workspace)?;
        Ok(())
    }

    fn exact_device_grants_do_not_expose_adjacent_devices() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace)?;
        let status = Command::new(env::current_exe()?)
            .env(DEVICE_CHILD, "1")
            .env(WORKSPACE, &workspace)
            .status()?;
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
        let status = Command::new(env::current_exe()?)
            .env(REPLACEMENT_CHILD, "1")
            .status()?;
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

    fn allow_all_preserves_pathname_socket_connections(
        root: &std::path::Path,
        workspace: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let socket = root.join("service.sock");
        let _listener = UnixListener::bind(&socket)?;
        let status = Command::new(env::current_exe()?)
            .env(ALLOW_SOCKET_CHILD, "1")
            .env(WORKSPACE, workspace)
            .env(SOCKET_PATH, &socket)
            .status()?;
        if !status.success() {
            return Err("allow-all pathname socket child failed".into());
        }
        Ok(())
    }

    fn allow_socket_child() -> Result<(), Box<dyn std::error::Error>> {
        let workspace = absolute_from_environment(WORKSPACE)?;
        let socket = absolute_from_environment(SOCKET_PATH)?;
        let policy = ValidatedPolicy::try_from(PolicySpec {
            files: vec![FileGrant {
                path: workspace.clone(),
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }],
            unix_sockets: vec![UnixSocketGrant {
                path: socket.clone(),
                operation: UnixSocketOperation::Connect,
            }],
            network: NetworkPolicy::AllowAll,
            ..PolicySpec::default()
        })?;
        let prepared = sandy_linux::prepare(sandy_linux::plan(&policy)?, &workspace)?;
        sandy_linux::apply(prepared)?;
        UnixStream::connect(socket.as_path())?;
        Ok(())
    }

    fn block_all_preserves_only_typed_endpoint_authority(
        root: &std::path::Path,
        workspace: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let allowed = root.join("allowed.sock");
        let denied = root.join("denied.sock");
        let abstract_name = format!("sandy-live-{}", std::process::id());
        let _allowed_listener = UnixListener::bind(&allowed)?;
        let _denied_listener = UnixListener::bind(&denied)?;
        let abstract_address = SocketAddr::from_abstract_name(abstract_name.as_bytes())?;
        let _abstract_listener = UnixListener::bind_addr(&abstract_address)?;

        let policy =
            block_socket_policy(absolute(root)?, absolute(workspace)?, absolute(&allowed)?)?;
        match sandy_linux::probe(&policy) {
            Ok(_) => {}
            Err(error) if error.kind() == sandy_linux::LinuxErrorKind::Unsupported => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }

        let status = Command::new(env::current_exe()?)
            .env(BLOCK_SOCKET_CHILD, "1")
            .env(WORKSPACE, workspace)
            .env(SOCKET_PATH, &allowed)
            .env(DENIED_SOCKET_PATH, &denied)
            .env(ABSTRACT_SOCKET_NAME, &abstract_name)
            .status()?;
        if !status.success() {
            return Err("block-all socket child failed".into());
        }
        Ok(())
    }

    fn block_socket_child() -> Result<(), Box<dyn std::error::Error>> {
        let workspace = absolute_from_environment(WORKSPACE)?;
        let allowed = absolute_from_environment(SOCKET_PATH)?;
        let denied = absolute_from_environment(DENIED_SOCKET_PATH)?;
        let root = absolute(allowed.as_path().parent().ok_or("socket has no parent")?)?;
        let policy = block_socket_policy(root.clone(), workspace, allowed.clone())?;
        let prepared = sandy_linux::prepare(sandy_linux::plan(&policy)?, &root)?;
        sandy_linux::apply(prepared)?;

        UnixStream::connect(allowed.as_path())?;
        if UnixStream::connect(denied.as_path()).is_ok() {
            return Err("adjacent pathname socket connection succeeded".into());
        }
        let abstract_name = env::var(ABSTRACT_SOCKET_NAME)?;
        let abstract_address = SocketAddr::from_abstract_name(abstract_name.as_bytes())?;
        if UnixStream::connect_addr(&abstract_address).is_ok() {
            return Err("external abstract socket connection succeeded".into());
        }
        if TcpListener::bind("127.0.0.1:0").is_ok()
            || TcpListener::bind("[::1]:0").is_ok()
            || UdpSocket::bind("127.0.0.1:0").is_ok()
            || TcpStream::connect_timeout(&"1.1.1.1:80".parse()?, Duration::from_millis(100))
                .is_ok()
        {
            return Err("IP socket creation succeeded".into());
        }
        let _local_pair = UnixStream::pair()?;
        Ok(())
    }

    fn block_socket_policy(
        root: AbsolutePath,
        workspace: AbsolutePath,
        allowed: AbsolutePath,
    ) -> Result<ValidatedPolicy, Box<dyn std::error::Error>> {
        Ok(ValidatedPolicy::try_from(PolicySpec {
            files: vec![
                FileGrant {
                    path: root,
                    access: AccessMode::Read,
                    scope: PathScope::Subtree,
                },
                FileGrant {
                    path: workspace,
                    access: AccessMode::ReadWrite,
                    scope: PathScope::Subtree,
                },
            ],
            unix_sockets: vec![UnixSocketGrant {
                path: allowed,
                operation: UnixSocketOperation::Connect,
            }],
            network: NetworkPolicy::BlockAll,
            ..PolicySpec::default()
        })?)
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
        let data_true = AbsolutePath::new(format!("{}/data-true", workspace.as_str()))?;
        let system_libraries = absolute(std::path::Path::new("/usr/lib"))?;
        let loader = absolute(&fs::canonicalize(dynamic_loader())?)?;
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

        let prepared = sandy_linux::prepare(sandy_linux::plan(&policy)?, &workspace)?;
        sandy_linux::apply(prepared)?;

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
        if !Command::new(loader.as_path())
            .arg(allowed_true.as_path())
            .status()?
            .success()
        {
            return Err("explicit executable mapping was not preserved".into());
        }
        if Command::new(loader.as_path())
            .arg(data_true.as_path())
            .status()?
            .success()
        {
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
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {}
