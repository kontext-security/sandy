#[cfg(target_os = "linux")]
mod linux {
    use std::{
        env, fs,
        net::TcpStream,
        os::unix::net::{UnixListener, UnixStream},
        process::Command,
        time::Duration,
    };

    use sandy_core::{
        AbsolutePath, AccessMode, FileGrant, NetworkPolicy, PathScope, PolicySpec, UnixSocketGrant,
        UnixSocketOperation, ValidatedPolicy, WriteProtection,
    };

    const CHILD_MODE: &str = "SANDY_LINUX_LIVE_CHILD";
    const ALLOW_SOCKET_CHILD: &str = "SANDY_LINUX_ALLOW_SOCKET_CHILD";
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
        if env::var_os(EXPECT_UNSUPPORTED).is_some() {
            return restricted_host_is_rejected_before_enforcement();
        }

        exact_directory_grants_are_rejected_before_enforcement()?;

        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace)?;
        fs::write(workspace.join("readable.txt"), "visible")?;
        fs::write(workspace.join("locked.txt"), "locked")?;
        fs::write(root.path().join("outside.txt"), "hidden")?;

        let status = Command::new(env::current_exe()?)
            .env(CHILD_MODE, "1")
            .env(WORKSPACE, &workspace)
            .status()?;
        if !status.success() {
            return Err("sacrificial sandbox child failed".into());
        }
        allow_all_preserves_pathname_socket_connections(root.path(), &workspace)?;
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

    fn absolute_from_environment(name: &str) -> Result<AbsolutePath, Box<dyn std::error::Error>> {
        let path = fs::canonicalize(env::var_os(name).ok_or("missing test path")?)?;
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
        let policy = ValidatedPolicy::try_from(PolicySpec {
            files: vec![FileGrant {
                path: workspace.clone(),
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }],
            write_protections: vec![WriteProtection {
                path: locked,
                scope: PathScope::Exact,
            }],
            network: NetworkPolicy::BlockAll,
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
        if TcpStream::connect_timeout(&"1.1.1.1:80".parse()?, Duration::from_millis(100)).is_ok() {
            return Err("blocked network connection succeeded".into());
        }
        Ok(())
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
