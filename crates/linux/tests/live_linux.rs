#[cfg(target_os = "linux")]
mod linux {
    use std::{env, fs, net::TcpStream, process::Command, time::Duration};

    use sandy_core::{
        AbsolutePath, AccessMode, FileGrant, NetworkPolicy, PathScope, PolicySpec, ValidatedPolicy,
        WriteProtection,
    };

    const CHILD_MODE: &str = "SANDY_LINUX_LIVE_CHILD";
    const WORKSPACE: &str = "SANDY_LINUX_LIVE_WORKSPACE";

    pub(super) fn run() -> Result<(), Box<dyn std::error::Error>> {
        if env::var_os(CHILD_MODE).is_some() {
            return child_checks();
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
