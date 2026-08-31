#[cfg(target_os = "linux")]
mod linux {
    use std::{env, fs, net::TcpStream, process::Command, time::Duration};

    use sandy::{AccessMode, ErrorKind, NetworkPolicy, PathScope, SandboxPolicy};

    const CHILD_MODE: &str = "SANDY_FACADE_LINUX_CHILD";
    const WORKSPACE: &str = "SANDY_FACADE_LINUX_WORKSPACE";

    pub(super) fn run() -> Result<(), Box<dyn std::error::Error>> {
        if env::var_os(CHILD_MODE).is_some() {
            return child_checks();
        }

        unsupported_nested_deny_is_rejected_before_enforcement()?;

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
            return Err("sacrificial facade child failed".into());
        }
        Ok(())
    }

    fn child_checks() -> Result<(), Box<dyn std::error::Error>> {
        let workspace = fs::canonicalize(env::var_os(WORKSPACE).ok_or("missing workspace")?)?;
        let policy = SandboxPolicy::new(NetworkPolicy::BlockAll)
            .grant(&workspace, AccessMode::ReadWrite, PathScope::Subtree)
            .deny_write_exact(workspace.join("locked.txt"));

        env::set_current_dir(&workspace)?;
        sandy::apply(policy)?;

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

    fn unsupported_nested_deny_is_rejected_before_enforcement()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        let secret = workspace.join("secret");
        fs::create_dir_all(&secret)?;
        let error = sandy::apply(
            SandboxPolicy::new(NetworkPolicy::BlockAll)
                .grant(&workspace, AccessMode::Read, PathScope::Subtree)
                .deny_subtree(&secret),
        )
        .err()
        .ok_or("nested deny unexpectedly applied")?;
        if error.kind() != ErrorKind::Unsupported {
            return Err("nested deny returned the wrong error class".into());
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
