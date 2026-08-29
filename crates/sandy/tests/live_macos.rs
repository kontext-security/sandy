#[cfg(not(target_os = "macos"))]
fn main() {}

#[cfg(target_os = "macos")]
fn main() {
    macos::main();
}

#[cfg(target_os = "macos")]
mod macos {

    use std::{
        env, fs, io,
        net::{SocketAddr, TcpListener, TcpStream},
        os::unix::fs::symlink,
        path::{Path, PathBuf},
        process::Command,
    };

    use sandy::{AccessMode, ErrorKind, NetworkPolicy, PathScope, SandboxPolicy};

    const MODE: &str = "SANDY_LIBRARY_LIVE_MODE";
    const ROOT: &str = "SANDY_LIBRARY_LIVE_ROOT";
    const EXECUTABLE: &str = "SANDY_LIBRARY_LIVE_EXECUTABLE";
    const ADDRESS: &str = "SANDY_LIBRARY_LIVE_ADDRESS";

    pub(super) fn main() {
        if let Err(error) = run() {
            eprintln!("live Sandy library test failed: {error}");
            std::process::exit(1);
        }
    }

    fn run() -> Result<(), Box<dyn std::error::Error>> {
        match env::var(MODE).as_deref() {
            Ok("apply") => return run_apply_probe(),
            Ok("descendant") => return run_descendant_probe(),
            Ok("readable-no-execute") => return run_readable_no_execute_probe(),
            Ok("execute-no-subprocess") => return run_execute_no_subprocess_probe(),
            Ok("adjacent-execute") => return run_adjacent_execute_probe(),
            Ok("success") => return Ok(()),
            _ => {}
        }

        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        let credentials = workspace.join("credentials");
        let config = workspace.join("config");
        fs::create_dir_all(&credentials)?;
        fs::create_dir_all(&config)?;
        fs::write(credentials.join("secret.txt"), "secret")?;
        let executable = env::current_exe()?;
        fs::copy(&executable, credentials.join("credential-tool"))?;
        fs::write(config.join("settings.json"), "fixed")?;
        fs::write(config.join("adjacent.txt"), "mutable")?;
        fs::write(root.path().join("outside.txt"), "ungranted")?;
        let request = root.path().join("request");
        let outside = root.path().join("symlink-outside");
        let linked_directory = outside.join("directory");
        fs::create_dir_all(&request)?;
        fs::create_dir_all(&linked_directory)?;
        fs::write(request.join("allowed"), "wrong target")?;
        fs::write(outside.join("allowed"), "filesystem target")?;
        fs::write(outside.join("denied"), "protected target")?;
        let allowed_executable = root.path().join("allowed-executable");
        let adjacent_executable = root.path().join("adjacent-executable");
        fs::copy(&executable, &allowed_executable)?;
        fs::copy(&executable, &adjacent_executable)?;
        symlink(&linked_directory, request.join("link"))?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let status = Command::new(&executable)
            .env(MODE, "apply")
            .env(ROOT, root.path())
            .env(EXECUTABLE, &executable)
            .env(ADDRESS, listener.local_addr()?.to_string())
            .status()?;

        assert!(
            status.success(),
            "sacrificial library probe failed: {status}"
        );
        for mode in [
            "readable-no-execute",
            "execute-no-subprocess",
            "adjacent-execute",
        ] {
            let status = Command::new(&executable)
                .env(MODE, mode)
                .env(ROOT, root.path())
                .env(EXECUTABLE, &executable)
                .status()?;
            assert!(
                status.success(),
                "sacrificial {mode} probe failed: {status}"
            );
        }
        Ok(())
    }

    fn run_apply_probe() -> Result<(), Box<dyn std::error::Error>> {
        let root = required_path(ROOT)?;
        let workspace = fs::canonicalize(root.join("workspace"))?;
        let credentials = fs::canonicalize(workspace.join("credentials"))?;
        let config = fs::canonicalize(workspace.join("config"))?;
        let settings = fs::canonicalize(config.join("settings.json"))?;
        let outside = fs::canonicalize(root.join("outside.txt"))?;
        let requested_allowed = root.join("request/link/../allowed");
        let requested_denied = root.join("request/link/../denied");
        let symlink_target_allowed = fs::canonicalize(&requested_allowed)?;
        let symlink_target_denied = fs::canonicalize(&requested_denied)?;
        let lexical_wrong_target = fs::canonicalize(root.join("request/allowed"))?;
        let executable = fs::canonicalize(required_path(EXECUTABLE)?)?;
        let credential_tool = fs::canonicalize(credentials.join("credential-tool"))?;
        let address: SocketAddr = env::var(ADDRESS)?.parse()?;

        let policy = SandboxPolicy::new(NetworkPolicy::BlockAll)
            .allow_subprocesses()
            .grant(&workspace, AccessMode::ReadWrite, PathScope::Subtree)
            .allow_execute(&workspace, PathScope::Subtree)
            .grant(&requested_allowed, AccessMode::Read, PathScope::Exact)
            .grant(&requested_denied, AccessMode::Read, PathScope::Exact)
            .deny_subtree(&credentials)
            .deny_subtree(&requested_denied)
            .deny_write_exact(&settings);
        let policy = add_macos_runtime(policy, &executable, true);

        env::set_current_dir(&workspace)?;
        sandy::apply(policy)?;

        fs::write(workspace.join("created.txt"), "allowed")?;
        assert_permission_denied(
            fs::read(credentials.join("secret.txt")),
            "credential subtree read",
        )?;
        assert_eq!(fs::read_to_string(&settings)?, "fixed");
        assert_permission_denied(fs::write(&settings, "changed"), "settings write")?;
        fs::write(config.join("adjacent.txt"), "still mutable")?;
        assert_permission_denied(
            fs::rename(&config, workspace.join("moved-config")),
            "protected ancestor rename",
        )?;
        assert_permission_denied(TcpStream::connect(address), "network connect")?;
        assert_permission_denied(fs::read(&outside), "ungranted adjacent read")?;
        assert_eq!(
            fs::read_to_string(&symlink_target_allowed)?,
            "filesystem target"
        );
        assert_permission_denied(
            fs::read(&symlink_target_denied),
            "symlink parent-component deny",
        )?;
        assert_permission_denied(
            fs::read(&lexical_wrong_target),
            "lexically collapsed wrong target",
        )?;
        assert_command_denied(
            Command::new(&credential_tool).env(MODE, "success").status(),
            "terminal executable deny",
        )?;

        let status = Command::new(&executable)
            .env(MODE, "descendant")
            .env(ROOT, &root)
            .status()?;
        assert!(
            status.success(),
            "restricted descendant probe failed: {status}"
        );

        let second_error = sandy::apply(SandboxPolicy::new(NetworkPolicy::AllowAll))
            .err()
            .ok_or("a second sandbox application must fail")?;
        assert!(matches!(
            second_error.kind(),
            ErrorKind::PreparationFailed | ErrorKind::EnforcementFailed
        ));
        Ok(())
    }

    fn run_readable_no_execute_probe() -> Result<(), Box<dyn std::error::Error>> {
        let root = required_path(ROOT)?;
        let executable = fs::canonicalize(required_path(EXECUTABLE)?)?;
        let readable = fs::canonicalize(root.join("adjacent-executable"))?;
        let policy = SandboxPolicy::new(NetworkPolicy::BlockAll)
            .allow_subprocesses()
            .grant(&readable, AccessMode::Read, PathScope::Exact);
        sandy::apply(add_macos_runtime(policy, &executable, false))?;

        assert_command_denied(
            Command::new(&readable).env(MODE, "success").status(),
            "readable executable without mapping",
        )?;
        Ok(())
    }

    fn run_execute_no_subprocess_probe() -> Result<(), Box<dyn std::error::Error>> {
        let executable = fs::canonicalize(required_path(EXECUTABLE)?)?;
        let policy = SandboxPolicy::new(NetworkPolicy::BlockAll)
            .grant(&executable, AccessMode::Read, PathScope::Exact)
            .allow_execute(&executable, PathScope::Exact);
        sandy::apply(add_macos_runtime(policy, &executable, false))?;

        assert_command_denied(
            Command::new(&executable).env(MODE, "success").status(),
            "executable mapping without subprocess authority",
        )?;
        Ok(())
    }

    fn run_adjacent_execute_probe() -> Result<(), Box<dyn std::error::Error>> {
        let root = required_path(ROOT)?;
        let executable = fs::canonicalize(required_path(EXECUTABLE)?)?;
        let allowed = fs::canonicalize(root.join("allowed-executable"))?;
        let adjacent = fs::canonicalize(root.join("adjacent-executable"))?;
        let policy = SandboxPolicy::new(NetworkPolicy::BlockAll)
            .allow_subprocesses()
            .grant(&root, AccessMode::Read, PathScope::Subtree)
            .allow_execute(&allowed, PathScope::Exact);
        sandy::apply(add_macos_runtime(policy, &executable, false))?;

        let allowed_status = Command::new(&allowed).env(MODE, "success").status()?;
        assert!(
            allowed_status.success(),
            "explicitly mapped executable failed: {allowed_status}"
        );
        assert_command_denied(
            Command::new(&adjacent).env(MODE, "success").status(),
            "adjacent executable",
        )?;
        Ok(())
    }

    fn add_macos_runtime(
        mut policy: SandboxPolicy,
        executable: &Path,
        map_executable: bool,
    ) -> SandboxPolicy {
        policy = policy
            .grant(executable, AccessMode::Read, PathScope::Exact)
            .grant("/", AccessMode::Read, PathScope::Exact);
        if map_executable {
            policy = policy.allow_execute(executable, PathScope::Exact);
        }
        for path in [
            "/System",
            "/usr",
            "/bin",
            "/sbin",
            "/Library/Apple",
            "/private/etc",
            "/private/var/db/dyld",
            "/private/var/db/timezone",
        ] {
            if Path::new(path).exists() {
                policy = policy
                    .grant(path, AccessMode::Read, PathScope::Subtree)
                    .allow_execute(path, PathScope::Subtree);
            }
        }
        for path in [
            "/dev/null",
            "/dev/random",
            "/dev/urandom",
            "/dev/tty",
            "/dev/ptmx",
        ] {
            if Path::new(path).exists() {
                policy = policy.grant(path, AccessMode::ReadWrite, PathScope::Exact);
            }
        }
        policy
    }

    fn run_descendant_probe() -> Result<(), Box<dyn std::error::Error>> {
        let root = required_path(ROOT)?;
        assert_permission_denied(
            fs::read(root.join("workspace/credentials/secret.txt")),
            "descendant credential read",
        )?;
        Ok(())
    }

    fn required_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        Ok(PathBuf::from(
            env::var_os(name).ok_or("missing probe path")?,
        ))
    }

    fn assert_permission_denied<T>(result: io::Result<T>, operation: &str) -> io::Result<()> {
        match result {
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(()),
            Err(error) => Err(io::Error::other(format!(
                "{operation} failed for the wrong reason: {error}"
            ))),
            Ok(_) => Err(io::Error::other(format!(
                "{operation} unexpectedly succeeded"
            ))),
        }
    }

    fn assert_command_denied(
        result: io::Result<std::process::ExitStatus>,
        operation: &str,
    ) -> io::Result<()> {
        // macOS may surface a terminal read deny during executable lookup as
        // ENOENT, while an executable-map or process deny normally surfaces as
        // EACCES. Every caller canonicalizes the executable before `apply`.
        match result {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(io::Error::other(format!(
                "{operation} failed for the wrong reason: {error}"
            ))),
            Ok(status) => Err(io::Error::other(format!(
                "{operation} unexpectedly started with {status}"
            ))),
        }
    }
}
