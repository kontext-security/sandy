#[cfg(target_os = "linux")]
mod linux {

    use std::{
        fs,
        io::Read as _,
        net::{TcpListener, TcpStream, UdpSocket},
        os::{
            linux::net::SocketAddrExt as _,
            unix::{
                net::{SocketAddr, UnixListener, UnixStream},
                process::CommandExt as _,
            },
        },
        path::Path,
        process::{Child, Command, ExitStatus, Output, Stdio},
        thread,
        time::{Duration, Instant},
    };

    const BLOCK_NET_CHILD: &str = "SANDY_CLI_BLOCK_NET_CHILD";
    const BLOCK_NET_ABSTRACT: &str = "SANDY_CLI_BLOCK_NET_ABSTRACT";
    const BLOCK_NET_SOCKET: &str = "SANDY_CLI_BLOCK_NET_SOCKET";
    const PRIVATE_ROOT_CHILD: &str = "SANDY_CLI_PRIVATE_ROOT_CHILD";
    const REAL_CODEX: &str = "SANDY_REAL_CODEX";
    const REQUIRE_REAL_CODEX: &str = "SANDY_REQUIRE_REAL_CODEX";
    const SANDY: &str = env!("CARGO_BIN_EXE_sandy");
    const LIVE_TIMEOUT: Duration = Duration::from_secs(15);

    pub(super) fn run() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(BLOCK_NET_CHILD).is_some() {
            return block_net_child();
        }
        if std::env::var_os(PRIVATE_ROOT_CHILD).is_some() {
            return private_root_child();
        }
        doctor_succeeds_on_supported_host()?;
        project_access_and_exit_behavior()?;
        blocked_network_reaches_the_bootstrap_policy()?;
        node_runtime_uses_only_the_explicit_baseline()?;
        python_and_subprocesses_use_the_explicit_baseline()?;
        private_root_limitations_are_stable()?;
        generic_user_profile_runs_without_exposing_its_source()?;
        built_in_agent_profiles_enforce_state_boundaries()?;
        installed_codex_binary_starts()?;
        timeout_terminates_the_managed_process_group()?;
        inherited_terminal_remains_native()?;
        Ok(())
    }

    fn doctor_succeeds_on_supported_host() -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new(SANDY);
        command.arg("doctor");
        let output = output_with_timeout(&mut command)?;
        if !output.status.success()
            || !String::from_utf8_lossy(&output.stdout).contains("Linux enforcement: available")
        {
            return Err("doctor did not validate the supported Linux host".into());
        }
        Ok(())
    }

    fn blocked_network_reaches_the_bootstrap_policy() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let project = root.path().join("project");
        fs::create_dir(&home)?;
        fs::create_dir(&project)?;
        let socket = root.path().join("service.sock");
        let _listener = UnixListener::bind(&socket)?;
        let abstract_name = format!("sandy-cli-live-{}", std::process::id());
        let abstract_address = SocketAddr::from_abstract_name(abstract_name.as_bytes())?;
        let _abstract_listener = UnixListener::bind_addr(&abstract_address)?;

        let mut command = Command::new(SANDY);
        command
            .env("HOME", &home)
            .env(BLOCK_NET_CHILD, "1")
            .env(BLOCK_NET_SOCKET, &socket)
            .env(BLOCK_NET_ABSTRACT, &abstract_name)
            .current_dir(&project)
            .args(["run", "--profile", "generic", "--block-net", "--"])
            .arg(std::env::current_exe()?);
        let status = status_with_timeout(&mut command)?;
        if !status.success() {
            return Err("CLI block-net policy did not reach the target".into());
        }
        Ok(())
    }

    fn block_net_child() -> Result<(), Box<dyn std::error::Error>> {
        let pathname = std::env::var_os(BLOCK_NET_SOCKET).ok_or("missing socket path")?;
        let abstract_name = std::env::var(BLOCK_NET_ABSTRACT)?;
        let abstract_address = SocketAddr::from_abstract_name(abstract_name.as_bytes())?;
        if TcpListener::bind("127.0.0.1:0").is_ok()
            || UdpSocket::bind("127.0.0.1:0").is_ok()
            || TcpStream::connect_timeout(&"1.1.1.1:80".parse()?, Duration::from_millis(100))
                .is_ok()
            || UnixStream::connect(pathname).is_ok()
            || UnixStream::connect_addr(&abstract_address).is_ok()
            || UnixListener::bind("unexpected.sock").is_ok()
        {
            return Err("blocked network authority remained available".into());
        }
        let _local_pair = UnixStream::pair()?;
        Ok(())
    }

    fn project_access_and_exit_behavior() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let project = root.path().join("project");
        let outside = root.path().join("outside.txt");
        fs::create_dir(&home)?;
        fs::create_dir(&project)?;
        fs::write(&outside, "not visible")?;
        let hidden_run_entry = ["/run/lock", "/run/user", "/run/utmp"]
            .into_iter()
            .find(|path| Path::new(path).exists())
            .ok_or("host has no known adjacent /run entry for the negative test")?;

        let mut command = Command::new(SANDY);
        command
            .env("HOME", &home)
            .env("SANDY_LIVE_SENTINEL", "preserved")
            .current_dir(&project)
            .args([
                "run",
                "--profile",
                "generic",
                "--",
                "/bin/sh",
                "-c",
                r#"
                test "$SANDY_LIVE_SENTINEL" = preserved || exit 91
                printf created > created.txt || exit 92
                if test -r "$1"; then exit 93; fi
                printf discarded > /dev/null || exit 94
                test -r /dev/urandom || exit 95
                test -r /dev/random || exit 96
                head -c 1 /dev/zero > /dev/null || exit 97
                head -c 1 /dev/urandom > /dev/null || exit 98
                if test -e /dev/full; then exit 99; fi
                if test -e /dev/ptmx; then exit 100; fi
                if test -e /proc/1/status; then exit 101; fi
                if test -e /sys; then exit 102; fi
                if test -e "$2"; then exit 103; fi
            "#,
                "sandy-live",
            ])
            .arg(&outside)
            .arg(hidden_run_entry);
        let status = status_with_timeout(&mut command)?;
        if !status.success() {
            return Err(format!("Linux CLI project smoke exited with {status}").into());
        }
        if fs::read_to_string(project.join("created.txt"))? != "created" {
            return Err("Linux CLI did not preserve intended project writes".into());
        }

        assert_exit(&home, &project, "exit 23", 23)?;
        assert_exit(&home, &project, "kill -TERM $$", 143)?;
        Ok(())
    }

    fn built_in_agent_profiles_enforce_state_boundaries() -> Result<(), Box<dyn std::error::Error>>
    {
        for profile in ["claude", "codex", "opencode"] {
            let root = tempfile::tempdir()?;
            let home = root.path().join("home");
            let project = root.path().join("project");
            fs::create_dir(&home)?;
            fs::create_dir(&project)?;

            let (protected, mutable) = match profile {
                "claude" => {
                    fs::create_dir(home.join(".claude"))?;
                    fs::write(home.join(".claude/settings.json"), "protected")?;
                    fs::write(home.join(".claude.json"), "protected")?;
                    (
                        home.join(".claude/settings.json"),
                        home.join(".claude/state.txt"),
                    )
                }
                "codex" => {
                    fs::create_dir(home.join(".codex"))?;
                    fs::write(home.join(".codex/hooks.json"), "protected")?;
                    fs::write(home.join(".codex/config.toml"), "protected")?;
                    (
                        home.join(".codex/config.toml"),
                        home.join(".codex/state.txt"),
                    )
                }
                "opencode" => {
                    fs::create_dir_all(home.join(".config/opencode"))?;
                    fs::create_dir_all(home.join(".local/share/opencode"))?;
                    fs::write(home.join(".config/opencode/opencode.json"), "protected")?;
                    fs::write(home.join(".config/opencode/opencode.jsonc"), "protected")?;
                    (
                        home.join(".config/opencode/opencode.json"),
                        home.join(".local/share/opencode/state.txt"),
                    )
                }
                _ => return Err("unexpected built-in profile fixture".into()),
            };

            let mut command = Command::new(SANDY);
            command
                .env("HOME", &home)
                .current_dir(&project)
                .args([
                    "run",
                    "--profile",
                    profile,
                    "--",
                    "/bin/sh",
                    "-c",
                    "if printf changed > \"$1\"; then exit 91; fi; printf state > \"$2\"",
                    "sandy-live",
                ])
                .arg(&protected)
                .arg(&mutable);
            let status = status_with_timeout(&mut command)?;
            if !status.success()
                || fs::read_to_string(&protected)? != "protected"
                || fs::read_to_string(&mutable)? != "state"
            {
                return Err(format!("Linux {profile} profile boundary failed").into());
            }
        }
        Ok(())
    }

    fn installed_codex_binary_starts() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(REQUIRE_REAL_CODEX).as_deref() != Some(std::ffi::OsStr::new("1")) {
            return Ok(());
        }

        let executable = std::env::var_os(REAL_CODEX).ok_or("missing required Codex fixture")?;
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let project = root.path().join("project");
        fs::create_dir(&home)?;
        fs::create_dir(&project)?;
        fs::create_dir(home.join(".codex"))?;
        fs::write(home.join(".codex/hooks.json"), "{}")?;
        fs::write(home.join(".codex/config.toml"), "")?;

        let mut command = Command::new(SANDY);
        command
            .env("HOME", &home)
            .env("CI", "1")
            .current_dir(&project)
            .args(["run", "--profile", "codex", "--block-net", "--"])
            .arg(executable)
            .arg("--version");
        let output = output_with_timeout(&mut command)?;
        if output.status.success() && (!output.stdout.is_empty() || !output.stderr.is_empty()) {
            return Ok(());
        }
        Err(format!(
            "installed Codex exited with {}; stdout={:?}; stderr={:?}",
            output.status,
            bounded_diagnostic(&output.stdout),
            bounded_diagnostic(&output.stderr),
        )
        .into())
    }

    fn bounded_diagnostic(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).chars().take(2_048).collect()
    }

    fn timeout_terminates_the_managed_process_group() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let pid_file = root.path().join("descendant.pid");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30 & echo $! > \"$1\"; wait", "sandy-live"])
            .arg(&pid_file)
            .process_group(0);
        let mut child = command.spawn()?;
        if wait_child_for(&mut child, Duration::from_millis(250)).is_ok() {
            return Err("timeout fixture exited before exercising cleanup".into());
        }

        let descendant = fs::read_to_string(pid_file)?.trim().to_owned();
        let deadline = Instant::now() + Duration::from_secs(2);
        while process_exists(&descendant)? {
            if Instant::now() >= deadline {
                return Err("timeout left a descendant process alive".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    fn process_exists(pid: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let status = Command::new("/usr/bin/kill")
            .args(["-0", "--"])
            .arg(pid)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        Ok(status.success())
    }

    fn node_runtime_uses_only_the_explicit_baseline() -> Result<(), Box<dyn std::error::Error>> {
        let mut lookup = Command::new("/bin/sh");
        lookup.args(["-c", "command -v node || true"]);
        let lookup = output_with_timeout(&mut lookup)?;
        let node = String::from_utf8(lookup.stdout)?;
        let node = node.trim();
        if node.is_empty() {
            if std::env::var_os("SANDY_REQUIRE_NODE").is_some() {
                return Err("Node is required for the Linux compatibility smoke test".into());
            }
            return Ok(());
        }

        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let project = root.path().join("project");
        fs::create_dir(&home)?;
        fs::create_dir(&project)?;
        let script = r#"
const fs = require('fs');
const crypto = require('crypto');
const childProcess = require('child_process');
fs.writeFileSync('/dev/null', 'discarded');
if (fs.existsSync('/dev/full')) process.exit(91);
if (fs.readFileSync('/etc/resolv.conf').length === 0) process.exit(92);
if (process.env.SSL_CERT_FILE) fs.accessSync(process.env.SSL_CERT_FILE, fs.constants.R_OK);
crypto.randomBytes(32);
if (fs.existsSync('/usr/bin/getent')) {
  childProcess.execFileSync('/usr/bin/getent', ['hosts', 'localhost']);
}
childProcess.execFileSync('/bin/sh', ['-c', 'printf node > node-runtime.txt']);
"#;
        let mut command = Command::new(SANDY);
        command.env("HOME", &home).current_dir(&project).args([
            "run",
            "--profile",
            "generic",
            "--",
            node,
            "-e",
            script,
        ]);
        let status = status_with_timeout(&mut command)?;
        if !status.success() || fs::read_to_string(project.join("node-runtime.txt"))? != "node" {
            return Err("Node did not run inside the explicit Linux CLI baseline".into());
        }
        Ok(())
    }

    fn python_and_subprocesses_use_the_explicit_baseline() -> Result<(), Box<dyn std::error::Error>>
    {
        let python = Path::new("/usr/bin/python3");
        if !python.is_file() {
            return Err(
                "/usr/bin/python3 is required for the Linux compatibility smoke test".into(),
            );
        }
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let project = root.path().join("project");
        fs::create_dir(&home)?;
        fs::create_dir(&project)?;
        let script = r#"
import pathlib
import subprocess

pathlib.Path("python-runtime.txt").write_text("python", encoding="utf-8")
subprocess.run(["/bin/sh", "-c", "printf child > python-child.txt"], check=True)
"#;
        let mut command = Command::new(SANDY);
        command.env("HOME", &home).current_dir(&project).args([
            "run",
            "--profile",
            "generic",
            "--",
            "/usr/bin/python3",
            "-c",
            script,
        ]);
        let status = status_with_timeout(&mut command)?;
        if !status.success()
            || fs::read_to_string(project.join("python-runtime.txt"))? != "python"
            || fs::read_to_string(project.join("python-child.txt"))? != "child"
        {
            return Err("Python or its subprocess failed inside the Linux baseline".into());
        }
        Ok(())
    }

    fn private_root_limitations_are_stable() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let project = root.path().join("project");
        fs::create_dir(&home)?;
        fs::create_dir(&project)?;
        let mut command = Command::new(SANDY);
        command
            .env("HOME", &home)
            .env(PRIVATE_ROOT_CHILD, "1")
            .current_dir(&project)
            .args(["run", "--profile", "generic", "--"])
            .arg(std::env::current_exe()?);
        let status = status_with_timeout(&mut command)?;
        if !status.success() {
            return Err("private-root compatibility contract changed".into());
        }
        Ok(())
    }

    fn private_root_child() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::current_exe().is_ok()
            || Path::new("/proc/self/exe").exists()
            || Path::new("/proc/self/fd").exists()
            || Path::new("/dev/fd").exists()
            || Path::new("/dev/shm").exists()
        {
            return Err("an intentionally absent process or shared-memory path was exposed".into());
        }
        let mut subprocess = Command::new("/bin/sh");
        subprocess.args(["-c", "exit 0"]);
        if !status_with_timeout(&mut subprocess)?.success() {
            return Err("ordinary subprocess behavior was not preserved".into());
        }
        Ok(())
    }

    fn generic_user_profile_runs_without_exposing_its_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let project = root.path().join("project");
        let profile = root.path().join("profile.json");
        fs::create_dir(&home)?;
        fs::create_dir(&project)?;
        fs::write(
            &profile,
            r#"{"schema_version":1,"name":"linux-session","extends":"generic"}"#,
        )?;

        let mut command = Command::new(SANDY);
        command
            .env("HOME", &home)
            .current_dir(&project)
            .args(["run", "--profile-file"])
            .arg(&profile)
            .args([
                "--",
                "/bin/sh",
                "-c",
                "if test -e \"$1\"; then exit 91; fi; printf user > user-profile.txt",
                "sandy-live",
            ])
            .arg(&profile);
        let status = status_with_timeout(&mut command)?;
        if !status.success() || fs::read_to_string(project.join("user-profile.txt"))? != "user" {
            return Err("generic-based Linux user profile failed".into());
        }
        Ok(())
    }

    fn inherited_terminal_remains_native() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let project = root.path().join("project");
        let transcript = root.path().join("typescript");
        fs::create_dir(&home)?;
        fs::create_dir(&project)?;
        let command = format!(
            "{SANDY} run --profile generic -- /bin/sh -c 'test -t 0 && exec 3<>/dev/tty && test -t 3'"
        );
        let mut terminal = Command::new("/usr/bin/script");
        terminal
            .env("HOME", &home)
            .current_dir(&project)
            .args(["--quiet", "--return", "--command"])
            .arg(command)
            .arg(&transcript);
        let status = status_with_timeout(&mut terminal)?;
        if !status.success() {
            return Err("inherited Linux terminal behavior was not preserved".into());
        }
        Ok(())
    }

    fn assert_exit(
        home: &Path,
        project: &Path,
        script: &str,
        expected: i32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new(SANDY);
        command.env("HOME", home).current_dir(project).args([
            "run",
            "--profile",
            "generic",
            "--",
            "/bin/sh",
            "-c",
            script,
        ]);
        let status = status_with_timeout(&mut command)?;
        if status.code() != Some(expected) {
            return Err(format!("expected exit {expected}, got {status:?}").into());
        }
        Ok(())
    }

    fn status_with_timeout(
        command: &mut Command,
    ) -> Result<ExitStatus, Box<dyn std::error::Error>> {
        command.process_group(0);
        let mut child = command.spawn()?;
        wait_child_with_timeout(&mut child)
    }

    fn output_with_timeout(command: &mut Command) -> Result<Output, Box<dyn std::error::Error>> {
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command.spawn()?;
        let mut stdout = child.stdout.take().ok_or("missing child stdout")?;
        let mut stderr = child.stderr.take().ok_or("missing child stderr")?;
        let stdout_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).map(|_| bytes)
        });
        let stderr_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).map(|_| bytes)
        });
        let status = wait_child_with_timeout(&mut child);
        let stdout = stdout_reader
            .join()
            .map_err(|_| "stdout reader panicked")??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| "stderr reader panicked")??;
        Ok(Output {
            status: status?,
            stdout,
            stderr,
        })
    }

    fn wait_child_with_timeout(
        child: &mut Child,
    ) -> Result<ExitStatus, Box<dyn std::error::Error>> {
        wait_child_for(child, LIVE_TIMEOUT)
    }

    fn wait_child_for(
        child: &mut Child,
        timeout: Duration,
    ) -> Result<ExitStatus, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                terminate_process_group(child)?;
                return Err("live Linux CLI fixture exceeded its hard timeout".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn terminate_process_group(child: &mut Child) -> Result<(), Box<dyn std::error::Error>> {
        let group = format!("-{}", child.id());
        let terminated = Command::new("/usr/bin/kill")
            .args(["-KILL", "--"])
            .arg(group)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success();
        if !terminated && child.try_wait()?.is_none() {
            child.kill()?;
        }
        let _ = child.wait();
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {}
