#[cfg(target_os = "linux")]
mod linux {

    use std::{
        fs,
        io::Read as _,
        net::{TcpListener, TcpStream, UdpSocket},
        os::{
            linux::net::SocketAddrExt as _,
            unix::net::{SocketAddr, UnixListener, UnixStream},
        },
        path::Path,
        process::{Child, Command, ExitStatus, Output, Stdio},
        thread,
        time::{Duration, Instant},
    };

    const BLOCK_NET_CHILD: &str = "SANDY_CLI_BLOCK_NET_CHILD";
    const BLOCK_NET_ABSTRACT: &str = "SANDY_CLI_BLOCK_NET_ABSTRACT";
    const BLOCK_NET_SOCKET: &str = "SANDY_CLI_BLOCK_NET_SOCKET";
    const SANDY: &str = env!("CARGO_BIN_EXE_sandy");

    pub(super) fn run() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(BLOCK_NET_CHILD).is_some() {
            return block_net_child();
        }
        doctor_succeeds_on_supported_host()?;
        project_access_and_exit_behavior()?;
        blocked_network_reaches_the_bootstrap_policy()?;
        node_runtime_uses_only_the_explicit_baseline()?;
        generic_user_profile_runs_without_exposing_its_source()?;
        built_in_agent_profiles_enforce_state_boundaries()?;
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
        let mut child = command.spawn()?;
        wait_child_with_timeout(&mut child)
    }

    fn output_with_timeout(command: &mut Command) -> Result<Output, Box<dyn std::error::Error>> {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
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
        let status = wait_child_with_timeout(&mut child)?;
        let stdout = stdout_reader
            .join()
            .map_err(|_| "stdout reader panicked")??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| "stderr reader panicked")??;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    fn wait_child_with_timeout(
        child: &mut Child,
    ) -> Result<ExitStatus, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                child.kill()?;
                let _ = child.wait();
                return Err("live Linux CLI fixture exceeded its hard timeout".into());
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
