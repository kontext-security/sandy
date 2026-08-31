#[cfg(target_os = "linux")]
mod linux {

    use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

    const SANDY: &str = env!("CARGO_BIN_EXE_sandy");

    pub(super) fn run() -> Result<(), Box<dyn std::error::Error>> {
        project_access_and_exit_behavior()?;
        node_runtime_uses_only_the_explicit_baseline()?;
        generic_user_profile_runs_without_exposing_its_source()?;
        unsupported_agent_profile_prevents_target_execution()?;
        inherited_terminal_remains_native()?;
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

        let status = Command::new(SANDY)
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
                test -d /proc/self/fd || exit 96
                if test -e /dev/full; then exit 97; fi
            "#,
                "sandy-live",
            ])
            .arg(&outside)
            .status()?;
        if !status.success() || fs::read_to_string(project.join("created.txt"))? != "created" {
            return Err("Linux CLI did not preserve intended project access".into());
        }

        assert_exit(&home, &project, "exit 23", 23)?;
        assert_exit(&home, &project, "kill -TERM $$", 143)?;
        Ok(())
    }

    fn unsupported_agent_profile_prevents_target_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let project = root.path().join("project");
        fs::create_dir_all(home.join(".codex"))?;
        fs::create_dir(&project)?;
        let marker = project.join("target-ran");
        let agent = project.join("codex");
        fs::write(
            &agent,
            format!("#!/bin/sh\nprintf ran > '{}'\n", marker.display()),
        )?;
        let mut permissions = fs::metadata(&agent)?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&agent, permissions)?;

        let status = Command::new(SANDY)
            .env("HOME", &home)
            .current_dir(&project)
            .args(["run", "--"])
            .arg(&agent)
            .status()?;
        if status.success() || marker.exists() {
            return Err("unsupported Linux agent profile executed the target".into());
        }
        Ok(())
    }

    fn node_runtime_uses_only_the_explicit_baseline() -> Result<(), Box<dyn std::error::Error>> {
        let lookup = Command::new("/bin/sh")
            .args(["-c", "command -v node || true"])
            .output()?;
        let node = String::from_utf8(lookup.stdout)?;
        let node = node.trim();
        if node.is_empty() {
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
if (fs.readdirSync('/proc/self/fd').length === 0) process.exit(91);
if (fs.existsSync('/dev/full')) process.exit(92);
if (fs.readFileSync('/etc/resolv.conf').length === 0) process.exit(93);
if (process.env.SSL_CERT_FILE) fs.accessSync(process.env.SSL_CERT_FILE, fs.constants.R_OK);
crypto.randomBytes(32);
if (fs.existsSync('/usr/bin/getent')) {
  childProcess.execFileSync('/usr/bin/getent', ['hosts', 'localhost']);
}
childProcess.execFileSync('/bin/sh', ['-c', 'printf node > node-runtime.txt']);
"#;
        let status = Command::new(SANDY)
            .env("HOME", &home)
            .current_dir(&project)
            .args(["run", "--profile", "generic", "--", node, "-e", script])
            .status()?;
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

        let status = Command::new(SANDY)
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
            .arg(&profile)
            .status()?;
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
        let command = format!("{SANDY} run --profile generic -- /usr/bin/test -t 0");
        let status = Command::new("/usr/bin/script")
            .env("HOME", &home)
            .current_dir(&project)
            .args(["--quiet", "--return", "--command"])
            .arg(command)
            .arg(&transcript)
            .status()?;
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
        let status = Command::new(SANDY)
            .env("HOME", home)
            .current_dir(project)
            .args(["run", "--profile", "generic", "--", "/bin/sh", "-c", script])
            .status()?;
        if status.code() != Some(expected) {
            return Err(format!("expected exit {expected}, got {status:?}").into());
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
