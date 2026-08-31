#[cfg(target_os = "linux")]
mod linux {

    use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

    const SANDY: &str = env!("CARGO_BIN_EXE_sandy");

    pub(super) fn run() -> Result<(), Box<dyn std::error::Error>> {
        project_access_and_exit_behavior()?;
        codex_state_remains_writable_while_configuration_is_immutable()?;
        missing_protected_control_file_prevents_target_execution()?;
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
                if test -r /dev/null; then exit 95; fi
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

    fn missing_protected_control_file_prevents_target_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let project = root.path().join("project");
        let codex_home = home.join(".codex");
        fs::create_dir_all(&codex_home)?;
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
            return Err("failed Linux preparation executed the target".into());
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

    fn codex_state_remains_writable_while_configuration_is_immutable()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let codex_home = home.join(".codex");
        let project = root.path().join("project");
        fs::create_dir_all(&codex_home)?;
        fs::create_dir(&project)?;
        fs::write(codex_home.join("config.toml"), "original")?;
        fs::write(codex_home.join("hooks.json"), "{}")?;

        let agent = project.join("codex");
        fs::write(
            &agent,
            r#"#!/bin/sh
if printf changed > "$HOME/.codex/config.toml"; then exit 94; fi
printf state > "$HOME/.codex/session-state"
"#,
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
        if !status.success() {
            return Err("Linux CLI agent profile probe failed".into());
        }
        if fs::read_to_string(codex_home.join("config.toml"))? != "original" {
            return Err("protected Codex configuration was modified".into());
        }
        if fs::read_to_string(codex_home.join("session-state"))? != "state" {
            return Err("Codex state directory was not writable".into());
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
