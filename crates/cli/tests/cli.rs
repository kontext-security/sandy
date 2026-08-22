use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_exposes_only_public_commands() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    command
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("run"))
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("__bootstrap").not());
    Ok(())
}

#[test]
fn dry_run_does_not_require_kontext() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    command
        .args(["run", "--dry-run", "--", "/bin/echo", "hello"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""enabled": false"#))
        .stdout(predicate::str::contains(r#""command": "/bin/echo""#));
    Ok(())
}

#[test]
fn unknown_target_falls_back_to_generic_profile() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    command
        .args(["run", "--dry-run", "--", "/bin/echo"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""name": "generic""#))
        .stdout(predicate::str::contains(r#""detected": false"#));
    Ok(())
}

#[test]
fn explicit_profile_overrides_detection() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    command
        .args([
            "run",
            "--dry-run",
            "--profile",
            "generic",
            "--",
            "/bin/echo",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""name": "generic""#))
        .stdout(predicate::str::contains(r#""detected": false"#));
    Ok(())
}

#[test]
fn unknown_profile_name_fails_with_available_list() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    command
        .args(["run", "--profile", "ghost", "--", "/bin/echo"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ghost"))
        .stderr(predicate::str::contains("opencode"))
        .stderr(predicate::str::contains("base").not());
    Ok(())
}

#[test]
fn inheritance_only_profile_cannot_be_selected() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    command
        .args(["run", "--profile", "base", "--", "/bin/echo"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown agent profile \"base\""));
    Ok(())
}

#[test]
fn detected_agent_profile_is_announced() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    fs::create_dir(&home)?;
    std::os::unix::fs::symlink("/bin/echo", directory.path().join("codex"))?;
    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", home)
        .env("PATH", directory.path())
        .args(["run", "--dry-run", "--", "codex"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""name": "codex""#))
        .stdout(predicate::str::contains(r#""detected": true"#))
        .stderr(predicate::str::contains(
            "applying detected agent profile 'codex'",
        ));
    Ok(())
}
