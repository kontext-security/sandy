#![cfg(target_os = "macos")]

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
#[ignore = "irreversibly applies Seatbelt; run on a host, not inside another sandbox"]
fn allows_project_writes_and_denies_sibling_reads() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let project = root.path().join("project");
    let secret = root.path().join("outside.txt");
    fs::create_dir(&project)?;
    fs::write(&secret, "must stay outside")?;

    let mut allowed = Command::cargo_bin("sandy")?;
    allowed
        .current_dir(&project)
        .args(["run", "--", "/usr/bin/touch", "created-inside"])
        .assert()
        .success();
    assert!(project.join("created-inside").is_file());

    let mut denied = Command::cargo_bin("sandy")?;
    denied
        .current_dir(&project)
        .args(["run", "--", "/bin/sh", "-c", "/bin/cat ../outside.txt"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Operation not permitted"));
    Ok(())
}

#[test]
#[ignore = "irreversibly applies Seatbelt; run on a host, not inside another sandbox"]
fn blocks_outbound_connect_when_network_is_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let project = tempfile::tempdir()?;
    let script = "begin; Socket.tcp('1.1.1.1', 80, connect_timeout: 1); rescue Errno::EPERM; exit 0; end; exit 1";
    let mut command = Command::cargo_bin("sandy")?;
    command
        .current_dir(project.path())
        .args([
            "run",
            "--block-net",
            "--",
            "/usr/bin/ruby",
            "--disable-gems",
            "-rsocket",
            "-e",
            script,
        ])
        .assert()
        .success();
    Ok(())
}

#[test]
#[ignore = "irreversibly applies Seatbelt; run on a host, not inside another sandbox"]
fn preserves_target_exit_code() -> Result<(), Box<dyn std::error::Error>> {
    let project = tempfile::tempdir()?;
    let mut command = Command::cargo_bin("sandy")?;
    command
        .current_dir(project.path())
        .args(["run", "--", "/bin/sh", "-c", "exit 42"])
        .assert()
        .code(42);
    Ok(())
}
