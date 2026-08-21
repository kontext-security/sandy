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
