use std::{fs, os::unix::fs::PermissionsExt as _};

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
fn dry_run_json_has_a_versioned_runtime_control_schema() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    let output = command
        .args(["run", "--dry-run", "--", "/bin/echo", "hello"])
        .output()?;
    assert!(output.status.success());

    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["dry_run_schema_version"], 1);
    assert!(document.get("schema_version").is_none());

    let keys = document
        .as_object()
        .ok_or("dry-run output must be a JSON object")?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        keys,
        std::collections::BTreeSet::from([
            "arguments",
            "command",
            "dry_run_schema_version",
            "file_grants",
            "network",
            "profile",
            "runtime_controls",
            "seatbelt_profile",
            "unix_socket_grants",
            "working_directory",
        ])
    );

    let controls = document["runtime_controls"]
        .as_array()
        .ok_or("runtime_controls must be an array")?;
    assert_eq!(controls.len(), 1);
    let control_keys = controls[0]
        .as_object()
        .ok_or("runtime control must be a JSON object")?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        control_keys,
        std::collections::BTreeSet::from(["enabled", "service", "version"])
    );
    assert_eq!(controls[0]["service"], "Kontext");
    assert_eq!(controls[0]["enabled"], false);
    assert!(controls[0]["version"].is_null());
    Ok(())
}

#[test]
fn blocked_network_dry_run_has_no_implicit_socket_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    command
        .args(["run", "--dry-run", "--block-net", "--", "/bin/echo"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""network": "block_all""#))
        .stdout(predicate::str::contains(r#""unix_socket_grants": []"#))
        .stdout(predicate::str::contains("(allow network-outbound").not());
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

#[test]
fn detected_kontext_failure_does_not_make_codex_depend_on_kontext()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let codex_config = home.join(".codex");
    let bin = directory.path().join("bin");
    fs::create_dir_all(&codex_config)?;
    fs::create_dir(&bin)?;

    let kontext = bin.join("kontext");
    fs::write(&kontext, "#!/bin/sh\nexit 1\n")?;
    fs::set_permissions(&kontext, fs::Permissions::from_mode(0o700))?;
    std::os::unix::fs::symlink("/bin/echo", bin.join("codex"))?;
    fs::write(
        codex_config.join("hooks.json"),
        format!(
            r#"{{"hooks":{{"Stop":[{{"hooks":[{{"type":"command","command":"'{}' hook --agent codex stop"}}]}}]}}}}"#,
            kontext.display()
        ),
    )?;

    let mut optional = Command::cargo_bin("sandy")?;
    optional
        .env("HOME", &home)
        .env("PATH", &bin)
        .args(["run", "--dry-run", "--", "codex"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""enabled": false"#))
        .stderr(predicate::str::contains(
            "optional Kontext runtime control unavailable; continuing without it",
        ));

    let mut required = Command::cargo_bin("sandy")?;
    required
        .env("HOME", &home)
        .env("PATH", &bin)
        .args(["run", "--dry-run", "--kontext", "--", "codex"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Kontext runtime control failed: kontext doctor --json failed",
        ));
    Ok(())
}

#[test]
fn malformed_detected_hook_configuration_still_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let codex_config = home.join(".codex");
    fs::create_dir_all(&codex_config)?;
    fs::write(codex_config.join("hooks.json"), "not json")?;
    std::os::unix::fs::symlink("/bin/echo", directory.path().join("codex"))?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", &home)
        .env("PATH", directory.path())
        .args(["run", "--dry-run", "--", "codex"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot parse hook configuration"));
    Ok(())
}
