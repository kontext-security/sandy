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

#[test]
#[ignore = "irreversibly applies Seatbelt; run on a host, not inside another sandbox"]
fn optional_kontext_failure_does_not_prevent_target_execution()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir()?;
    let home = root.path().join("home");
    let project = root.path().join("project");
    let bin = root.path().join("bin");
    let codex_config = home.join(".codex");
    fs::create_dir_all(&codex_config)?;
    fs::create_dir(&project)?;
    fs::create_dir(&bin)?;

    let doctor_marker = root.path().join("doctor-invoked");
    let kontext = bin.join("kontext");
    fs::write(
        &kontext,
        format!(
            "#!/bin/sh\n/usr/bin/touch '{}'\nexit 1\n",
            doctor_marker.display()
        ),
    )?;
    fs::set_permissions(&kontext, fs::Permissions::from_mode(0o700))?;
    std::os::unix::fs::symlink("/usr/bin/touch", bin.join("codex"))?;
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
        .current_dir(&project)
        .args(["run", "--", "codex", "optional-target-ran"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "optional Kontext runtime control unavailable; continuing without it",
        ));
    assert!(doctor_marker.is_file());
    assert!(project.join("optional-target-ran").is_file());

    fs::remove_file(&doctor_marker)?;
    let mut required = Command::cargo_bin("sandy")?;
    required
        .env("HOME", &home)
        .env("PATH", &bin)
        .current_dir(&project)
        .args([
            "run",
            "--kontext",
            "--",
            "codex",
            "required-target-must-not-run",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Kontext runtime control failed: kontext doctor --json failed",
        ));
    assert!(doctor_marker.is_file());
    assert!(!project.join("required-target-must-not-run").exists());
    Ok(())
}

#[test]
#[ignore = "irreversibly applies Seatbelt; run on a host, not inside another sandbox"]
fn opencode_profile_allows_state_but_protects_configuration_and_secrets()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let root_path = fs::canonicalize(root.path())?;
    let home = root_path.join("home");
    let project = root_path.join("project");
    let config = home.join(".config/opencode");
    let state = home.join(".local/share/opencode");
    let ssh = home.join(".ssh");
    fs::create_dir_all(&config)?;
    fs::create_dir_all(&state)?;
    fs::create_dir_all(&ssh)?;
    fs::create_dir(&project)?;
    fs::write(config.join("opencode.json"), "original json")?;
    fs::write(config.join("opencode.jsonc"), "original jsonc")?;
    fs::write(ssh.join("secret"), "must stay protected")?;

    let mut allowed = Command::cargo_bin("sandy")?;
    allowed
        .env("HOME", &home)
        .current_dir(&project)
        .args([
            "run",
            "--profile",
            "opencode",
            "--",
            "/bin/sh",
            "-c",
            "printf state > \"$HOME/.local/share/opencode/session\"",
        ])
        .assert()
        .success();
    assert_eq!(fs::read_to_string(state.join("session"))?, "state");

    for (name, original) in [
        ("opencode.json", "original json"),
        ("opencode.jsonc", "original jsonc"),
    ] {
        let script = format!("printf changed > \"$HOME/.config/opencode/{name}\"");
        let mut denied = Command::cargo_bin("sandy")?;
        denied
            .env("HOME", &home)
            .current_dir(&project)
            .args([
                "run",
                "--profile",
                "opencode",
                "--",
                "/bin/sh",
                "-c",
                &script,
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("Operation not permitted"));
        assert_eq!(fs::read_to_string(config.join(name))?, original);
    }

    let mut denied_secret = Command::cargo_bin("sandy")?;
    denied_secret
        .env("HOME", &home)
        .current_dir(&project)
        .args([
            "run",
            "--profile",
            "opencode",
            "--",
            "/bin/sh",
            "-c",
            "/bin/cat \"$HOME/.ssh/secret\"",
        ])
        .assert()
        .failure();
    Ok(())
}

#[test]
#[ignore = "irreversibly applies Seatbelt; run on a host, not inside another sandbox"]
fn codex_control_files_are_readable_but_cannot_be_replaced_or_modified()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let root_path = fs::canonicalize(root.path())?;
    let home = root_path.join("home");
    let project = root_path.join("project");
    let codex = home.join(".codex");
    fs::create_dir_all(&codex)?;
    fs::create_dir(&project)?;

    let hooks_target = codex.join("hooks-target.json");
    let hooks = codex.join("hooks.json");
    let config = codex.join("config.toml");
    fs::write(&hooks_target, "{\"hooks\":{}}\n")?;
    std::os::unix::fs::symlink(&hooks_target, &hooks)?;
    fs::write(&config, "[features]\nhooks = true\n")?;

    let mut readable = Command::cargo_bin("sandy")?;
    readable
        .env("HOME", &home)
        .current_dir(&project)
        .args([
            "run",
            "--profile",
            "codex",
            "--",
            "/bin/sh",
            "-c",
            "/bin/cat \"$HOME/.codex/hooks.json\" \"$HOME/.codex/config.toml\" >/dev/null",
        ])
        .assert()
        .success();

    for script in [
        "printf changed > \"$HOME/.codex/hooks.json\"",
        "/bin/rm \"$HOME/.codex/hooks.json\"",
        "printf replacement > \"$HOME/.codex/replacement\" && /bin/mv -f \"$HOME/.codex/replacement\" \"$HOME/.codex/hooks.json\"",
        "/bin/mv \"$HOME/.codex/hooks.json\" \"$HOME/.codex/hooks.disabled\"",
        "/bin/chmod 0600 \"$HOME/.codex/hooks.json\"",
        "printf changed > \"$HOME/.codex/hooks-target.json\"",
        "printf changed > \"$HOME/.codex/config.toml\"",
    ] {
        let mut denied = Command::cargo_bin("sandy")?;
        denied
            .env("HOME", &home)
            .current_dir(&project)
            .args(["run", "--profile", "codex", "--", "/bin/sh", "-c", script])
            .assert()
            .failure();
    }

    let mut adjacent = Command::cargo_bin("sandy")?;
    adjacent
        .env("HOME", &home)
        .current_dir(&project)
        .args([
            "run",
            "--profile",
            "codex",
            "--",
            "/bin/sh",
            "-c",
            "printf mutable > \"$HOME/.codex/session-state\"",
        ])
        .assert()
        .success();

    assert_eq!(fs::read_to_string(&hooks_target)?, "{\"hooks\":{}}\n");
    assert_eq!(fs::read_link(&hooks)?, hooks_target);
    assert_eq!(fs::read_to_string(&config)?, "[features]\nhooks = true\n");
    assert_eq!(fs::read_to_string(codex.join("session-state"))?, "mutable");
    Ok(())
}
