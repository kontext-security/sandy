use std::fs;

#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt as _;

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
        .stdout(predicate::str::contains("integrations"))
        .stdout(predicate::str::contains("__bootstrap").not());
    Ok(())
}

#[test]
fn run_help_documents_complete_policy_files() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    command
        .args(["run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--policy-file <PATH>"))
        .stdout(predicate::str::contains("--agent <NAME>"))
        .stdout(predicate::str::contains("--execute <PATH>"))
        .stdout(predicate::str::contains("built-in agent preset"))
        .stdout(predicate::str::contains("macOS only"));
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn linux_rejects_explicit_runtime_control_flags_before_launch()
-> Result<(), Box<dyn std::error::Error>> {
    for arguments in [
        &["run", "--kontext", "--", "/bin/echo"][..],
        &["run", "--numbat", "--", "/bin/echo"][..],
        &["doctor", "--kontext"][..],
        &["doctor", "--numbat"][..],
    ] {
        let mut command = Command::cargo_bin("sandy")?;
        command
            .args(arguments)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "runtime-control integrations are not supported by the Linux CLI",
            ));
    }
    Ok(())
}

#[test]
#[cfg(target_os = "macos")]
fn integration_setup_does_not_mutate_an_active_numbat_installation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let codex = home.join(".codex");
    let numbat = home.join(".numbat");
    let bin = directory.path().join("bin");
    fs::create_dir_all(&codex)?;
    fs::create_dir(&numbat)?;
    fs::create_dir(&bin)?;
    let marker = directory.path().join("unexpected-mutation");
    let binary = bin.join("numbat");
    fs::write(
        &binary,
        format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.display()),
    )?;
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
    fs::write(
        codex.join("hooks.json"),
        format!(
            r#"{{"hooks":{{"Stop":[{{"hooks":[{{"type":"command","command":"'{}' hook stop --agent codex --installed-by=numbat --output=file --output-file '$HOME/.numbat/findings.ndjson'"}}]}}]}}}}"#,
            binary.display()
        ),
    )?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", &home)
        .env("PATH", &bin)
        .args(["integrations", "setup", "numbat", "--agent", "codex"])
        .assert()
        .success()
        .stdout(predicate::str::contains("already installed and configured"));
    assert!(!marker.exists());
    Ok(())
}

#[test]
#[cfg(target_os = "macos")]
fn integration_setup_configures_an_existing_numbat_binary() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let codex = home.join(".codex");
    let bin = directory.path().join("bin");
    fs::create_dir(&home)?;
    fs::create_dir(&bin)?;
    let marker = directory.path().join("arguments");
    let binary = bin.join("numbat");
    let hooks = codex.join("hooks.json");
    let configured = format!(
        r#"{{"hooks":{{"Stop":[{{"hooks":[{{"type":"command","command":"{} hook stop --agent codex --installed-by=numbat --output=file --output-file {}"}}]}}]}}}}"#,
        binary.display(),
        home.join(".numbat/findings.ndjson").display()
    );
    fs::write(
        &binary,
        format!(
            "#!/bin/sh\n/usr/bin/printf '%s\\n' \"$@\" > '{}'\n/bin/mkdir -p '{}'\n/usr/bin/printf '%s' '{}' > '{}'\nexit 0\n",
            marker.display(),
            codex.display(),
            configured,
            hooks.display()
        ),
    )?;
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", &home)
        .env("PATH", &bin)
        .args(["integrations", "setup", "numbat", "--agent", "codex"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "already installed and is now configured",
        ));
    let arguments = fs::read_to_string(marker)?;
    assert!(arguments.contains("hook\ninstall\n--agent\ncodex"));
    assert!(arguments.contains("--output=file"));
    assert!(home.join(".numbat").is_dir());
    assert!(hooks.is_file());
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn integration_setup_is_explicitly_unsupported_on_linux() -> Result<(), Box<dyn std::error::Error>>
{
    let mut command = Command::cargo_bin("sandy")?;
    command
        .args(["integrations", "setup", "numbat", "--agent", "codex"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "integration setup is currently supported only on macOS",
        ));
    Ok(())
}

#[test]
fn dry_run_does_not_require_optional_runtime_controls() -> Result<(), Box<dyn std::error::Error>> {
    let expected_command = fs::canonicalize("/bin/echo")?;
    let expected_command = expected_command
        .to_str()
        .ok_or("canonical command path must be UTF-8")?;
    let mut command = Command::cargo_bin("sandy")?;
    let assertion = command
        .args(["run", "--dry-run", "--", "/bin/echo", "hello"])
        .assert()
        .success();
    #[cfg(target_os = "macos")]
    let assertion = assertion.stdout(predicate::str::contains(r#""enabled": false"#));
    assertion.stdout(predicate::str::contains(format!(
        r#""command": "{expected_command}""#
    )));
    Ok(())
}

#[test]
fn dry_run_json_has_a_versioned_runtime_control_schema() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    let output = command
        .env_remove("SSL_CERT_FILE")
        .args(["run", "--dry-run", "--", "/bin/echo", "hello"])
        .output()?;
    assert!(output.status.success());

    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["dry_run_schema_version"], 7);
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
            "agent",
            "allow_subprocesses",
            "arguments",
            "command",
            "dry_run_schema_version",
            "executable_grants",
            "file_grants",
            "file_metadata",
            "local_host_tcp_grants",
            "network",
            "policy_source",
            "runtime_controls",
            "runtime_compatibility",
            "native_policy",
            "unix_socket_grants",
            "working_directory",
        ])
    );

    let controls = document["runtime_controls"]
        .as_array()
        .ok_or("runtime_controls must be an array")?;
    #[cfg(target_os = "macos")]
    {
        assert_eq!(controls.len(), 2);
        for control in controls {
            let control_keys = control
                .as_object()
                .ok_or("runtime control must be a JSON object")?
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                control_keys,
                std::collections::BTreeSet::from(["enabled", "service", "version"])
            );
            assert_eq!(control["enabled"], false);
            assert!(control["version"].is_null());
        }
        assert_eq!(controls[0]["service"], "Kontext");
        assert_eq!(controls[1]["service"], "Numbat");
    }
    #[cfg(target_os = "linux")]
    assert!(controls.is_empty());

    let grants = document["file_grants"]
        .as_array()
        .ok_or("file_grants must be an array")?;
    #[cfg(target_os = "macos")]
    assert!(grants.iter().any(|grant| {
        grant["path"] == "/" && grant["access"] == "read" && grant["scope"] == "exact"
    }));
    let runtime_bin = fs::canonicalize("/bin")?;
    let runtime_bin = runtime_bin
        .to_str()
        .ok_or("canonical runtime path must be UTF-8")?;
    assert!(grants.iter().any(|grant| {
        grant["path"] == runtime_bin && grant["access"] == "read" && grant["scope"] == "subtree"
    }));
    #[cfg(target_os = "macos")]
    {
        assert!(grants.iter().any(|grant| {
            grant["path"] == "/dev/null"
                && grant["access"] == "read_write"
                && grant["scope"] == "exact"
        }));
        assert_eq!(document["file_metadata"], "allow");
    }
    #[cfg(target_os = "linux")]
    {
        assert!(grants.iter().any(|grant| {
            grant["path"] == "/dev/null"
                && grant["access"] == "read_write"
                && grant["scope"] == "exact"
        }));
        assert_eq!(document["file_metadata"], "deny");
    }
    assert_eq!(document["allow_subprocesses"], true);
    assert_eq!(document["runtime_compatibility"], "foreground_cli");
    assert!(
        document["executable_grants"]
            .as_array()
            .is_some_and(|grants| !grants.is_empty())
    );
    let executables = document["executable_grants"]
        .as_array()
        .ok_or("executable_grants must be an array")?;
    assert!(!executables.iter().any(|grant| grant["path"] == "/"));
    if let Ok(ca_bundle) = fs::canonicalize("/etc/ssl/cert.pem") {
        let ca_bundle = ca_bundle
            .to_str()
            .ok_or("canonical CA bundle path must be UTF-8")?;
        assert!(grants.iter().any(|grant| {
            grant["path"] == ca_bundle && grant["access"] == "read" && grant["scope"] == "exact"
        }));
        assert!(!executables.iter().any(|grant| grant["path"] == ca_bundle));
    }
    #[cfg(target_os = "macos")]
    {
        assert_eq!(document["native_policy"]["backend"], "seatbelt");
        assert!(
            document["native_policy"]["details"]
                .as_str()
                .ok_or("native policy details must be a string")?
                .contains("file-read-metadata")
        );
    }
    #[cfg(target_os = "linux")]
    {
        assert_eq!(document["native_policy"]["backend"], "linux");
        assert_eq!(document["native_policy"]["landlock_abi"], 6);
        assert!(document["native_policy"].get("details").is_none());
    }
    Ok(())
}

#[test]
fn cli_file_and_executable_grants_are_independent() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let readable = directory.path().join("readable");
    let writable = directory.path().join("writable");
    let executable = directory.path().join("executable");
    let readable_file = directory.path().join("readable.txt");
    #[cfg(target_os = "macos")]
    let writable_file = directory.path().join("writable.txt");
    let executable_file = directory.path().join("executable-file");
    fs::create_dir(&home)?;
    fs::create_dir(&readable)?;
    fs::create_dir(&writable)?;
    fs::create_dir(&executable)?;
    fs::write(&readable_file, "readable")?;
    #[cfg(target_os = "macos")]
    fs::write(&writable_file, "writable")?;
    fs::write(&executable_file, "executable")?;

    let mut command = Command::cargo_bin("sandy")?;
    command.env("HOME", home).args([
        "run",
        "--dry-run",
        "--read",
        readable.to_str().ok_or("test path must be UTF-8")?,
        "--read-write",
        writable.to_str().ok_or("test path must be UTF-8")?,
        "--execute",
        executable.to_str().ok_or("test path must be UTF-8")?,
        "--read",
        readable_file.to_str().ok_or("test path must be UTF-8")?,
        "--execute",
        executable_file.to_str().ok_or("test path must be UTF-8")?,
    ]);
    #[cfg(target_os = "macos")]
    command.args([
        "--read-write",
        writable_file.to_str().ok_or("test path must be UTF-8")?,
    ]);
    let output = command.args(["--", "/bin/echo"]).output()?;
    assert!(output.status.success());

    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let files = document["file_grants"]
        .as_array()
        .ok_or("file_grants must be an array")?;
    let executables = document["executable_grants"]
        .as_array()
        .ok_or("executable_grants must be an array")?;
    for (path, access) in [
        (fs::canonicalize(readable)?, "read"),
        (fs::canonicalize(writable)?, "read_write"),
    ] {
        let path = path.to_str().ok_or("canonical test path must be UTF-8")?;
        assert!(files.iter().any(|grant| {
            grant["path"] == path && grant["access"] == access && grant["scope"] == "subtree"
        }));
        assert!(!executables.iter().any(|grant| grant["path"] == path));
    }
    let executable = fs::canonicalize(executable)?;
    let executable = executable
        .to_str()
        .ok_or("canonical test path must be UTF-8")?;
    assert!(
        executables
            .iter()
            .any(|grant| { grant["path"] == executable && grant["scope"] == "subtree" })
    );
    assert!(!files.iter().any(|grant| grant["path"] == executable));
    let readable_file = fs::canonicalize(readable_file)?;
    let readable_file = readable_file
        .to_str()
        .ok_or("canonical test path must be UTF-8")?;
    assert!(files.iter().any(|grant| {
        grant["path"] == readable_file && grant["access"] == "read" && grant["scope"] == "exact"
    }));
    assert!(
        !executables
            .iter()
            .any(|grant| grant["path"] == readable_file)
    );
    #[cfg(target_os = "macos")]
    {
        let writable_file = fs::canonicalize(writable_file)?;
        let writable_file = writable_file
            .to_str()
            .ok_or("canonical test path must be UTF-8")?;
        assert!(files.iter().any(|grant| {
            grant["path"] == writable_file
                && grant["access"] == "read_write"
                && grant["scope"] == "exact"
        }));
        assert!(
            !executables
                .iter()
                .any(|grant| grant["path"] == writable_file)
        );
    }
    let executable_file = fs::canonicalize(executable_file)?;
    let executable_file = executable_file
        .to_str()
        .ok_or("canonical test path must be UTF-8")?;
    assert!(
        executables
            .iter()
            .any(|grant| { grant["path"] == executable_file && grant["scope"] == "exact" })
    );
    assert!(!files.iter().any(|grant| grant["path"] == executable_file));
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn linux_rejects_read_write_regular_files_before_launch() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let project = directory.path().join("project");
    let writable_file = directory.path().join("one-file");
    let marker = directory.path().join("target-ran");
    fs::create_dir(&home)?;
    fs::create_dir(&project)?;
    fs::write(&writable_file, "unchanged")?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", &home)
        .env("SANDY_TEST_MARKER", &marker)
        .current_dir(&project)
        .args(["run", "--agent", "generic", "--read-write"])
        .arg(&writable_file)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "printf ran > \"$SANDY_TEST_MARKER\"",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--read-write on Linux requires an existing directory; grant the containing directory instead",
        ));
    assert!(!marker.exists());
    assert_eq!(fs::read_to_string(writable_file)?, "unchanged");
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn linux_rejects_missing_codex_protected_files_before_launch()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let project = directory.path().join("project");
    let marker = directory.path().join("target-ran");
    fs::create_dir(&home)?;
    fs::create_dir(&project)?;
    fs::create_dir(home.join(".codex"))?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", &home)
        .env("SANDY_TEST_MARKER", &marker)
        .current_dir(&project)
        .args([
            "run",
            "--agent",
            "codex",
            "--",
            "/bin/sh",
            "-c",
            "printf ran > \"$SANDY_TEST_MARKER\"",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Linux agent preset \"codex\" requires its write-protected files to exist before launch",
        ));

    assert!(!home.join(".codex/config.toml").exists());
    assert!(!home.join(".codex/hooks.json").exists());
    assert!(!marker.exists());
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
#[cfg(target_os = "macos")]
fn numbat_collector_grants_only_the_selected_local_host_port()
-> Result<(), Box<dyn std::error::Error>> {
    let mut default_port = Command::cargo_bin("sandy")?;
    default_port
        .args([
            "run",
            "--dry-run",
            "--block-net",
            "--numbat-collector",
            "--",
            "/bin/echo",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""service": "Numbat collector""#))
        .stdout(predicate::str::contains(r#""local_host_tcp_grants""#))
        .stdout(predicate::str::contains(r#""port": 4318"#))
        .stdout(predicate::str::contains(
            r#"(allow network-outbound (remote tcp \"localhost:4318\"))"#,
        ))
        .stdout(predicate::str::contains("localhost:4317").not())
        .stdout(predicate::str::contains("(allow network*)").not());

    let mut custom_port = Command::cargo_bin("sandy")?;
    custom_port
        .args([
            "run",
            "--dry-run",
            "--block-net",
            "--numbat-collector=8123",
            "--",
            "/bin/echo",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""port": 8123"#));

    let mut zero = Command::cargo_bin("sandy")?;
    zero.args([
        "run",
        "--dry-run",
        "--block-net",
        "--numbat-collector=0",
        "--",
        "/bin/echo",
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "collector port must be between 1 and 65535",
    ));

    let mut unrestricted = Command::cargo_bin("sandy")?;
    unrestricted
        .args(["run", "--dry-run", "--numbat-collector", "--", "/bin/echo"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "the following required arguments were not provided",
        ))
        .stderr(predicate::str::contains("--block-net"));
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn linux_rejects_local_host_tcp_exceptions_before_launch() -> Result<(), Box<dyn std::error::Error>>
{
    let mut command = Command::cargo_bin("sandy")?;
    command
        .args([
            "run",
            "--dry-run",
            "--block-net",
            "--numbat-collector",
            "--",
            "/bin/echo",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "local-host TCP exceptions are not supported by the Linux backend",
        ));
    Ok(())
}

#[test]
fn unknown_target_falls_back_to_generic_agent() -> Result<(), Box<dyn std::error::Error>> {
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
fn explicit_agent_overrides_detection() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    command
        .args(["run", "--dry-run", "--agent", "generic", "--", "/bin/echo"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""name": "generic""#))
        .stdout(predicate::str::contains(r#""detected": false"#));
    Ok(())
}

#[test]
fn complete_policy_file_replaces_agent_policy_and_resolves_relative_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let project = directory.path().join("project");
    let readable = directory.path().join("readable");
    let policy = directory.path().join("sandbox.json");
    fs::create_dir(&project)?;
    fs::create_dir(&readable)?;
    fs::write(
        &policy,
        r#"{
            "schema_version": 1,
            "network": "block_all",
            "allow_subprocesses": true,
            "grants": [
                {"path": "../readable", "access": "read", "scope": "subtree"}
            ]
        }"#,
    )?;

    let mut command = Command::cargo_bin("sandy")?;
    let output = command
        .current_dir(&project)
        .args([
            "run",
            "--dry-run",
            "--policy-file",
            policy.to_str().ok_or("policy path must be UTF-8")?,
            "--",
            "/bin/echo",
        ])
        .output()?;
    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    assert_eq!(document["dry_run_schema_version"], 7);
    assert_eq!(document["policy_source"]["kind"], "policy_file");
    assert_eq!(document["agent"]["name"], "generic");
    assert_eq!(document["network"], "block_all");
    assert_eq!(document["allow_subprocesses"], true);
    assert!(
        !document["policy_source"]
            .to_string()
            .contains(policy.to_string_lossy().as_ref())
    );
    let readable = fs::canonicalize(readable)?;
    assert!(document["file_grants"].as_array().is_some_and(|grants| {
        grants.iter().any(|grant| {
            grant["path"] == readable.to_string_lossy().as_ref()
                && grant["access"] == "read"
                && grant["scope"] == "subtree"
        })
    }));
    Ok(())
}

#[test]
fn policy_file_rejects_non_executable_cli_policy_and_authority_modifiers()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let policy = directory.path().join("sandbox.json");
    fs::write(&policy, r#"{"schema_version":1,"network":"block_all"}"#)?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .args([
            "run",
            "--policy-file",
            policy.to_str().ok_or("policy path must be UTF-8")?,
            "--",
            "/bin/echo",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "CLI execution requires allow_subprocesses to be true",
        ));

    let mut conflict = Command::cargo_bin("sandy")?;
    conflict
        .args([
            "run",
            "--policy-file",
            policy.to_str().ok_or("policy path must be UTF-8")?,
            "--read",
            directory.path().to_str().ok_or("test path must be UTF-8")?,
            "--",
            "/bin/echo",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));

    let mut agent_conflict = Command::cargo_bin("sandy")?;
    agent_conflict
        .args([
            "run",
            "--policy-file",
            policy.to_str().ok_or("policy path must be UTF-8")?,
            "--agent",
            "generic",
            "--",
            "/bin/echo",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
    Ok(())
}

#[test]
#[cfg(target_os = "macos")]
fn policy_file_disables_automatic_integration_discovery() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let codex_home = home.join(".codex");
    let project = directory.path().join("project");
    let target = directory.path().join("codex");
    let policy = directory.path().join("sandbox.json");
    fs::create_dir_all(&codex_home)?;
    fs::create_dir(&project)?;
    fs::write(codex_home.join("hooks.json"), "not json")?;
    fs::write(&target, "#!/bin/sh\nexit 0\n")?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
    fs::write(
        &policy,
        r#"{"schema_version":1,"network":"block_all","allow_subprocesses":true}"#,
    )?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", home)
        .current_dir(project)
        .args([
            "run",
            "--dry-run",
            "--policy-file",
            policy.to_str().ok_or("policy path must be UTF-8")?,
            "--",
            target.to_str().ok_or("target path must be UTF-8")?,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""kind": "policy_file""#));
    Ok(())
}

#[test]
fn agent_default_dry_run_reports_version_seven_source_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    let output = command
        .args(["run", "--dry-run", "--", "/bin/echo"])
        .output()?;
    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["dry_run_schema_version"], 7);
    assert_eq!(document["agent"]["name"], "generic");
    assert_eq!(document["policy_source"]["kind"], "agent_default");
    assert_eq!(sandy_core::MANIFEST_SCHEMA_V2, 2);
    Ok(())
}

#[test]
fn unknown_agent_name_fails_with_available_list() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    command
        .args(["run", "--agent", "ghost", "--", "/bin/echo"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ghost"))
        .stderr(predicate::str::contains("opencode"))
        .stderr(predicate::str::contains("base").not());
    Ok(())
}

#[test]
#[cfg(target_os = "macos")]
fn detected_agent_preset_is_announced() -> Result<(), Box<dyn std::error::Error>> {
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
            "applying detected agent preset 'codex'",
        ));
    Ok(())
}

#[test]
#[cfg(target_os = "macos")]
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
#[cfg(target_os = "macos")]
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

#[test]
#[cfg(target_os = "macos")]
fn required_numbat_hooks_must_be_installed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    fs::create_dir(&home)?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", home)
        .args([
            "run",
            "--dry-run",
            "--agent",
            "codex",
            "--numbat",
            "--",
            "/bin/echo",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--numbat requires installed hooks",
        ));
    Ok(())
}

#[test]
#[cfg(target_os = "macos")]
fn configured_numbat_hooks_contribute_only_when_present() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let codex = home.join(".codex");
    let numbat = home.join(".numbat");
    fs::create_dir_all(&codex)?;
    fs::create_dir(&numbat)?;
    let binary = directory.path().join("numbat-renamed");
    fs::write(&binary, "#!/bin/sh\nexit 0\n")?;
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
    fs::write(
        codex.join("hooks.json"),
        format!(
            r#"{{"hooks":{{"Stop":[{{"hooks":[{{"type":"command","command":"'{}' hook stop --agent codex --installed-by=numbat --output=file --output-file '$HOME/.numbat/findings.ndjson'"}}]}}]}}}}"#,
            binary.display()
        ),
    )?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", &home)
        .args([
            "run",
            "--dry-run",
            "--agent",
            "codex",
            "--numbat",
            "--",
            "/bin/echo",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""service": "Numbat""#))
        .stdout(predicate::str::contains(r#""enabled": true"#))
        .stdout(predicate::str::contains(
            numbat.join("findings.ndjson").to_string_lossy(),
        ));
    Ok(())
}

#[test]
#[cfg(target_os = "macos")]
fn unsupported_numbat_delivery_is_optional_unless_required()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let codex = home.join(".codex");
    fs::create_dir_all(&codex)?;
    let binary = directory.path().join("numbat");
    fs::write(&binary, "#!/bin/sh\nexit 0\n")?;
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
    fs::write(
        codex.join("hooks.json"),
        format!(
            r#"{{"hooks":{{"Stop":[{{"hooks":[{{"type":"command","command":"'{}' hook stop --agent codex --installed-by=numbat --output=http --http-url https://example.test"}}]}}]}}}}"#,
            binary.display()
        ),
    )?;

    let mut optional = Command::cargo_bin("sandy")?;
    optional
        .env("HOME", &home)
        .args(["run", "--dry-run", "--agent", "codex", "--", "/bin/echo"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "optional Numbat runtime control unavailable; continuing without it",
        ));

    let mut required = Command::cargo_bin("sandy")?;
    required
        .env("HOME", &home)
        .args([
            "run",
            "--dry-run",
            "--agent",
            "codex",
            "--numbat",
            "--",
            "/bin/echo",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "direct HTTP hook delivery is not supported inside Sandy",
        ));
    Ok(())
}
