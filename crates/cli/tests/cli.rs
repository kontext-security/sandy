use std::{fs, os::unix::fs::PermissionsExt as _, sync::mpsc, thread, time::Duration};

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
fn run_help_documents_explicit_user_profile_files() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    command
        .args(["run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--profile-file <PATH>"))
        .stdout(predicate::str::contains("--execute <PATH>"))
        .stdout(predicate::str::contains("built-in profile"));
    Ok(())
}

#[test]
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
        .env_remove("SSL_CERT_FILE")
        .args(["run", "--dry-run", "--", "/bin/echo", "hello"])
        .output()?;
    assert!(output.status.success());

    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["dry_run_schema_version"], 5);
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
            "allow_subprocesses",
            "arguments",
            "command",
            "dry_run_schema_version",
            "executable_grants",
            "file_grants",
            "file_metadata",
            "local_host_tcp_grants",
            "network",
            "profile",
            "runtime_controls",
            "runtime_compatibility",
            "seatbelt_profile",
            "unix_socket_grants",
            "working_directory",
        ])
    );

    let controls = document["runtime_controls"]
        .as_array()
        .ok_or("runtime_controls must be an array")?;
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

    let grants = document["file_grants"]
        .as_array()
        .ok_or("file_grants must be an array")?;
    assert!(grants.iter().any(|grant| {
        grant["path"] == "/" && grant["access"] == "read" && grant["scope"] == "exact"
    }));
    assert!(grants.iter().any(|grant| {
        grant["path"] == "/bin" && grant["access"] == "read" && grant["scope"] == "subtree"
    }));
    assert!(grants.iter().any(|grant| {
        grant["path"] == "/dev/null" && grant["access"] == "read_write" && grant["scope"] == "exact"
    }));
    assert_eq!(document["file_metadata"], "allow");
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
    assert!(
        document["seatbelt_profile"]
            .as_str()
            .ok_or("seatbelt_profile must be a string")?
            .contains("file-read-metadata")
    );
    Ok(())
}

#[test]
fn cli_file_and_executable_grants_are_independent() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let readable = directory.path().join("readable");
    let writable = directory.path().join("writable");
    let executable = directory.path().join("executable");
    fs::create_dir(&home)?;
    fs::create_dir(&readable)?;
    fs::create_dir(&writable)?;
    fs::create_dir(&executable)?;

    let mut command = Command::cargo_bin("sandy")?;
    let output = command
        .env("HOME", home)
        .args([
            "run",
            "--dry-run",
            "--read",
            readable.to_str().ok_or("test path must be UTF-8")?,
            "--read-write",
            writable.to_str().ok_or("test path must be UTF-8")?,
            "--execute",
            executable.to_str().ok_or("test path must be UTF-8")?,
            "--",
            "/bin/echo",
        ])
        .output()?;
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
fn profile_and_profile_file_conflict_at_the_cli_boundary() -> Result<(), Box<dyn std::error::Error>>
{
    let mut command = Command::cargo_bin("sandy")?;
    command
        .args([
            "run",
            "--profile",
            "generic",
            "--profile-file",
            "session.json",
            "--",
            "/bin/echo",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
    Ok(())
}

#[test]
fn profile_file_may_be_supplied_only_once() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    command
        .args([
            "run",
            "--profile-file",
            "first.json",
            "--profile-file",
            "second.json",
            "--",
            "/bin/echo",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "argument '--profile-file <PATH>' cannot be used multiple times",
        ));
    Ok(())
}

#[test]
fn user_profile_composes_with_one_embedded_base_and_reports_safe_source()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let readable = directory.path().join("readable");
    let executable = directory.path().join("executable");
    let protected = directory.path().join("protected");
    let immutable = directory.path().join("immutable.json");
    let profile = directory.path().join("session.json");
    fs::create_dir(&home)?;
    fs::create_dir(&readable)?;
    fs::create_dir(&executable)?;
    fs::create_dir(&protected)?;
    fs::write(&immutable, "{}")?;
    fs::write(
        &profile,
        format!(
            r#"{{
                "schema_version": 1,
                "name": "team-session",
                "extends": "generic",
                "grants": [{{
                    "path": "{}",
                    "access": "read",
                    "scope": "subtree"
                }}],
                "executable_grants": [{{
                    "path": "{}",
                    "scope": "subtree"
                }}],
                "deny_subtrees": ["{}"],
                "deny_write_exact": ["{}"]
            }}"#,
            readable.display(),
            executable.display(),
            protected.display(),
            immutable.display(),
        ),
    )?;

    let mut command = Command::cargo_bin("sandy")?;
    let output = command
        .env("HOME", &home)
        .args([
            "run",
            "--dry-run",
            "--profile-file",
            profile.to_str().ok_or("profile path must be UTF-8")?,
            "--",
            "/bin/echo",
        ])
        .output()?;
    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    assert_eq!(document["dry_run_schema_version"], 5);
    assert_eq!(document["profile"]["name"], "team-session");
    assert_eq!(document["profile"]["source"], "user_file");
    assert_eq!(document["profile"]["base"], "generic");
    assert_eq!(document["profile"]["detected"], false);
    let metadata = document["profile"].to_string();
    assert!(!metadata.contains(profile.to_string_lossy().as_ref()));
    assert!(!metadata.contains("schema_version"));

    let readable = fs::canonicalize(readable)?;
    let executable = fs::canonicalize(executable)?;
    let grants = document["file_grants"]
        .as_array()
        .ok_or("file_grants must be an array")?;
    let executables = document["executable_grants"]
        .as_array()
        .ok_or("executable_grants must be an array")?;
    assert!(grants.iter().any(|grant| {
        grant["path"] == readable.to_string_lossy().as_ref()
            && grant["access"] == "read"
            && grant["scope"] == "subtree"
    }));
    assert!(
        !executables
            .iter()
            .any(|grant| { grant["path"] == readable.to_string_lossy().as_ref() })
    );
    assert!(executables.iter().any(|grant| {
        grant["path"] == executable.to_string_lossy().as_ref() && grant["scope"] == "subtree"
    }));
    assert!(
        !grants
            .iter()
            .any(|grant| { grant["path"] == executable.to_string_lossy().as_ref() })
    );

    let rendered = document["seatbelt_profile"]
        .as_str()
        .ok_or("seatbelt_profile must be a string")?;
    for denied in [&profile, &protected, &immutable] {
        assert!(rendered.contains(denied.to_string_lossy().as_ref()));
    }
    Ok(())
}

#[test]
fn user_protected_alias_conflicts_with_a_grant_to_its_canonical_target()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let target = directory.path().join("sensitive-target");
    let alias = directory.path().join("sensitive-alias");
    let profile = directory.path().join("session.json");
    fs::create_dir(&home)?;
    fs::create_dir(&target)?;
    std::os::unix::fs::symlink(&target, &alias)?;
    fs::write(
        &profile,
        format!(
            r#"{{
                "schema_version": 1,
                "name": "session",
                "extends": "generic",
                "grants": [{{
                    "path": "{}",
                    "access": "read",
                    "scope": "subtree"
                }}],
                "deny_subtrees": ["{}"]
            }}"#,
            target.display(),
            alias.display(),
        ),
    )?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", home)
        .args([
            "run",
            "--dry-run",
            "--profile-file",
            profile.to_str().ok_or("profile path must be UTF-8")?,
            "--",
            "/bin/echo",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "user profile grant 1 overlaps protected data",
        ))
        .stderr(predicate::str::contains(target.to_string_lossy().as_ref()).not())
        .stderr(predicate::str::contains(alias.to_string_lossy().as_ref()).not());
    Ok(())
}

#[test]
fn user_protected_working_directory_error_is_positioned_and_redacted()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let protected_working_directory = directory
        .path()
        .join("sentinel-user-protected-working-directory");
    let profile = directory.path().join("session.json");
    let marker = protected_working_directory.join("target-ran");
    fs::create_dir(&home)?;
    fs::create_dir(&protected_working_directory)?;
    fs::write(
        &profile,
        format!(
            r#"{{
                "schema_version": 1,
                "name": "session",
                "extends": "generic",
                "deny_subtrees": ["{}"]
            }}"#,
            protected_working_directory.display(),
        ),
    )?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", home)
        .current_dir(&protected_working_directory)
        .args([
            "run",
            "--profile-file",
            profile.to_str().ok_or("profile path must be UTF-8")?,
            "--",
            "/usr/bin/touch",
            "target-ran",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "user profile deny_subtrees entry 1 overlaps the working directory",
        ))
        .stderr(
            predicate::str::contains(protected_working_directory.to_string_lossy().as_ref()).not(),
        );
    assert!(!marker.exists());
    Ok(())
}

#[test]
fn user_protected_target_error_is_positioned_and_redacted() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let project = directory.path().join("project");
    let profile = directory.path().join("session.json");
    fs::create_dir(&home)?;
    fs::create_dir(&project)?;
    fs::write(
        &profile,
        r#"{
            "schema_version": 1,
            "name": "session",
            "extends": "generic",
            "deny_subtrees": ["/bin/echo"]
        }"#,
    )?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", home)
        .current_dir(project)
        .args([
            "run",
            "--dry-run",
            "--profile-file",
            profile.to_str().ok_or("profile path must be UTF-8")?,
            "--",
            "/bin/echo",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "user profile deny_subtrees entry 1 overlaps a required launch path",
        ))
        .stderr(predicate::str::contains("/bin/echo").not())
        .stderr(predicate::str::contains("/usr/bin/echo").not());
    Ok(())
}

#[test]
fn embedded_profile_dry_run_reports_version_five_source_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::cargo_bin("sandy")?;
    let output = command
        .args(["run", "--dry-run", "--", "/bin/echo"])
        .output()?;
    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["dry_run_schema_version"], 5);
    assert_eq!(document["profile"]["source"], "embedded");
    assert!(document["profile"]["base"].is_null());
    assert_eq!(sandy_core::MANIFEST_SCHEMA_V2, 2);
    Ok(())
}

#[test]
fn missing_user_profile_grants_fail_before_target_execution()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let profile = directory.path().join("session.json");
    let marker = directory.path().join("target-ran");
    let missing = directory.path().join("missing-sensitive-policy-path");
    fs::create_dir(&home)?;
    fs::write(
        &profile,
        format!(
            r#"{{
                "schema_version": 1,
                "name": "session",
                "extends": "generic",
                "grants": [{{
                    "path": "{}",
                    "access": "read",
                    "scope": "exact"
                }}]
            }}"#,
            missing.display()
        ),
    )?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", home)
        .args([
            "run",
            "--profile-file",
            profile.to_str().ok_or("profile path must be UTF-8")?,
            "--",
            "/usr/bin/touch",
            marker.to_str().ok_or("marker path must be UTF-8")?,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "user profile grant 1 is unavailable",
        ))
        .stderr(predicate::str::contains(missing.to_string_lossy().as_ref()).not());
    assert!(!marker.exists());
    Ok(())
}

#[test]
fn missing_user_profile_executable_grants_fail_before_target_execution()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let profile = directory.path().join("session.json");
    let marker = directory.path().join("target-ran");
    let missing = directory.path().join("missing-executable-policy-path");
    fs::create_dir(&home)?;
    fs::write(
        &profile,
        format!(
            r#"{{
                "schema_version": 1,
                "name": "session",
                "extends": "generic",
                "executable_grants": [{{
                    "path": "{}",
                    "scope": "exact"
                }}]
            }}"#,
            missing.display()
        ),
    )?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", home)
        .args([
            "run",
            "--profile-file",
            profile.to_str().ok_or("profile path must be UTF-8")?,
            "--",
            "/usr/bin/touch",
            marker.to_str().ok_or("marker path must be UTF-8")?,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "user profile executable_grants entry 1 is unavailable",
        ))
        .stderr(predicate::str::contains(missing.to_string_lossy().as_ref()).not());
    assert!(!marker.exists());
    Ok(())
}

#[test]
fn protected_user_profile_grant_errors_are_redacted() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let protected = home.join(".ssh/sensitive-policy-sentinel");
    let profile = directory.path().join("session.json");
    fs::create_dir_all(protected.parent().ok_or("protected path needs a parent")?)?;
    fs::write(&protected, "not secret")?;
    fs::write(
        &profile,
        format!(
            r#"{{
                "schema_version": 1,
                "name": "session",
                "extends": "generic",
                "grants": [{{
                    "path": "{}",
                    "access": "read",
                    "scope": "exact"
                }}]
            }}"#,
            protected.display()
        ),
    )?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", home)
        .args([
            "run",
            "--dry-run",
            "--profile-file",
            profile.to_str().ok_or("profile path must be UTF-8")?,
            "--",
            "/bin/echo",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "user profile grant 1 overlaps protected data",
        ))
        .stderr(predicate::str::contains("sensitive-policy-sentinel").not());
    Ok(())
}

#[test]
fn user_profile_write_protection_errors_are_redacted() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let profile = directory.path().join("session.json");
    let loop_path = directory.path().join("sensitive-protection-sentinel");
    fs::create_dir(&home)?;
    std::os::unix::fs::symlink(&loop_path, &loop_path)?;
    fs::write(
        &profile,
        format!(
            r#"{{
                "schema_version": 1,
                "name": "session",
                "extends": "generic",
                "deny_write_exact": ["{}"]
            }}"#,
            loop_path.display()
        ),
    )?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", home)
        .args([
            "run",
            "--dry-run",
            "--profile-file",
            profile.to_str().ok_or("profile path must be UTF-8")?,
            "--",
            "/bin/echo",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "user profile deny_write_exact entry 1 could not be resolved safely",
        ))
        .stderr(predicate::str::contains("sensitive-protection-sentinel").not());
    Ok(())
}

#[test]
fn user_profile_input_is_bounded_regular_utf8_and_strict() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    fs::create_dir(&home)?;

    let missing = directory.path().join("missing.json");
    let malformed = directory.path().join("malformed.json");
    let oversized = directory.path().join("oversized.json");
    let non_utf8 = directory.path().join("non-utf8.json");
    let non_regular = directory.path().join("profile-directory");
    let unknown = directory.path().join("unknown.json");
    let bad_version = directory.path().join("version.json");
    fs::write(&malformed, "secret-material is not JSON")?;
    fs::write(
        &oversized,
        vec![b' '; sandy_core::MAX_USER_PROFILE_SOURCE_BYTES + 1],
    )?;
    fs::write(&non_utf8, [0xff, 0xfe])?;
    fs::create_dir(&non_regular)?;
    fs::write(
        &unknown,
        r#"{
            "schema_version": 1,
            "name": "session",
            "extends": "generic",
            "sensitive_policy_sentinel": "must-not-appear"
        }"#,
    )?;
    fs::write(
        &bad_version,
        r#"{ "schema_version": 2, "name": "session", "extends": "generic" }"#,
    )?;

    for (path, message) in [
        (&missing, "resolve user profile file"),
        (&malformed, "malformed or does not match its schema"),
        (&oversized, "source-size limit"),
        (&non_utf8, "strict UTF-8 JSON"),
        (&non_regular, "regular file"),
        (&unknown, "malformed or does not match its schema"),
        (&bad_version, "unsupported schema version 2"),
    ] {
        let mut command = Command::cargo_bin("sandy")?;
        command
            .env("HOME", &home)
            .args([
                "run",
                "--dry-run",
                "--profile-file",
                path.to_str().ok_or("test path must be UTF-8")?,
                "--",
                "/bin/echo",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains(message))
            .stderr(predicate::str::contains("secret-material").not())
            .stderr(predicate::str::contains("sensitive_policy_sentinel").not())
            .stderr(predicate::str::contains("must-not-appear").not());
    }
    Ok(())
}

#[test]
fn expanded_user_protections_and_source_denials_fit_the_final_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    let canonical_parent = directory.path().join("canonical-parent");
    let lexical_parent = directory.path().join("lexical-parent");
    let stored_profile = directory.path().join("stored-profile.json");
    let profile = directory.path().join("session.json");
    fs::create_dir(&home)?;
    fs::create_dir(&canonical_parent)?;
    std::os::unix::fs::symlink(&canonical_parent, &lexical_parent)?;
    let deny_subtrees = (0..508)
        .map(|index| lexical_parent.join(format!("future-{index}")))
        .collect::<Vec<_>>();
    fs::write(
        &stored_profile,
        serde_json::json!({
            "schema_version": 1,
            "name": "session",
            "extends": "generic",
            "deny_subtrees": deny_subtrees,
        })
        .to_string(),
    )?;
    std::os::unix::fs::symlink(&stored_profile, &profile)?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", home)
        .args([
            "run",
            "--dry-run",
            "--profile-file",
            profile.to_str().ok_or("profile path must be UTF-8")?,
            "--",
            "/bin/echo",
        ])
        .assert()
        .success();
    Ok(())
}

#[test]
fn user_profile_fifo_is_rejected_without_blocking() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let fifo = directory.path().join("session.json");
    assert!(
        std::process::Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()?
            .success()
    );

    let mut command = Command::cargo_bin("sandy")?;
    command.args([
        "run",
        "--dry-run",
        "--profile-file",
        fifo.to_str().ok_or("FIFO path must be UTF-8")?,
        "--",
        "/bin/echo",
    ]);
    let (sender, receiver) = mpsc::channel();
    let child = thread::spawn(move || sender.send(command.output()).is_ok());
    let output = receiver.recv_timeout(Duration::from_secs(2))??;

    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("regular file"));
    assert_eq!(child.join().ok(), Some(true));
    Ok(())
}

#[test]
fn user_profile_rejects_unknown_abstract_and_colliding_embedded_names()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    fs::create_dir(&home)?;

    for (name, base, message) in [
        ("session", "missing", "unknown embedded profile"),
        ("session", "base", "inheritance-only profile"),
        ("generic", "generic", "collides with an embedded profile"),
    ] {
        let profile = directory.path().join(format!("{name}-{base}.json"));
        fs::write(
            &profile,
            format!(r#"{{ "schema_version": 1, "name": "{name}", "extends": "{base}" }}"#),
        )?;
        let mut command = Command::cargo_bin("sandy")?;
        command
            .env("HOME", &home)
            .args([
                "run",
                "--dry-run",
                "--profile-file",
                profile.to_str().ok_or("test path must be UTF-8")?,
                "--",
                "/bin/echo",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains(message));
    }
    Ok(())
}

#[test]
fn user_profiles_are_never_discovered_implicitly() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let home = directory.path().join("home");
    fs::create_dir(&home)?;
    fs::write(directory.path().join("sandy-profile.json"), "not JSON")?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .current_dir(directory.path())
        .env("HOME", home)
        .args(["run", "--dry-run", "--", "/bin/echo"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""source": "embedded""#));
    Ok(())
}

#[test]
fn empty_user_profile_preserves_optional_base_paths_without_home()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let profile = directory.path().join("session.json");
    fs::write(
        &profile,
        r#"{
            "schema_version": 1,
            "name": "session",
            "extends": "generic"
        }"#,
    )?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env_remove("HOME")
        .args([
            "run",
            "--dry-run",
            "--profile-file",
            profile.to_str().ok_or("profile path must be UTF-8")?,
            "--",
            "/bin/echo",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""source": "user_file""#));

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

#[test]
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
            "--profile",
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
            "--profile",
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
        .args(["run", "--dry-run", "--profile", "codex", "--", "/bin/echo"])
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
            "--profile",
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
