#![cfg(target_os = "macos")]

use std::{
    env, fs,
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::Command as StdCommand,
};

use assert_cmd::Command;
use predicates::prelude::*;
use sandy_core::{
    AbsolutePath, AccessMode, CommandSpec, FileGrant, LaunchManifestV1, MANIFEST_SCHEMA_V1,
    NetworkPolicy, OsValue, PathScope, PolicySpec, UnixSocketGrant, UnixSocketOperation,
    ValidatedLaunch,
};

const SOCKET_PROBE_MODE: &str = "SANDY_TEST_EXACT_SOCKET_PROBE";
const SOCKET_PROBE_ROOT: &str = "SANDY_TEST_SOCKET_ROOT";
const SOCKET_PROBE_ALLOWED: &str = "SANDY_TEST_SOCKET_ALLOWED";
const SOCKET_PROBE_DENIED: &str = "SANDY_TEST_SOCKET_DENIED";
const SOCKET_PROBE_TCP: &str = "SANDY_TEST_SOCKET_TCP";

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
fn allows_timezone_runtime_data_without_opening_adjacent_databases()
-> Result<(), Box<dyn std::error::Error>> {
    let project = tempfile::tempdir()?;

    let mut timezone = Command::cargo_bin("sandy")?;
    timezone
        .current_dir(project.path())
        .args([
            "run",
            "--",
            "/usr/bin/head",
            "-c",
            "1",
            "/private/var/db/timezone/zoneinfo/UTC",
        ])
        .assert()
        .success();

    let mut adjacent = Command::cargo_bin("sandy")?;
    adjacent
        .current_dir(project.path())
        .args(["run", "--", "/bin/ls", "/private/var/db/receipts"])
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
fn supplies_public_tls_roots_without_exposing_keychain_items()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let project = root.path().join("project");
    fs::create_dir(&project)?;
    let keychain = project.join("test.keychain-db");
    let account = "sandy-test-account";
    let service = "sandy-test-service";
    let sentinel = "non-secret-test-value";

    security(&["create-keychain", "-p", "test-password"], &keychain)?;
    security(
        &[
            "add-generic-password",
            "-a",
            account,
            "-s",
            service,
            "-w",
            sentinel,
        ],
        &keychain,
    )?;
    security(&["unlock-keychain", "-p", "test-password"], &keychain)?;
    assert_eq!(read_test_keychain(account, service, &keychain)?, sentinel);

    let mut roots = Command::cargo_bin("sandy")?;
    roots
        .env_remove("SSL_CERT_FILE")
        .current_dir(&project)
        .args([
            "run",
            "--",
            "/bin/sh",
            "-c",
            "test -n \"$SSL_CERT_FILE\" && /usr/bin/grep -q 'BEGIN CERTIFICATE' \"$SSL_CERT_FILE\"",
        ])
        .assert()
        .success();

    let mut denied = Command::cargo_bin("sandy")?;
    denied
        .env_remove("SSL_CERT_FILE")
        .current_dir(&project)
        .args([
            "run",
            "--",
            "/usr/bin/security",
            "find-generic-password",
            "-a",
            account,
            "-s",
            service,
            "-w",
        ])
        .arg(&keychain)
        .assert()
        .failure()
        .stdout(predicate::str::contains(sentinel).not());
    assert_eq!(read_test_keychain(account, service, &keychain)?, sentinel);
    Ok(())
}

fn security(arguments: &[&str], keychain: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let status = StdCommand::new("/usr/bin/security")
        .args(arguments)
        .arg(keychain)
        .status()?;
    if !status.success() {
        return Err(format!("test Keychain setup failed: {status}").into());
    }
    Ok(())
}

fn read_test_keychain(
    account: &str,
    service: &str,
    keychain: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let output = StdCommand::new("/usr/bin/security")
        .args(["find-generic-password", "-a", account, "-s", service, "-w"])
        .arg(keychain)
        .output()?;
    if !output.status.success() {
        return Err(format!("test Keychain read failed: {}", output.status).into());
    }
    Ok(String::from_utf8(output.stdout)?.trim_end().to_owned())
}

#[test]
#[ignore = "irreversibly applies Seatbelt; run on a host, not inside another sandbox"]
fn exact_unix_socket_connect_does_not_open_adjacent_services_or_ip_networking()
-> Result<(), Box<dyn std::error::Error>> {
    if env::var_os(SOCKET_PROBE_MODE).is_some() {
        return run_exact_socket_probe();
    }

    let root = tempfile::Builder::new()
        .prefix("sandy-exact-socket-")
        .tempdir_in("/tmp")?;
    let allowed = root.path().join("allowed.sock");
    let denied = root.path().join("denied.sock");
    let _allowed_listener = UnixListener::bind(&allowed)?;
    let _denied_listener = UnixListener::bind(&denied)?;
    let tcp_listener = TcpListener::bind("127.0.0.1:0")?;
    let tcp_address = tcp_listener.local_addr()?;

    let status = StdCommand::new(env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "exact_unix_socket_connect_does_not_open_adjacent_services_or_ip_networking",
        ])
        .env(SOCKET_PROBE_MODE, "1")
        .env(SOCKET_PROBE_ROOT, root.path())
        .env(SOCKET_PROBE_ALLOWED, &allowed)
        .env(SOCKET_PROBE_DENIED, &denied)
        .env(SOCKET_PROBE_TCP, tcp_address.to_string())
        .status()?;

    assert!(
        status.success(),
        "sacrificial socket probe failed: {status}"
    );
    Ok(())
}

fn run_exact_socket_probe() -> Result<(), Box<dyn std::error::Error>> {
    let root = required_probe_path(SOCKET_PROBE_ROOT)?;
    let allowed = required_probe_path(SOCKET_PROBE_ALLOWED)?;
    let denied = required_probe_path(SOCKET_PROBE_DENIED)?;
    let tcp_address: SocketAddr = env::var(SOCKET_PROBE_TCP)?.parse()?;
    let canonical_root = fs::canonicalize(&root)?;
    let mut socket_paths = vec![absolute(&allowed)?, absolute(&fs::canonicalize(&allowed)?)?];
    socket_paths.sort();
    socket_paths.dedup();

    let manifest = LaunchManifestV1 {
        schema_version: MANIFEST_SCHEMA_V1,
        command: CommandSpec {
            program: OsValue::from_os_str(std::ffi::OsStr::new("/bin/true")),
            arguments: Vec::new(),
        },
        working_directory: absolute(&canonical_root)?,
        environment: Vec::new(),
        policy: PolicySpec {
            files: vec![FileGrant {
                path: absolute(&canonical_root)?,
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }],
            protected_paths: Vec::new(),
            protected_write_paths: socket_paths.clone(),
            unix_sockets: socket_paths
                .into_iter()
                .map(|path| UnixSocketGrant {
                    path,
                    operation: UnixSocketOperation::Connect,
                })
                .collect(),
            network: NetworkPolicy::BlockAll,
        },
    };
    let launch = ValidatedLaunch::try_from(manifest)?;
    let profile = sandy_seatbelt::compile(launch.policy())?;
    sandy_seatbelt::apply(&profile)?;

    let _allowed_stream = UnixStream::connect(&allowed)?;
    assert_permission_denied(
        fs::remove_file(&allowed),
        "write to the read-only socket path",
    )?;
    assert_permission_denied(UnixStream::connect(&denied), "sibling Unix socket connect")?;
    assert_permission_denied(
        UnixListener::bind(root.join("bind.sock")),
        "Unix socket bind with connect-only authority",
    )?;
    assert_permission_denied(TcpStream::connect(tcp_address), "loopback TCP connect")?;
    Ok(())
}

fn required_probe_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name}").into())
}

fn absolute(path: &Path) -> Result<AbsolutePath, Box<dyn std::error::Error>> {
    let value = path
        .to_str()
        .ok_or_else(|| format!("non-UTF-8 test path: {}", path.display()))?;
    Ok(AbsolutePath::new(value.to_owned())?)
}

fn assert_permission_denied<T>(
    result: std::io::Result<T>,
    operation: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let error = result
        .err()
        .ok_or_else(|| format!("{operation} unexpectedly succeeded"))?;
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied,
        "{operation} failed for an unexpected reason: {error}"
    );
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
fn allows_terminal_control_but_denies_unrelated_device_ioctls()
-> Result<(), Box<dyn std::error::Error>> {
    let project = tempfile::tempdir()?;
    let sandy = Command::cargo_bin("sandy")?;
    let sandy_program = sandy.get_program().to_owned();

    let mut terminal = Command::new("/usr/bin/script");
    terminal
        .current_dir(project.path())
        .args(["-q", "/dev/null"])
        .arg(&sandy_program)
        .args(["run", "--", "/bin/stty", "-a"])
        .assert()
        .success()
        .stdout(predicate::str::contains("speed"));

    let script = r#"begin
  File.open("/dev/null") { |file| file.ioctl(0) }
rescue Errno::EPERM
  exit 0
rescue SystemCallError => error
  warn error.full_message
  exit 1
end
exit 2
"#;
    let mut unrelated_device = Command::cargo_bin("sandy")?;
    unrelated_device
        .current_dir(project.path())
        .args(["run", "--", "/usr/bin/ruby", "--disable-gems", "-e", script])
        .assert()
        .success();
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
