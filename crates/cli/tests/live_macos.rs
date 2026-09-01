#![cfg(target_os = "macos")]

use std::{
    env, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::unix::{
        fs::PermissionsExt as _,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::Command as StdCommand,
    time::Duration,
};

use assert_cmd::Command;
use predicates::prelude::*;
use sandy_core::{
    AbsolutePath, AccessMode, CommandSpec, FileGrant, FileMetadataPolicy, LaunchManifestV2,
    LocalHostTcpGrant, LocalHostTcpOperation, MANIFEST_SCHEMA_V2, NetworkPolicy, OsValue,
    PathScope, PolicySpec, RuntimeCompatibility, TcpPort, UnixSocketGrant, UnixSocketOperation,
    ValidatedLaunch, WriteProtection,
};

const SOCKET_PROBE_MODE: &str = "SANDY_TEST_EXACT_SOCKET_PROBE";
const SOCKET_PROBE_ROOT: &str = "SANDY_TEST_SOCKET_ROOT";
const SOCKET_PROBE_ALLOWED: &str = "SANDY_TEST_SOCKET_ALLOWED";
const SOCKET_PROBE_DENIED: &str = "SANDY_TEST_SOCKET_DENIED";
const SOCKET_PROBE_TCP: &str = "SANDY_TEST_SOCKET_TCP";
const WRITE_PROBE_MODE: &str = "SANDY_TEST_SCOPED_WRITE_PROBE";
const WRITE_PROBE_ROOT: &str = "SANDY_TEST_WRITE_ROOT";
const WRITE_PROBE_PROTECTED: &str = "SANDY_TEST_WRITE_PROTECTED";
const TCP_PROBE_MODE: &str = "SANDY_TEST_EXACT_TCP_PROBE";
const TCP_PROBE_ROOT: &str = "SANDY_TEST_TCP_ROOT";
const TCP_PROBE_ALLOWED: &str = "SANDY_TEST_TCP_ALLOWED";
const TCP_PROBE_SAME_HOST: &str = "SANDY_TEST_TCP_SAME_HOST";
const TCP_PROBE_DENIED: &str = "SANDY_TEST_TCP_DENIED";
const TCP_PROBE_IPV6: &str = "SANDY_TEST_TCP_IPV6";
const TCP_PROBE_UNIX: &str = "SANDY_TEST_TCP_UNIX";

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
fn explicit_executable_grants_allow_only_selected_descendant_tools()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let home = root.path().join("home");
    let project = root.path().join("project");
    let allowed_root = root.path().join("allowed-tools");
    let read_only_root = root.path().join("read-only-tools");
    let adjacent_root = root.path().join("adjacent-tools");
    for path in [
        &home,
        &project,
        &allowed_root,
        &read_only_root,
        &adjacent_root,
    ] {
        fs::create_dir(path)?;
    }
    let allowed = write_test_tool(&allowed_root.join("tool"))?;
    let read_only = write_test_tool(&read_only_root.join("tool"))?;
    let adjacent = write_test_tool(&adjacent_root.join("tool"))?;

    let cli_allowed_marker = project.join("cli-allowed");
    let cli_read_only_marker = project.join("cli-read-only");
    let cli_adjacent_marker = project.join("cli-adjacent");
    let mut cli = Command::cargo_bin("sandy")?;
    cli.env("HOME", &home)
        .current_dir(&project)
        .args(["run", "--read"])
        .arg(&allowed_root)
        .args(["--read"])
        .arg(&read_only_root)
        .args(["--read"])
        .arg(&adjacent_root)
        .args(["--execute"])
        .arg(&allowed_root)
        .args(["--", "/bin/sh", "-c", descendant_tool_probe(), "tool-probe"])
        .arg(&allowed)
        .arg(&read_only)
        .arg(&adjacent)
        .arg(&cli_allowed_marker)
        .arg(&cli_read_only_marker)
        .arg(&cli_adjacent_marker)
        .assert()
        .success();
    assert!(cli_allowed_marker.is_file());
    assert!(!cli_read_only_marker.exists());
    assert!(!cli_adjacent_marker.exists());
    Ok(())
}

fn write_test_tool(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    fs::write(path, "#!/bin/sh\n/usr/bin/touch \"$1\"\n")?;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)?;
    Ok(path.to_owned())
}

fn descendant_tool_probe() -> &'static str {
    r#"
        "$1" "$4" &&
        ! "$2" "$5" 2>/dev/null &&
        ! "$3" "$6" 2>/dev/null
    "#
}

#[test]
#[ignore = "irreversibly applies Seatbelt; run on a host, not inside another sandbox"]
fn policy_file_source_and_declared_denials_override_the_working_directory_grant()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let project = root.path().join("project");
    let stored_policy = project.join("stored-policy.json");
    let policy_link = project.join("sandbox.json");
    let protected_target = project.join("protected-target.txt");
    let protected_alias = project.join("protected-alias.txt");
    let adjacent = project.join("adjacent.txt");
    fs::create_dir(&project)?;
    fs::write(&protected_target, "protected")?;
    std::os::unix::fs::symlink(&protected_target, &protected_alias)?;
    fs::write(&adjacent, "before")?;
    fs::write(
        &stored_policy,
        format!(
            r#"{{
                "schema_version": 1,
                "network": "block_all",
                "allow_subprocesses": true,
                "deny_subtrees": ["{}"]
            }}"#,
            protected_alias.display(),
        ),
    )?;
    std::os::unix::fs::symlink(&stored_policy, &policy_link)?;

    let script = r#"
        ! /bin/cat "$1" >/dev/null 2>&1 &&
        ! /usr/bin/printf changed > "$1" 2>/dev/null &&
        ! /bin/cat "$2" >/dev/null 2>&1 &&
        ! /usr/bin/printf changed > "$2" 2>/dev/null &&
        ! /bin/cat "$3" >/dev/null 2>&1 &&
        ! /usr/bin/printf changed > "$3" 2>/dev/null &&
        ! /bin/cat "$4" >/dev/null 2>&1 &&
        ! /usr/bin/printf changed > "$4" 2>/dev/null &&
        /usr/bin/printf changed > "$5"
    "#;
    let mut command = Command::cargo_bin("sandy")?;
    command
        .current_dir(&project)
        .args(["run", "--policy-file"])
        .arg(&policy_link)
        .args(["--", "/bin/sh", "-c", script, "policy-probe"])
        .arg(&policy_link)
        .arg(&stored_policy)
        .arg(&protected_alias)
        .arg(&protected_target)
        .arg(&adjacent)
        .assert()
        .success();

    assert!(fs::read_to_string(&stored_policy)?.contains("schema_version"));
    assert_eq!(fs::read_to_string(&protected_target)?, "protected");
    assert_eq!(fs::read_to_string(adjacent)?, "changed");
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
fn recursive_write_protection_overrides_a_broader_grant() -> Result<(), Box<dyn std::error::Error>>
{
    if env::var_os(WRITE_PROBE_MODE).is_some() {
        return run_scoped_write_probe();
    }

    let root = tempfile::tempdir()?;
    let protected = root.path().join("config/operator-rules");
    fs::create_dir_all(&protected)?;
    fs::write(protected.join("policy.json"), "original")?;

    let status = StdCommand::new(env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "recursive_write_protection_overrides_a_broader_grant",
        ])
        .env(WRITE_PROBE_MODE, "1")
        .env(WRITE_PROBE_ROOT, root.path())
        .env(WRITE_PROBE_PROTECTED, &protected)
        .status()?;

    assert!(status.success(), "sacrificial write probe failed: {status}");
    assert_eq!(
        fs::read_to_string(protected.join("policy.json"))?,
        "original"
    );
    Ok(())
}

#[test]
#[ignore = "irreversibly applies Seatbelt; run on a host, not inside another sandbox"]
fn numbat_runtime_resources_preserve_operator_integrity() -> Result<(), Box<dyn std::error::Error>>
{
    let root = tempfile::tempdir()?;
    let home = root.path().join("home");
    let project = root.path().join("project");
    let codex = home.join(".codex");
    let numbat_home = home.join(".numbat");
    let rules_parent = project.join("operator");
    let rules = rules_parent.join("rules");
    fs::create_dir_all(&codex)?;
    fs::create_dir(&numbat_home)?;
    fs::create_dir(&project)?;
    fs::create_dir(&rules_parent)?;
    fs::create_dir(&rules)?;
    let rule = rules.join("operator.yaml");
    fs::write(&rule, "original-rule")?;

    let binary = root.path().join("numbat-renamed");
    fs::write(&binary, "#!/bin/sh\nexit 0\n")?;
    let mut permissions = fs::metadata(&binary)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&binary, permissions)?;
    let hooks = codex.join("hooks.json");
    fs::write(
        &hooks,
        format!(
            r#"{{"hooks":{{"PreToolUse":[{{"hooks":[{{"type":"command","command":"'{}' hook codex-pre-tool --agent codex --installed-by=numbat --rules-dir '{}' --output=file --output-file '$HOME/.numbat/findings.ndjson'"}}]}}]}}}}"#,
            binary.display(),
            rules.display()
        ),
    )?;
    let output = numbat_home.join("findings.ndjson");
    let state = numbat_home.join("state.db");
    let adjacent = numbat_home.join("operator-owned.txt");
    let mutable = project.join("mutable.txt");
    fs::write(&adjacent, "operator-owned")?;
    let script = r#"
        test "$(/bin/cat "$2")" = original-rule &&
        /usr/bin/printf output > "$5" &&
        /usr/bin/printf state > "$6" &&
        ! /usr/bin/printf changed > "$1" 2>/dev/null &&
        ! /usr/bin/printf changed > "$2" 2>/dev/null &&
        ! /usr/bin/printf changed > "$3" 2>/dev/null &&
        ! /usr/bin/printf changed > "$7" 2>/dev/null &&
        ! /bin/mv "$4" "$4-moved" 2>/dev/null &&
        ! /bin/mv "$8" "$8-moved" 2>/dev/null &&
        /usr/bin/printf mutable > "$9"
    "#;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", &home)
        .current_dir(&project)
        .args([
            "run",
            "--agent",
            "codex",
            "--numbat",
            "--",
            "/bin/sh",
            "-c",
            script,
            "numbat-probe",
        ])
        .arg(&hooks)
        .arg(&rule)
        .arg(&binary)
        .arg(&rules)
        .arg(&output)
        .arg(&state)
        .arg(&adjacent)
        .arg(&rules_parent)
        .arg(&mutable)
        .assert()
        .success();

    assert!(fs::read_to_string(&hooks)?.contains("installed-by=numbat"));
    assert_eq!(fs::read_to_string(&rule)?, "original-rule");
    assert!(fs::read_to_string(&binary)?.contains("exit 0"));
    assert_eq!(fs::read_to_string(output)?, "output");
    assert_eq!(fs::read_to_string(state)?, "state");
    assert_eq!(fs::read_to_string(adjacent)?, "operator-owned");
    assert_eq!(fs::read_to_string(mutable)?, "mutable");
    Ok(())
}

#[test]
#[ignore = "irreversibly applies Seatbelt; run on a host, not inside another sandbox"]
fn numbat_opencode_plugin_parent_cannot_be_relocated() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let home = root.path().join("home");
    let project = root.path().join("project");
    let config = home.join(".config/opencode");
    let plugins = config.join("plugins");
    let numbat_home = home.join(".numbat");
    fs::create_dir_all(&plugins)?;
    fs::create_dir(&numbat_home)?;
    fs::create_dir(&project)?;

    let binary = root.path().join("numbat-renamed");
    fs::write(&binary, "#!/bin/sh\nexit 0\n")?;
    let mut permissions = fs::metadata(&binary)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&binary, permissions)?;
    let output = numbat_home.join("findings.ndjson");
    let plugin = include_str!("fixtures/numbat/opencode-plugin.ts")
        .replace("__NUMBAT_BIN__", &binary.to_string_lossy())
        .replace("__OUTPUT_FILE__", &output.to_string_lossy());
    fs::write(plugins.join("numbat.ts"), plugin)?;

    let mut command = Command::cargo_bin("sandy")?;
    command
        .env("HOME", &home)
        .current_dir(&project)
        .args([
            "run",
            "--agent",
            "opencode",
            "--numbat",
            "--",
            "/bin/sh",
            "-c",
            "! /bin/mv \"$HOME/.config/opencode/plugins\" \"$HOME/.config/opencode/plugins-disabled\" 2>/dev/null && /usr/bin/printf mutable > \"$HOME/.config/opencode/session-state\"",
        ])
        .assert()
        .success();

    assert!(plugins.join("numbat.ts").is_file());
    assert_eq!(fs::read_to_string(config.join("session-state"))?, "mutable");
    Ok(())
}

#[test]
#[ignore = "irreversibly applies Seatbelt; run on a host, not inside another sandbox"]
fn absent_opencode_registration_cannot_be_planted_for_a_later_run()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let home = root.path().join("home");
    let project = root.path().join("project");
    let plugins = home.join(".config/opencode/plugins");
    fs::create_dir_all(&plugins)?;
    fs::create_dir(&project)?;

    let mut first = Command::cargo_bin("sandy")?;
    first
        .env("HOME", &home)
        .current_dir(&project)
        .args([
            "run",
            "--agent",
            "opencode",
            "--",
            "/bin/sh",
            "-c",
            "! /usr/bin/touch \"$HOME/.config/opencode/plugins/numbat.ts\" 2>/dev/null && /usr/bin/touch \"$HOME/.config/opencode/plugins/other.ts\"",
        ])
        .assert()
        .success();
    assert!(!plugins.join("numbat.ts").exists());
    assert!(plugins.join("other.ts").is_file());

    let mut second = Command::cargo_bin("sandy")?;
    second
        .env("HOME", &home)
        .current_dir(&project)
        .args([
            "run",
            "--dry-run",
            "--agent",
            "opencode",
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

fn run_scoped_write_probe() -> Result<(), Box<dyn std::error::Error>> {
    let root = fs::canonicalize(required_probe_path(WRITE_PROBE_ROOT)?)?;
    let protected = fs::canonicalize(required_probe_path(WRITE_PROBE_PROTECTED)?)?;
    let mut policy = PolicySpec {
        files: vec![FileGrant {
            path: absolute(&root)?,
            access: AccessMode::ReadWrite,
            scope: PathScope::Subtree,
        }],
        executables: Vec::new(),
        protected_paths: Vec::new(),
        write_protections: vec![WriteProtection {
            path: absolute(&protected)?,
            scope: PathScope::Subtree,
        }],
        unix_sockets: Vec::new(),
        local_host_tcp: Vec::new(),
        file_metadata: FileMetadataPolicy::Deny,
        allow_subprocesses: false,
        runtime_compatibility: RuntimeCompatibility::Minimal,
        network: NetworkPolicy::BlockAll,
    };
    policy.close_write_protection_ancestors();
    let manifest = LaunchManifestV2 {
        schema_version: MANIFEST_SCHEMA_V2,
        command: CommandSpec {
            program: OsValue::from_os_str(std::ffi::OsStr::new("/bin/true")),
            arguments: Vec::new(),
        },
        working_directory: absolute(&root)?,
        environment: Vec::new(),
        policy,
    };
    let launch = ValidatedLaunch::try_from(manifest)?;
    let profile = sandy_seatbelt::compile(launch.policy())?;
    sandy_seatbelt::apply(&profile)?;

    assert_eq!(
        fs::read_to_string(protected.join("policy.json"))?,
        "original"
    );
    assert_permission_denied(
        fs::write(protected.join("policy.json"), "changed"),
        "overwrite protected rule",
    )?;
    assert_permission_denied(
        fs::write(protected.join("new.json"), "new"),
        "create rule under protected subtree",
    )?;
    assert_permission_denied(
        fs::rename(root.join("config"), root.join("config-disabled")),
        "rename a writable ancestor of the protected rule subtree",
    )?;
    fs::write(root.join("mutable.txt"), "allowed")?;
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

    let manifest = LaunchManifestV2 {
        schema_version: MANIFEST_SCHEMA_V2,
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
            executables: Vec::new(),
            protected_paths: Vec::new(),
            write_protections: socket_paths
                .iter()
                .cloned()
                .map(|path| WriteProtection {
                    path,
                    scope: PathScope::Exact,
                })
                .collect(),
            unix_sockets: socket_paths
                .into_iter()
                .map(|path| UnixSocketGrant {
                    path,
                    operation: UnixSocketOperation::Connect,
                })
                .collect(),
            local_host_tcp: Vec::new(),
            file_metadata: FileMetadataPolicy::Allow,
            allow_subprocesses: false,
            runtime_compatibility: RuntimeCompatibility::Minimal,
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
    assert_permission_denied(TcpStream::connect(tcp_address), "local-host TCP connect")?;
    Ok(())
}

#[test]
#[ignore = "irreversibly applies Seatbelt; run on a host, not inside another sandbox"]
fn local_host_tcp_connect_covers_one_port_without_other_network_authority()
-> Result<(), Box<dyn std::error::Error>> {
    if env::var_os(TCP_PROBE_MODE).is_some() {
        return run_local_host_tcp_probe();
    }

    let root = tempfile::Builder::new()
        .prefix("sandy-exact-tcp-")
        .tempdir_in("/tmp")?;
    let local_address = non_loopback_ipv4()?;
    let same_host = TcpListener::bind((local_address, 0))?;
    let allowed = TcpListener::bind((Ipv4Addr::LOCALHOST, same_host.local_addr()?.port()))?;
    let denied = TcpListener::bind("127.0.0.1:0")?;
    let ipv6 = TcpListener::bind("[::1]:0")?;
    let unix_path = root.path().join("ungranted.sock");
    let _unix_listener = UnixListener::bind(&unix_path)?;

    let status = StdCommand::new(env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "local_host_tcp_connect_covers_one_port_without_other_network_authority",
        ])
        .env(TCP_PROBE_MODE, "1")
        .env(TCP_PROBE_ROOT, root.path())
        .env(TCP_PROBE_ALLOWED, allowed.local_addr()?.to_string())
        .env(TCP_PROBE_SAME_HOST, same_host.local_addr()?.to_string())
        .env(TCP_PROBE_DENIED, denied.local_addr()?.to_string())
        .env(TCP_PROBE_IPV6, ipv6.local_addr()?.to_string())
        .env(TCP_PROBE_UNIX, &unix_path)
        .status()?;

    assert!(status.success(), "sacrificial TCP probe failed: {status}");
    Ok(())
}

fn run_local_host_tcp_probe() -> Result<(), Box<dyn std::error::Error>> {
    let root = fs::canonicalize(required_probe_path(TCP_PROBE_ROOT)?)?;
    let allowed: SocketAddr = env::var(TCP_PROBE_ALLOWED)?.parse()?;
    let same_host: SocketAddr = env::var(TCP_PROBE_SAME_HOST)?.parse()?;
    let denied: SocketAddr = env::var(TCP_PROBE_DENIED)?.parse()?;
    let ipv6: SocketAddr = env::var(TCP_PROBE_IPV6)?.parse()?;
    let unix_path = required_probe_path(TCP_PROBE_UNIX)?;
    let manifest = LaunchManifestV2 {
        schema_version: MANIFEST_SCHEMA_V2,
        command: CommandSpec {
            program: OsValue::from_os_str(std::ffi::OsStr::new("/usr/bin/true")),
            arguments: Vec::new(),
        },
        working_directory: absolute(&root)?,
        environment: Vec::new(),
        policy: PolicySpec {
            files: vec![FileGrant {
                path: absolute(&root)?,
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
            }],
            executables: Vec::new(),
            protected_paths: Vec::new(),
            write_protections: Vec::new(),
            unix_sockets: Vec::new(),
            local_host_tcp: vec![LocalHostTcpGrant {
                port: TcpPort::new(allowed.port()).ok_or("test port must be nonzero")?,
                operation: LocalHostTcpOperation::Connect,
            }],
            file_metadata: FileMetadataPolicy::Deny,
            allow_subprocesses: false,
            runtime_compatibility: RuntimeCompatibility::Minimal,
            network: NetworkPolicy::BlockAll,
        },
    };
    let launch = ValidatedLaunch::try_from(manifest)?;
    let profile = sandy_seatbelt::compile(launch.policy())?;
    sandy_seatbelt::apply(&profile)?;

    let _allowed_stream = TcpStream::connect(allowed)?;
    let _same_host_stream = TcpStream::connect(same_host)?;
    assert_permission_denied(TcpStream::connect(denied), "adjacent local-host TCP port")?;
    let external = SocketAddr::from(([1, 1, 1, 1], allowed.port()));
    assert_permission_denied(
        TcpStream::connect_timeout(&external, Duration::from_secs(1)),
        "external IPv4 address on the granted port",
    )?;
    assert_permission_denied(TcpStream::connect(ipv6), "IPv6 loopback connect")?;
    assert_permission_denied(UnixStream::connect(unix_path), "Unix socket connect")?;
    assert_permission_denied(
        TcpListener::bind("127.0.0.1:0"),
        "loopback bind with connect-only authority",
    )?;
    Ok(())
}

fn non_loopback_ipv4() -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    // UDP connect chooses the interface that would route this documentation
    // address without sending a packet. The listener below proves that the
    // selected address belongs to this Mac.
    probe.connect((Ipv4Addr::new(192, 0, 2, 1), 9))?;
    match probe.local_addr()?.ip() {
        IpAddr::V4(address) if !address.is_loopback() && !address.is_unspecified() => Ok(address),
        address => Err(format!("no non-loopback IPv4 interface available: {address}").into()),
    }
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
fn opencode_preset_allows_state_but_protects_configuration_and_secrets()
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
            "--agent",
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
            .args(["run", "--agent", "opencode", "--", "/bin/sh", "-c", &script])
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
            "--agent",
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
            "--agent",
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
            .args(["run", "--agent", "codex", "--", "/bin/sh", "-c", script])
            .assert()
            .failure();
    }

    let mut adjacent = Command::cargo_bin("sandy")?;
    adjacent
        .env("HOME", &home)
        .current_dir(&project)
        .args([
            "run",
            "--agent",
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
