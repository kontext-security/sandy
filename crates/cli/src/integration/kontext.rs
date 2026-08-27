use std::{
    ffi::OsString,
    fs,
    io::{Read as _, Seek as _},
    os::unix::fs::{FileTypeExt as _, MetadataExt as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use sandy_core::{
    AbsolutePath, AccessMode, FileGrant, HookProtocol, PathScope, UnixSocketGrant,
    UnixSocketOperation, WriteProtection,
};
use serde::Deserialize;
use serde_json::Value;

use super::{
    ImmutableExecutable, IntegrationMode, ResolvedRuntimeControl, RuntimeControlCapabilities,
};
use crate::{
    error::AppError,
    profile::ResolvedHookSource,
    resolve::{
        ResolvedCommand, ResolvedPaths, absolute_if_utf8, grant, resolve_command, write_protections,
    },
};

const SERVICE: &str = "Kontext";
const MAX_HOOK_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_DOCTOR_OUTPUT_BYTES: u64 = 64 * 1024;
const DOCTOR_OUTPUT_KIB: u64 = MAX_DOCTOR_OUTPUT_BYTES / 1024;
const DOCTOR_TIMEOUT: Duration = Duration::from_secs(5);
const DOCTOR_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Deserialize)]
struct DoctorReport {
    healthy: bool,
    configured: bool,
    self_serve: bool,
    daemon_running: bool,
    installed_version: Option<String>,
    config_path: Option<PathBuf>,
    active_profile: Option<String>,
    legacy_install: bool,
    mode: Option<ManagedMode>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ManagedMode {
    Observe,
    Enforce,
    Remote,
}

pub(crate) fn resolve(
    hook_sources: &[ResolvedHookSource],
    mode: IntegrationMode,
    paths: &ResolvedPaths,
) -> Result<ResolvedRuntimeControl, AppError> {
    let configured = find_configured_binaries(hook_sources)?;
    if configured.is_empty() {
        if mode.is_required() {
            return Err(error(
                "--kontext requires installed hooks; install Kontext and run kontext setup, or omit --kontext",
            ));
        }
        return Ok(ResolvedRuntimeControl::inactive(SERVICE));
    }

    match resolve_configured(configured, hook_sources, paths) {
        Ok(runtime_control) => Ok(runtime_control),
        Err(error) if mode.is_required() => Err(error),
        Err(error) => Ok(ResolvedRuntimeControl::unavailable(
            SERVICE,
            unavailable_reason(&error),
        )),
    }
}

fn resolve_configured(
    configured: Vec<PathBuf>,
    hook_sources: &[ResolvedHookSource],
    paths: &ResolvedPaths,
) -> Result<ResolvedRuntimeControl, AppError> {
    let binaries = resolve_binaries(&configured)?;
    let binary = binaries
        .first()
        .ok_or_else(|| error("configured hook executable could not be resolved"))?;
    if binaries
        .iter()
        .any(|candidate| candidate.program != binary.program)
    {
        return Err(error(
            "configured hooks resolve to different Kontext executables; rerun kontext setup",
        ));
    }

    let home = paths
        .home
        .as_deref()
        .ok_or_else(|| error("cannot resolve the home directory for Kontext resources"))?;
    let report = doctor(binary, home)?;
    if !report.configured || !report.self_serve || !report.daemon_running || !report.healthy {
        return Err(error(
            "the configured self-serve installation is unhealthy; run kontext doctor",
        ));
    }

    let executable = exact_existing(&binary.program)?;
    let mut read_only = Vec::new();
    let mut protection_inputs = configured;
    protection_inputs.push(binary.program.clone());

    for source in hook_sources {
        push_existing(&mut read_only, &source.path)?;
        protection_inputs.push(source.path.clone());
    }

    let kontext_root = home.join("Library/Application Support/Kontext");
    if let Some(config_path) = &report.config_path {
        validate_self_serve_config_path(
            config_path,
            &kontext_root,
            report.active_profile.as_deref(),
            report.legacy_install,
        )?;
        read_only.push(exact_existing_within(config_path, &kontext_root)?);
        protection_inputs.push(config_path.clone());
        if let Some(cache) = policy_cache_path(config_path, report.mode) {
            push_existing_within(&mut read_only, &cache, &kontext_root)?;
            protection_inputs.push(cache);
        }
    } else {
        return Err(error(
            "kontext doctor did not report the active self-serve configuration path",
        ));
    }

    let active = kontext_root.join("active");
    if !report.legacy_install {
        read_only.push(exact_existing_within(&active, &kontext_root)?);
    }
    protection_inputs.push(active);

    let uid = fs::metadata(home)
        .map_err(|source| AppError::io("inspect home directory owner", source))?
        .uid();
    let socket_path = PathBuf::from(format!("/tmp/kontext-managed-observe-{uid}/kontext.sock"));
    let socket_paths = verified_socket_paths(&socket_path, uid)?;

    read_only.retain(|path| path != &executable && !socket_paths.contains(path));
    read_only.extend(socket_paths.iter().cloned());
    read_only.sort();
    read_only.dedup();
    let mut protected_from_write = write_protections(protection_inputs)?;
    protected_from_write.extend(socket_paths.iter().cloned().map(|path| WriteProtection {
        path,
        scope: PathScope::Exact,
    }));
    protected_from_write.sort();
    protected_from_write.dedup();
    let unix_sockets = socket_paths
        .into_iter()
        .map(|path| UnixSocketGrant {
            path,
            operation: UnixSocketOperation::Connect,
        })
        .collect();

    ResolvedRuntimeControl::active(
        SERVICE,
        report.installed_version,
        RuntimeControlCapabilities {
            executables: vec![ImmutableExecutable::new(executable)],
            files: read_only
                .into_iter()
                .map(|path| FileGrant {
                    path,
                    access: AccessMode::Read,
                    scope: PathScope::Exact,
                })
                .collect(),
            write_protections: protected_from_write,
            unix_sockets,
        },
    )
}

fn verified_socket_paths(path: &Path, uid: u32) -> Result<Vec<AbsolutePath>, AppError> {
    // Do not follow a final-component symlink: the lexical exact-connect rule
    // must name the verified socket node, not an attacker-replaceable alias.
    // Parent aliases such as macOS `/tmp` are handled by emitting both this
    // lexical path and the canonical path below.
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| AppError::io("inspect Kontext daemon socket", source))?;
    if !metadata.file_type().is_socket() || metadata.uid() != uid {
        return Err(error(
            "the Kontext daemon endpoint is not a same-user Unix socket",
        ));
    }

    let mut paths = vec![exact_existing(path)?, absolute_if_utf8(path)?];
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn find_configured_binaries(sources: &[ResolvedHookSource]) -> Result<Vec<PathBuf>, AppError> {
    let mut binaries = Vec::new();
    for source in sources {
        match fs::symlink_metadata(&source.path) {
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(AppError::io(
                    "inspect agent hook configuration entry",
                    source,
                ));
            }
        }
        let file = fs::File::open(&source.path)
            .map_err(|source| AppError::io("open agent hook configuration", source))?;
        let metadata = file
            .metadata()
            .map_err(|source| AppError::io("inspect agent hook configuration", source))?;
        if !metadata.is_file() {
            return Err(error(format!(
                "agent hook configuration is not a regular file: {}",
                source.path.display()
            )));
        }
        if metadata.len() > MAX_HOOK_CONFIG_BYTES {
            return Err(error(format!(
                "hook configuration is unexpectedly large: {}",
                source.path.display()
            )));
        }
        let mut data = Vec::new();
        file.take(MAX_HOOK_CONFIG_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|source| AppError::io("read agent hook configuration", source))?;
        if data.len() as u64 > MAX_HOOK_CONFIG_BYTES {
            return Err(error(format!(
                "hook configuration is unexpectedly large: {}",
                source.path.display()
            )));
        }
        let value: Value = serde_json::from_slice(&data).map_err(|parse_error| {
            error(format!(
                "cannot parse hook configuration {}: {parse_error}",
                source.path.display()
            ))
        })?;
        let Some(commands) = hook_commands(&value) else {
            continue;
        };
        for command in commands {
            if let Some(binary) = parse_kontext_command(command, source.protocol)
                && !binaries.contains(&binary)
            {
                binaries.push(binary);
            }
        }
    }
    Ok(binaries)
}

fn hook_commands(value: &Value) -> Option<Vec<&str>> {
    let Some(hooks) = value.get("hooks") else {
        return Some(Vec::new());
    };
    let hooks = hooks.as_object()?;
    let mut commands = Vec::new();
    for groups in hooks.values() {
        let groups = groups.as_array()?;
        for group in groups {
            let handlers = group.get("hooks").and_then(Value::as_array)?;
            for handler in handlers {
                if handler.get("type").and_then(Value::as_str) == Some("command")
                    && let Some(command) = handler.get("command").and_then(Value::as_str)
                {
                    commands.push(command);
                }
            }
        }
    }
    Some(commands)
}

fn parse_kontext_command(command: &str, protocol: HookProtocol) -> Option<PathBuf> {
    let words = shell_words(command)?;
    let alias = words.last()?.as_str();
    let valid_shape = match protocol {
        HookProtocol::ClaudeSettings => {
            words.len() == 3
                && matches!(
                    alias,
                    "session-start"
                        | "pre-tool-use"
                        | "post-tool-use"
                        | "post-tool-use-failure"
                        | "session-end"
                )
        }
        HookProtocol::CodexHooks => {
            words.len() == 5
                && words[2] == "--agent"
                && words[3] == "codex"
                && matches!(
                    alias,
                    "session-start"
                        | "pre-tool-use"
                        | "post-tool-use"
                        | "user-prompt-submit"
                        | "stop"
                )
        }
    };
    if !valid_shape || words[1] != "hook" {
        return None;
    }
    let binary = PathBuf::from(&words[0]);
    if !binary.is_absolute() || binary.file_name()?.to_str()? != "kontext" {
        return None;
    }
    Some(binary)
}

fn shell_words(command: &str) -> Option<Vec<String>> {
    #[derive(Clone, Copy)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = Quote::None;
    let mut started = false;
    let mut characters = command.chars();
    while let Some(character) = characters.next() {
        match quote {
            Quote::Single => {
                if character == '\'' {
                    quote = Quote::None;
                } else {
                    word.push(character);
                }
            }
            Quote::Double => match character {
                '"' => quote = Quote::None,
                '\\' => {
                    let escaped = characters.next()?;
                    if matches!(escaped, '$' | '`' | '"' | '\\') {
                        word.push(escaped);
                    } else {
                        word.push('\\');
                        word.push(escaped);
                    }
                }
                '$' | '`' => return None,
                _ => word.push(character),
            },
            Quote::None => match character {
                '\'' => {
                    quote = Quote::Single;
                    started = true;
                }
                '"' => {
                    quote = Quote::Double;
                    started = true;
                }
                '\\' => {
                    word.push(characters.next()?);
                    started = true;
                }
                character if character.is_ascii_whitespace() => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                }
                ';' | '|' | '&' | '<' | '>' | '$' | '`' | '(' | ')' => return None,
                _ => {
                    word.push(character);
                    started = true;
                }
            },
        }
    }
    if !matches!(quote, Quote::None) {
        return None;
    }
    if started {
        words.push(word);
    }
    Some(words)
}

fn resolve_binaries(configured: &[PathBuf]) -> Result<Vec<ResolvedCommand>, AppError> {
    configured
        .iter()
        .map(|path| resolve_command(&[OsString::from(path)]))
        .collect()
}

fn doctor(binary: &ResolvedCommand, home: &Path) -> Result<DoctorReport, AppError> {
    doctor_with_timeout(binary, home, DOCTOR_TIMEOUT)
}

fn doctor_with_timeout(
    binary: &ResolvedCommand,
    home: &Path,
    timeout: Duration,
) -> Result<DoctorReport, AppError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| error("kontext doctor timeout could not be represented"))?;
    let mut output = tempfile::tempfile()
        .map_err(|source| AppError::io("create bounded kontext doctor output", source))?;
    let child_output = output
        .try_clone()
        .map_err(|source| AppError::io("prepare kontext doctor output", source))?;
    // macOS `/bin/sh` expresses `ulimit -f` in KiB. Set both limits and abort
    // the launcher if either operation fails. The fixed script never
    // interpolates provider-controlled data; the resolved executable is passed
    // as an opaque positional argument.
    let limit_script = format!(
        "ulimit -S -f {DOCTOR_OUTPUT_KIB} && ulimit -H -f {DOCTOR_OUTPUT_KIB} && exec \"$1\" doctor --json"
    );
    let mut child = Command::new("/bin/sh")
        .args(["-c", &limit_script, "sandy-kontext-doctor"])
        .arg(&binary.program)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(child_output))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| AppError::io("run kontext doctor --json", source))?;
    let status = loop {
        let output_size = match output.metadata() {
            Ok(metadata) => metadata.len(),
            Err(source) => {
                return Err(cleanup_doctor_after_error(
                    &mut child,
                    AppError::io("inspect kontext doctor output", source),
                ));
            }
        };
        if output_size > MAX_DOCTOR_OUTPUT_BYTES {
            terminate_doctor(&mut child)?;
            return Err(error("kontext doctor --json output exceeded the limit"));
        }
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(source) => {
                return Err(cleanup_doctor_after_error(
                    &mut child,
                    AppError::io("wait for kontext doctor --json", source),
                ));
            }
        };
        if let Some(status) = status {
            break status;
        }

        let now = Instant::now();
        if now >= deadline {
            terminate_doctor(&mut child)?;
            return Err(error("kontext doctor --json timed out"));
        }
        thread::sleep(DOCTOR_POLL_INTERVAL.min(deadline.duration_since(now)));
    };

    output
        .rewind()
        .map_err(|source| AppError::io("rewind kontext doctor output", source))?;
    let mut bytes = Vec::new();
    output
        .take(MAX_DOCTOR_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| AppError::io("read kontext doctor --json output", source))?;
    if bytes.len() as u64 > MAX_DOCTOR_OUTPUT_BYTES {
        return Err(error("kontext doctor --json output exceeded the limit"));
    }
    if !status.success() {
        return Err(error(
            "kontext doctor --json failed; update Kontext or run kontext doctor",
        ));
    }
    serde_json::from_slice(&bytes).map_err(|parse_error| {
        error(format!(
            "kontext doctor --json returned malformed output: {parse_error}"
        ))
    })
}

fn terminate_doctor(child: &mut std::process::Child) -> Result<(), AppError> {
    let kill_error = child.kill().err();
    let wait_result = child
        .wait()
        .map_err(|source| AppError::io("reap kontext doctor --json", source));
    match (kill_error, wait_result) {
        (_, Err(error)) => Err(error),
        (_, Ok(_)) => Ok(()),
    }
}

fn cleanup_doctor_after_error(child: &mut std::process::Child, error: AppError) -> AppError {
    match terminate_doctor(child) {
        Ok(()) => error,
        Err(cleanup_error) => cleanup_error,
    }
}

fn unavailable_reason(error: &AppError) -> String {
    match error {
        AppError::RuntimeControl { message, .. } => message.clone(),
        _ => error.to_string(),
    }
}

fn exact_existing(path: &Path) -> Result<AbsolutePath, AppError> {
    Ok(grant(path, AccessMode::Read, PathScope::Exact, &[])?.path)
}

fn exact_existing_within(path: &Path, root: &Path) -> Result<AbsolutePath, AppError> {
    let root = fs::canonicalize(root)
        .map_err(|source| AppError::io("canonicalize Kontext resource root", source))?;
    let resolved = exact_existing(path)?;
    if !resolved.as_path().starts_with(&root) {
        return Err(error(format!(
            "Kontext resource resolves outside its expected root: {}",
            path.display()
        )));
    }
    Ok(resolved)
}

fn validate_self_serve_config_path(
    path: &Path,
    root: &Path,
    active_profile: Option<&str>,
    legacy_install: bool,
) -> Result<(), AppError> {
    // The trusted parent supplies Kontext with the canonical HOME used to build
    // `root`. Requiring the doctor response to reproduce this exact lexical path
    // rejects aliases and `..` spellings before any resource is granted.
    let expected = if legacy_install {
        if active_profile.is_some() {
            return Err(error(
                "kontext doctor reported both legacy and active-profile state",
            ));
        }
        root.join("managed.json")
    } else {
        let active_profile = active_profile
            .filter(|name| valid_profile_name(std::ffi::OsStr::new(name)))
            .ok_or_else(|| error("kontext doctor did not report a valid active profile"))?;
        root.join("profiles")
            .join(active_profile)
            .join("managed.json")
    };
    if path != expected {
        return Err(error(
            "kontext doctor reported a configuration outside the active self-serve profile",
        ));
    }
    Ok(())
}

fn policy_cache_path(config_path: &Path, mode: Option<ManagedMode>) -> Option<PathBuf> {
    (mode == Some(ManagedMode::Remote))
        .then(|| config_path.parent())
        .flatten()
        .map(|directory| directory.join("managed-observe/cedar-policy.json"))
}

fn valid_profile_name(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    !name.is_empty()
        && name.len() <= 32
        && name.chars().enumerate().all(|(index, character)| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || (index > 0 && matches!(character, '-' | '_'))
        })
}

fn push_required(paths: &mut Vec<AbsolutePath>, path: &Path) -> Result<(), AppError> {
    paths.push(exact_existing(path)?);
    Ok(())
}

fn push_existing(paths: &mut Vec<AbsolutePath>, path: &Path) -> Result<(), AppError> {
    if path.exists() {
        push_required(paths, path)?;
    }
    Ok(())
}

fn push_existing_within(
    paths: &mut Vec<AbsolutePath>,
    path: &Path,
    root: &Path,
) -> Result<(), AppError> {
    if path.exists() {
        paths.push(exact_existing_within(path, root)?);
    }
    Ok(())
}

fn error(message: impl Into<String>) -> AppError {
    AppError::runtime_control(SERVICE, message)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    const HEALTHY_DOCTOR_REPORT: &str = r#"{"healthy":true,"configured":true,"self_serve":true,"daemon_running":true,"active_profile":"test","legacy_install":false,"mode":"observe"}"#;

    #[test]
    fn recognizes_current_quoted_hook_commands() {
        assert_eq!(
            parse_kontext_command(
                "'/opt/homebrew/bin/kontext' hook 'pre-tool-use'",
                HookProtocol::ClaudeSettings,
            ),
            Some(PathBuf::from("/opt/homebrew/bin/kontext"))
        );
        assert_eq!(
            parse_kontext_command(
                "'/usr/local/bin/kontext' hook --agent 'codex' 'session-start'",
                HookProtocol::CodexHooks,
            ),
            Some(PathBuf::from("/usr/local/bin/kontext"))
        );
    }

    #[test]
    fn accepts_spaces_and_shell_quoted_apostrophes() {
        let command = "'/Applications/Control'\\''s Tools/kontext' hook 'session-end'";
        assert_eq!(
            shell_words(command),
            Some(vec![
                "/Applications/Control's Tools/kontext".to_owned(),
                "hook".to_owned(),
                "session-end".to_owned(),
            ])
        );
        assert_eq!(
            parse_kontext_command(command, HookProtocol::ClaudeSettings),
            Some(PathBuf::from("/Applications/Control's Tools/kontext"))
        );
    }

    #[test]
    fn rejects_wrong_protocol_shapes_and_shell_operators() {
        assert_eq!(
            parse_kontext_command(
                "'/opt/homebrew/bin/kontext' hook --agent codex stop",
                HookProtocol::ClaudeSettings,
            ),
            None
        );
        assert_eq!(
            parse_kontext_command(
                "'/opt/homebrew/bin/kontext' hook stop; other",
                HookProtocol::ClaudeSettings,
            ),
            None
        );
        assert_eq!(
            parse_kontext_command("kontext hook stop", HookProtocol::ClaudeSettings),
            None
        );
        assert_eq!(
            parse_kontext_command(
                "'/opt/homebrew/bin/kontext' hook 'not-a-kontext-event'",
                HookProtocol::ClaudeSettings,
            ),
            None
        );
        assert_eq!(
            parse_kontext_command(
                r#""/tmp/kon\text" hook pre-tool-use"#,
                HookProtocol::ClaudeSettings,
            ),
            None
        );
    }

    #[test]
    fn reads_commands_only_from_the_hook_schema() -> Result<(), Box<dyn std::error::Error>> {
        let value: Value = serde_json::from_str(
            r#"{
                "description": "/tmp/kontext hook ignored",
                "hooks": {
                    "PreToolUse": [{
                        "matcher": "",
                        "hooks": [{"type": "command", "command": "'/opt/homebrew/bin/kontext' hook 'pre-tool-use'"}]
                    }]
                }
            }"#,
        )?;
        assert_eq!(
            hook_commands(&value),
            Some(vec!["'/opt/homebrew/bin/kontext' hook 'pre-tool-use'"])
        );
        Ok(())
    }

    #[test]
    fn unfamiliar_hook_shapes_are_not_positive_proof() -> Result<(), Box<dyn std::error::Error>> {
        for document in [
            r#"{"hooks": "managed-by-another-agent"}"#,
            r#"{"hooks": {"PreToolUse": {}}}"#,
            r#"{"hooks": {"PreToolUse": [{"hooks": {}}]}}"#,
            r#"{
                "hooks": {
                    "PreToolUse": [{
                        "hooks": [{"type": "command", "command": "'/opt/homebrew/bin/kontext' hook 'pre-tool-use'"}]
                    }],
                    "Unknown": {}
                }
            }"#,
        ] {
            let value: Value = serde_json::from_str(document)?;
            assert_eq!(hook_commands(&value), None);
        }
        Ok(())
    }

    #[test]
    fn discovers_only_protocol_owned_command_fields() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let hooks = root.path().join("hooks.json");
        fs::write(
            &hooks,
            r#"{
                "note": "'/tmp/ignored/kontext' hook 'stop'",
                "hooks": {
                    "SessionEnd": [{
                        "hooks": [{"type": "command", "command": "'/opt/homebrew/bin/kontext' hook 'session-end'"}]
                    }]
                }
            }"#,
        )?;
        let binaries = find_configured_binaries(&[ResolvedHookSource {
            protocol: HookProtocol::ClaudeSettings,
            path: hooks,
        }])?;
        assert_eq!(binaries, [PathBuf::from("/opt/homebrew/bin/kontext")]);
        Ok(())
    }

    #[test]
    fn broken_hook_symlinks_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let hooks = root.path().join("hooks.json");
        std::os::unix::fs::symlink(root.path().join("missing.json"), &hooks)?;

        let result = find_configured_binaries(&[ResolvedHookSource {
            protocol: HookProtocol::CodexHooks,
            path: hooks,
        }]);
        assert!(matches!(result, Err(AppError::Io { .. })));
        Ok(())
    }

    #[test]
    fn hook_configuration_read_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let hooks = root.path().join("hooks.json");
        fs::write(&hooks, vec![b' '; MAX_HOOK_CONFIG_BYTES as usize + 1])?;

        let result = find_configured_binaries(&[ResolvedHookSource {
            protocol: HookProtocol::ClaudeSettings,
            path: hooks,
        }]);
        assert!(matches!(result, Err(AppError::RuntimeControl { .. })));
        Ok(())
    }

    #[test]
    fn accepts_only_bounded_self_serve_config_paths() {
        let root = Path::new("/test-home/Library/Application Support/Kontext");
        assert!(
            validate_self_serve_config_path(&root.join("managed.json"), root, None, true).is_ok()
        );
        assert!(
            validate_self_serve_config_path(
                &root.join("profiles/production_1/managed.json"),
                root,
                Some("production_1"),
                false,
            )
            .is_ok()
        );
        assert!(
            validate_self_serve_config_path(
                &root.join("profiles/../managed.json"),
                root,
                Some("production_1"),
                false,
            )
            .is_err()
        );
        assert!(
            validate_self_serve_config_path(
                &root.join("profiles/production_1/../production_1/managed.json"),
                root,
                Some("production_1"),
                false,
            )
            .is_err()
        );
        assert!(
            validate_self_serve_config_path(
                Path::new("/test-home/private/credentials.json"),
                root,
                None,
                true,
            )
            .is_err()
        );
        assert!(
            validate_self_serve_config_path(
                &root.join("profiles/invalid.profile/managed.json"),
                root,
                Some("invalid.profile"),
                false,
            )
            .is_err()
        );
        assert!(
            validate_self_serve_config_path(
                &root.join("managed.json"),
                root,
                Some("production"),
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn grants_cached_policy_only_for_remote_mode() {
        let config = Path::new("/test-home/profiles/production/managed.json");
        let expected =
            PathBuf::from("/test-home/profiles/production/managed-observe/cedar-policy.json");

        assert_eq!(
            policy_cache_path(config, Some(ManagedMode::Remote)),
            Some(expected)
        );
        assert_eq!(policy_cache_path(config, Some(ManagedMode::Observe)), None);
        assert_eq!(policy_cache_path(config, Some(ManagedMode::Enforce)), None);
        assert_eq!(policy_cache_path(config, None), None);
    }

    #[test]
    fn rejects_resources_that_symlink_outside_provider_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let provider = root.path().join("provider");
        let outside = root.path().join("outside.json");
        fs::create_dir(&provider)?;
        fs::write(&outside, "sensitive")?;
        let link = provider.join("managed.json");
        std::os::unix::fs::symlink(&outside, &link)?;

        assert!(matches!(
            exact_existing_within(&link, &provider),
            Err(AppError::RuntimeControl { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_final_component_socket_symlinks() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let socket = root.path().join("control.sock");
        let alias = root.path().join("control-link.sock");
        fs::write(&socket, "not a socket")?;
        std::os::unix::fs::symlink(&socket, &alias)?;
        let uid = fs::symlink_metadata(&alias)?.uid();

        assert!(matches!(
            verified_socket_paths(&alias, uid),
            Err(AppError::RuntimeControl { .. })
        ));
        Ok(())
    }

    #[test]
    fn doctor_output_is_bounded_and_requires_success() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let binary = root.path().join("kontext");
        fs::write(
            &binary,
            format!("#!/bin/sh\nprintf '%s\\n' '{HEALTHY_DOCTOR_REPORT}'\n"),
        )?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
        let command = ResolvedCommand {
            requested_name: OsString::from("kontext"),
            program: binary.clone(),
            arguments: Vec::new(),
        };
        assert!(doctor(&command, root.path())?.healthy);

        fs::write(&binary, "#!/bin/sh\nexit 1\n")?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
        assert!(matches!(
            doctor(&command, root.path()),
            Err(AppError::RuntimeControl { .. })
        ));
        Ok(())
    }

    #[test]
    fn doctor_accepts_valid_output_larger_than_32_kib() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let binary = root.path().join("kontext");
        fs::write(
            &binary,
            format!("#!/bin/sh\nprintf '%s' '{HEALTHY_DOCTOR_REPORT}'\nprintf '%40000s' ''\n"),
        )?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
        let command = ResolvedCommand {
            requested_name: OsString::from("kontext"),
            program: binary,
            arguments: Vec::new(),
        };

        assert!(doctor(&command, root.path())?.healthy);
        Ok(())
    }

    #[test]
    fn doctor_timeout_returns_within_deadline() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let binary = root.path().join("kontext");
        fs::write(&binary, "#!/bin/sh\nwhile :; do :; done\n")?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
        let command = ResolvedCommand {
            requested_name: OsString::from("kontext"),
            program: binary,
            arguments: Vec::new(),
        };
        let started = Instant::now();

        let result = doctor_with_timeout(&command, root.path(), Duration::from_millis(50));

        assert!(matches!(result, Err(AppError::RuntimeControl { .. })));
        assert!(started.elapsed() < Duration::from_secs(1));
        Ok(())
    }

    #[test]
    fn doctor_output_flood_is_stopped_by_the_file_size_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let binary = root.path().join("kontext");
        fs::write(&binary, "#!/bin/sh\nexec /usr/bin/yes x\n")?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
        let command = ResolvedCommand {
            requested_name: OsString::from("kontext"),
            program: binary,
            arguments: Vec::new(),
        };
        let started = Instant::now();

        let result = doctor_with_timeout(&command, root.path(), Duration::from_secs(1));

        assert!(matches!(result, Err(AppError::RuntimeControl { .. })));
        assert!(started.elapsed() < Duration::from_secs(1));
        Ok(())
    }
}
