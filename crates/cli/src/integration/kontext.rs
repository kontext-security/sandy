use std::{
    ffi::OsString,
    fs,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    process::Command,
};

use sandy_core::{AccessMode, FileGrant, PathScope};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    error::AppError,
    profile::Preset,
    resolve::{ResolvedCommand, ResolvedPaths, grant, resolve_command},
};

const MAX_HOOK_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Default)]
pub(crate) struct KontextIntegration {
    pub(crate) enabled: bool,
    pub(crate) grants: Vec<FileGrant>,
    pub(crate) version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DoctorReport {
    healthy: bool,
    configured: bool,
    self_serve: bool,
    daemon_running: bool,
    installed_version: Option<String>,
    config_path: Option<PathBuf>,
}

pub(crate) fn resolve(
    preset: Preset,
    required: bool,
    paths: &ResolvedPaths,
) -> Result<KontextIntegration, AppError> {
    let hook_files = hook_files(preset, paths);
    let configured = find_configured_binary(&hook_files)?;
    let Some(configured_binary) = configured else {
        if required {
            return Err(AppError::Kontext(
                "--kontext requires installed hooks; install Kontext and run kontext setup, or omit --kontext"
                    .to_owned(),
            ));
        }
        return Ok(KontextIntegration::default());
    };

    let binary = resolve_binary(&configured_binary)?;
    let report = doctor(&binary)?;
    if !report.configured || !report.self_serve || !report.daemon_running || !report.healthy {
        return Err(AppError::Kontext(
            "the configured self-serve installation is unhealthy; run kontext doctor".to_owned(),
        ));
    }

    let mut grants = Vec::new();
    add_existing(
        &mut grants,
        &configured_binary,
        AccessMode::Read,
        PathScope::Exact,
    )?;
    add_existing(
        &mut grants,
        &binary.program,
        AccessMode::Read,
        PathScope::Exact,
    )?;
    if let Some(parent) = binary.program.parent() {
        add_existing(&mut grants, parent, AccessMode::Read, PathScope::Subtree)?;
    }
    for hook_file in hook_files {
        add_existing(&mut grants, &hook_file, AccessMode::Read, PathScope::Exact)?;
    }
    if let Some(config_path) = &report.config_path {
        add_existing(&mut grants, config_path, AccessMode::Read, PathScope::Exact)?;
        if let Some(directory) = config_path.parent() {
            add_existing(
                &mut grants,
                &directory.join("managed-observe/cedar-policy.json"),
                AccessMode::Read,
                PathScope::Exact,
            )?;
        }
    }
    if let Some(home) = &paths.home {
        add_existing(
            &mut grants,
            &home.join("Library/Application Support/Kontext/active"),
            AccessMode::Read,
            PathScope::Exact,
        )?;
        let uid = fs::metadata(home)
            .map_err(|error| AppError::io("inspect home directory owner", error))?
            .uid();
        add_existing(
            &mut grants,
            &PathBuf::from(format!("/tmp/kontext-managed-observe-{uid}/kontext.sock")),
            AccessMode::ReadWrite,
            PathScope::Exact,
        )?;
    }

    Ok(KontextIntegration {
        enabled: true,
        grants,
        version: report.installed_version,
    })
}

fn hook_files(preset: Preset, paths: &ResolvedPaths) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(home) = &paths.home {
        match preset {
            Preset::Claude => files.push(home.join(".claude/settings.json")),
            Preset::Codex => files.push(home.join(".codex/hooks.json")),
            Preset::Minimal => {}
        }
    }
    if preset == Preset::Claude {
        files.push(PathBuf::from(
            "/Library/Application Support/ClaudeCode/managed-settings.d/20-kontext.json",
        ));
        files.push(PathBuf::from(
            "/Library/Application Support/ClaudeCode/managed-settings.json",
        ));
    }
    files
}

fn find_configured_binary(paths: &[PathBuf]) -> Result<Option<PathBuf>, AppError> {
    for path in paths {
        if !path.exists() {
            continue;
        }
        let metadata = fs::metadata(path)
            .map_err(|error| AppError::io("inspect agent hook configuration", error))?;
        if metadata.len() > MAX_HOOK_CONFIG_BYTES {
            return Err(AppError::Kontext(format!(
                "hook configuration is unexpectedly large: {}",
                path.display()
            )));
        }
        let data =
            fs::read(path).map_err(|error| AppError::io("read agent hook configuration", error))?;
        let value: Value = serde_json::from_slice(&data).map_err(|error| {
            AppError::Kontext(format!(
                "cannot parse hook configuration {}: {error}",
                path.display()
            ))
        })?;
        if let Some(binary) = find_command(&value) {
            return Ok(Some(binary));
        }
    }
    Ok(None)
}

fn find_command(value: &Value) -> Option<PathBuf> {
    match value {
        Value::String(value) => parse_kontext_command(value),
        Value::Array(values) => values.iter().find_map(find_command),
        Value::Object(values) => values.values().find_map(find_command),
        _ => None,
    }
}

fn parse_kontext_command(command: &str) -> Option<PathBuf> {
    let fields: Vec<&str> = command.split_ascii_whitespace().collect();
    if fields.len() < 2
        || Path::new(fields[0]).file_name()?.to_str()? != "kontext"
        || fields[1] != "hook"
    {
        return None;
    }
    Some(PathBuf::from(fields[0]))
}

fn resolve_binary(configured: &Path) -> Result<ResolvedCommand, AppError> {
    resolve_command(&[OsString::from(configured)])
}

fn doctor(binary: &ResolvedCommand) -> Result<DoctorReport, AppError> {
    let output = Command::new(&binary.program)
        .args(["doctor", "--json"])
        .output()
        .map_err(|error| AppError::io("run kontext doctor --json", error))?;
    serde_json::from_slice(&output.stdout).map_err(|error| {
        AppError::Kontext(format!(
            "kontext doctor --json returned malformed output: {error}"
        ))
    })
}

fn add_existing(
    grants: &mut Vec<FileGrant>,
    path: &Path,
    access: AccessMode,
    scope: PathScope,
) -> Result<(), AppError> {
    if path.exists() {
        grants.push(grant(path, access, scope, &[])?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_owned_hook_commands() {
        assert_eq!(
            parse_kontext_command("/opt/homebrew/bin/kontext hook --agent claude pre-tool-use"),
            Some(PathBuf::from("/opt/homebrew/bin/kontext"))
        );
        assert_eq!(parse_kontext_command("other hook"), None);
    }
}
