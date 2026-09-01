use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use super::{
    CODEX_BLOCK_END, CODEX_BLOCK_START, OPENCODE_PLUGIN_MARKER, OPENCODE_PLUGIN_SENTINELS,
    OWNERSHIP_MARKER, error,
};
use crate::{agent::HookProtocol, error::AppError, integration::hook_source::shell_words};

#[derive(Debug)]
pub(super) enum ConfiguredSource {
    Json {
        protocol: HookProtocol,
        path: PathBuf,
        commands: Vec<(String, ConfiguredInvocation)>,
    },
    CodexRequirements {
        path: PathBuf,
        body: String,
    },
    OpenCodePlugin {
        path: PathBuf,
        body: String,
    },
}

#[derive(Debug)]
pub(super) enum ConfiguredInvocation {
    Shell(String),
    Direct {
        program: String,
        arguments: Vec<String>,
    },
}

impl ConfiguredInvocation {
    pub(super) fn owns_numbat_registration(&self) -> bool {
        match self {
            Self::Shell(command) => command.contains(OWNERSHIP_MARKER),
            Self::Direct { arguments, .. } => arguments
                .iter()
                .any(|argument| argument == OWNERSHIP_MARKER),
        }
    }
}

impl ConfiguredSource {
    pub(super) fn path(&self) -> &Path {
        match self {
            Self::Json { path, .. }
            | Self::CodexRequirements { path, .. }
            | Self::OpenCodePlugin { path, .. } => path,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct HookRuntime {
    pub(super) rule_directories: Vec<PathBuf>,
    pub(super) output_file: Option<PathBuf>,
    pub(super) state_database: Option<PathBuf>,
    pub(super) outputs: BTreeSet<String>,
}

#[derive(Debug)]
pub(super) struct ParsedSource {
    pub(super) binary: PathBuf,
    pub(super) runtime: HookRuntime,
}

pub(super) fn parse_source(
    source: &ConfiguredSource,
    home: &Path,
) -> Result<ParsedSource, AppError> {
    match source {
        ConfiguredSource::Json {
            protocol, commands, ..
        } => parse_command_set(
            commands.iter().map(|(event, invocation)| {
                let lifecycle = expected_lifecycle(*protocol, event).ok_or_else(|| {
                    error(format!(
                        "Numbat hook is registered for unsupported {event} event"
                    ))
                })?;
                let agent = match protocol {
                    HookProtocol::ClaudeSettings => "claude",
                    HookProtocol::CodexHooks => "codex",
                    HookProtocol::CodexRequirements | HookProtocol::OpenCodePlugin => {
                        return Err(error("unexpected protocol for JSON Numbat hooks"));
                    }
                };
                Ok((invocation, agent, lifecycle))
            }),
            home,
        ),
        ConfiguredSource::CodexRequirements { body, .. } => {
            let commands = codex_requirements_commands(body)?;
            parse_command_set(
                commands.iter().map(|(event, invocation)| {
                    let lifecycle = expected_lifecycle(HookProtocol::CodexHooks, event)
                        .ok_or_else(|| error(format!("unsupported managed Codex event {event}")))?;
                    Ok((invocation, "codex", lifecycle))
                }),
                home,
            )
        }
        ConfiguredSource::OpenCodePlugin { body, .. } => parse_opencode_plugin(body, home),
    }
}

fn parse_command_set<'a>(
    commands: impl IntoIterator<
        Item = Result<(&'a ConfiguredInvocation, &'static str, &'static str), AppError>,
    >,
    home: &Path,
) -> Result<ParsedSource, AppError> {
    let mut parsed: Option<ParsedSource> = None;
    for command in commands {
        let (invocation, agent, lifecycle) = command?;
        let next = parse_invocation(invocation, agent, lifecycle, home)?;
        if let Some(current) = &parsed
            && (current.binary != next.binary || current.runtime != next.runtime)
        {
            return Err(error(
                "one hook source contains inconsistent Numbat binaries or runtime resources",
            ));
        }
        parsed = Some(next);
    }
    parsed.ok_or_else(|| error("Numbat-owned hook source contains no supported commands"))
}

fn parse_invocation(
    invocation: &ConfiguredInvocation,
    agent: &str,
    lifecycle: &str,
    home: &Path,
) -> Result<ParsedSource, AppError> {
    match invocation {
        ConfiguredInvocation::Shell(command) => parse_command(command, agent, lifecycle, home),
        ConfiguredInvocation::Direct { program, arguments } => {
            let mut words = Vec::with_capacity(arguments.len().saturating_add(1));
            words.push(program.clone());
            words.extend(arguments.iter().cloned());
            parse_words(&words, agent, lifecycle, home)
        }
    }
}

pub(super) fn parse_command(
    command: &str,
    agent: &str,
    lifecycle: &str,
    home: &Path,
) -> Result<ParsedSource, AppError> {
    let words = shell_words(command)
        .ok_or_else(|| error("Numbat hook command uses unsupported shell evaluation or quoting"))?;
    parse_words(&words, agent, lifecycle, home)
}

fn parse_words(
    words: &[String],
    agent: &str,
    lifecycle: &str,
    home: &Path,
) -> Result<ParsedSource, AppError> {
    if words.len() < 6
        || words[1] != "hook"
        || words[2] != lifecycle
        || words[3] != "--agent"
        || words[4] != agent
        || words[5] != OWNERSHIP_MARKER
    {
        return Err(error(
            "Numbat hook command does not match the agent protocol",
        ));
    }
    let binary = PathBuf::from(&words[0]);
    if !binary.is_absolute() {
        return Err(error("Numbat hook executable path must be absolute"));
    }
    let runtime = parse_runtime_arguments(&words[6..], home)?;
    Ok(ParsedSource { binary, runtime })
}

fn parse_runtime_arguments(arguments: &[String], home: &Path) -> Result<HookRuntime, AppError> {
    let mut runtime = HookRuntime::default();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        let (name, inline) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(name, value)| {
                (name, Some(value))
            });
        match name {
            "--enforce" | "--include-reasoning" | "--no-builtin-rules" => {
                require_boolean_flag(name, inline)?;
            }
            "--http-allow-insecure" | "--http-gzip" => {
                require_boolean_flag(name, inline)?;
            }
            "--rules-dir" => {
                let value = flag_value(arguments, &mut index, name, inline)?;
                runtime.rule_directories.push(expand_path(value, home)?);
            }
            "--output-file" => {
                let value = flag_value(arguments, &mut index, name, inline)?;
                set_once(&mut runtime.output_file, expand_path(value, home)?, name)?;
            }
            "--state-db" => {
                let value = flag_value(arguments, &mut index, name, inline)?;
                set_once(&mut runtime.state_database, expand_path(value, home)?, name)?;
            }
            "--output" => {
                let value = flag_value(arguments, &mut index, name, inline)?;
                for output in value.split(',') {
                    if !matches!(output, "file" | "stdout" | "http") {
                        return Err(error(format!("unsupported Numbat output mode {output:?}")));
                    }
                    runtime.outputs.insert(output.to_owned());
                }
            }
            "--http-url"
            | "--http-auth"
            | "--http-batch-size"
            | "--http-timeout"
            | "--http-sig-header"
            | "--http-timestamp-header"
            | "--emit"
            | "--content"
            | "--case-id" => {
                let _ = flag_value(arguments, &mut index, name, inline)?;
            }
            _ => return Err(error(format!("unsupported Numbat hook argument {name:?}"))),
        }
        index += 1;
    }

    if runtime.outputs.contains("http") {
        return Err(error(
            "direct HTTP hook delivery is not supported inside Sandy; use file output or an external collector",
        ));
    }
    if runtime.outputs.contains("file") != runtime.output_file.is_some() {
        return Err(error(
            "Numbat file output and --output-file must be configured together",
        ));
    }
    if runtime.state_database.is_none() {
        runtime.state_database = Some(home.join(".numbat/state.db"));
    }
    runtime.rule_directories.sort();
    runtime.rule_directories.dedup();
    Ok(runtime)
}

fn flag_value<'a>(
    arguments: &'a [String],
    index: &mut usize,
    name: &str,
    inline: Option<&'a str>,
) -> Result<&'a str, AppError> {
    let value = if let Some(value) = inline {
        value
    } else {
        *index = index
            .checked_add(1)
            .ok_or_else(|| error("Numbat hook argument index overflow"))?;
        arguments
            .get(*index)
            .map(String::as_str)
            .ok_or_else(|| error(format!("{name} requires a value")))?
    };
    if value.is_empty() {
        return Err(error(format!("{name} requires a non-empty value")));
    }
    Ok(value)
}

fn require_boolean_flag(name: &str, inline: Option<&str>) -> Result<(), AppError> {
    if inline.is_none_or(|value| matches!(value, "true" | "false")) {
        return Ok(());
    }
    Err(error(format!("{name} requires true or false")))
}

fn set_once<T: Eq>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), AppError> {
    if slot.as_ref().is_some_and(|existing| existing != &value) {
        return Err(error(format!("{name} is configured more than once")));
    }
    *slot = Some(value);
    Ok(())
}

fn expand_path(value: &str, home: &Path) -> Result<PathBuf, AppError> {
    let expanded = if let Some(rest) = value.strip_prefix("~/") {
        home.join(rest)
    } else if let Some(rest) = value.strip_prefix("$HOME/") {
        home.join(rest)
    } else if let Some(rest) = value.strip_prefix("${HOME}/") {
        home.join(rest)
    } else {
        if value.contains('$') || value.starts_with('~') {
            return Err(error(
                "Numbat resource paths may expand only the current user's home directory",
            ));
        }
        PathBuf::from(value)
    };
    if !expanded.is_absolute() || expanded == Path::new("/") {
        return Err(error("Numbat resource paths must be absolute and non-root"));
    }
    Ok(expanded)
}

fn expected_lifecycle(protocol: HookProtocol, event: &str) -> Option<&'static str> {
    match protocol {
        HookProtocol::ClaudeSettings => match event {
            "SessionStart" | "SubagentStart" => Some("session-start"),
            "UserPromptSubmit" => Some("prompt-submit"),
            "PreToolUse" => Some("pre-tool"),
            "PostToolUse" | "PostToolUseFailure" => Some("post-tool"),
            "PermissionRequest" => Some("permission-request"),
            "PermissionDenied" => Some("permission-denied"),
            "Stop" => Some("stop"),
            "SessionEnd" | "SubagentStop" => Some("session-end"),
            _ => None,
        },
        HookProtocol::CodexHooks => match event {
            "SessionStart" | "SubagentStart" => Some("session-start"),
            "UserPromptSubmit" => Some("prompt-submit"),
            "PreToolUse" => Some("codex-pre-tool"),
            "PostToolUse" => Some("codex-post-tool"),
            "PermissionRequest" => Some("codex-permission-request"),
            "SubagentStop" => Some("session-end"),
            "Stop" => Some("stop"),
            _ => None,
        },
        HookProtocol::CodexRequirements | HookProtocol::OpenCodePlugin => None,
    }
}

fn codex_requirements_commands(
    body: &str,
) -> Result<Vec<(String, ConfiguredInvocation)>, AppError> {
    if !codex_hooks_feature_enabled(body)? {
        return Err(error("managed Codex hooks feature is not enabled"));
    }
    let mut in_block = false;
    let mut ended = false;
    let mut event: Option<String> = None;
    let mut commands = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed == CODEX_BLOCK_START {
            if in_block || ended {
                return Err(error("managed Codex hook block marker is duplicated"));
            }
            in_block = true;
            continue;
        }
        if trimmed == CODEX_BLOCK_END {
            if !in_block {
                return Err(error("managed Codex hook block end marker is unexpected"));
            }
            in_block = false;
            ended = true;
            continue;
        }
        if !in_block {
            continue;
        }
        if let Some(name) = trimmed
            .strip_prefix("[[hooks.")
            .and_then(|value| value.strip_suffix("]]"))
            && !name.ends_with(".hooks")
        {
            event = Some(name.to_owned());
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("command = ") {
            let command: String = serde_json::from_str(value)
                .map_err(|_| error("managed Codex hook command is not a bounded TOML string"))?;
            let event = event
                .clone()
                .ok_or_else(|| error("managed Codex hook command has no event table"))?;
            commands.push((event, ConfiguredInvocation::Shell(command)));
        }
    }
    if in_block || !ended {
        return Err(error("managed Codex hook block is not closed"));
    }
    if commands.is_empty() {
        return Err(error("managed Codex hook block contains no commands"));
    }
    Ok(commands)
}

pub(super) fn codex_hooks_feature_enabled(body: &str) -> Result<bool, AppError> {
    let mut in_features = false;
    let mut feature_value = None;
    for line in body.lines() {
        let statement = line.split_once('#').map_or(line, |(value, _)| value).trim();
        if statement.is_empty() {
            continue;
        }
        if statement.starts_with('[') {
            in_features = statement == "[features]";
            continue;
        }
        if !in_features {
            continue;
        }
        let Some((key, value)) = statement.split_once('=') else {
            continue;
        };
        if key.trim() != "hooks" {
            continue;
        }
        let value = match value.trim() {
            "true" => true,
            "false" => false,
            _ => return Err(error("managed Codex hooks feature has an invalid value")),
        };
        if feature_value.replace(value).is_some() {
            return Err(error(
                "managed Codex hooks feature is declared more than once",
            ));
        }
    }
    Ok(feature_value == Some(true))
}

fn parse_opencode_plugin(body: &str, home: &Path) -> Result<ParsedSource, AppError> {
    if !body
        .lines()
        .any(|line| line.trim() == OPENCODE_PLUGIN_MARKER)
    {
        return Err(error("OpenCode plugin ownership marker is missing"));
    }
    if OPENCODE_PLUGIN_SENTINELS
        .iter()
        .any(|sentinel| !body.contains(sentinel))
    {
        return Err(error(
            "OpenCode plugin does not match the supported generated registration",
        ));
    }
    let binary: String = parse_javascript_constant(body, "const NUMBAT_BIN = ")?;
    let extra: Vec<String> = parse_javascript_constant(body, "const EXTRA_ARGS = ")?;
    if extra.first().map(String::as_str) != Some(OWNERSHIP_MARKER) {
        return Err(error("OpenCode plugin runtime marker is missing"));
    }
    let mut words = vec![
        binary,
        "hook".to_owned(),
        "opencode-pre-tool".to_owned(),
        "--agent".to_owned(),
        "opencode".to_owned(),
    ];
    words.extend(extra);
    parse_words(&words, "opencode", "opencode-pre-tool", home)
}

fn parse_javascript_constant<T: serde::de::DeserializeOwned>(
    body: &str,
    prefix: &str,
) -> Result<T, AppError> {
    let value = body
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix))
        .and_then(|value| value.strip_suffix(';'))
        .ok_or_else(|| error(format!("OpenCode plugin is missing {prefix:?}")))?;
    serde_json::from_str(value).map_err(|_| {
        error(format!(
            "OpenCode plugin contains an invalid {prefix:?} value"
        ))
    })
}
