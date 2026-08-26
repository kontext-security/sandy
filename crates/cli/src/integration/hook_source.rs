use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
};

use sandy_core::{HookProtocol, HookSourceScope};
use serde_json::Value;

use crate::{error::AppError, profile::ResolvedHookSource};

const MAX_HOOK_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAX_HOOK_DOCUMENTS: usize = 128;

#[derive(Debug)]
pub(crate) struct JsonHookDocument {
    pub(crate) protocol: HookProtocol,
    pub(crate) path: PathBuf,
    pub(crate) value: Value,
}

#[derive(Clone, Debug)]
pub(crate) struct JsonHookCommand<'a> {
    pub(crate) event: &'a str,
    pub(crate) invocation: JsonHookInvocation<'a>,
}

/// Invocation forms used by supported JSON hook protocols.
///
/// A direct program plus argument vector is kept distinct from a shell command
/// so adapters never need to concatenate or evaluate structured arguments.
#[derive(Clone, Debug)]
pub(crate) enum JsonHookInvocation<'a> {
    Shell(&'a str),
    Direct {
        program: &'a str,
        arguments: Vec<&'a str>,
    },
}

/// Loads bounded JSON hook documents from exact files and direct children of
/// agent-managed drop-in directories.
pub(crate) fn json_documents(
    service: &'static str,
    sources: &[ResolvedHookSource],
) -> Result<Vec<JsonHookDocument>, AppError> {
    let mut documents = Vec::new();
    for source in sources.iter().filter(|source| {
        matches!(
            source.protocol,
            HookProtocol::ClaudeSettings | HookProtocol::CodexHooks
        )
    }) {
        match source.scope {
            HookSourceScope::File => {
                if let Some(data) = read_optional_bounded(service, &source.path)? {
                    push_document(
                        service,
                        &mut documents,
                        parse_json(service, source, source.path.clone(), &data)?,
                    )?;
                }
            }
            HookSourceScope::Directory => {
                let mut entries = directory_json_files(service, &source.path)?;
                for path in entries.drain(..) {
                    let Some(data) = read_optional_bounded(service, &path)? else {
                        continue;
                    };
                    push_document(
                        service,
                        &mut documents,
                        parse_json(service, source, path, &data)?,
                    )?;
                }
            }
        }
    }
    Ok(documents)
}

fn push_document(
    service: &'static str,
    documents: &mut Vec<JsonHookDocument>,
    document: JsonHookDocument,
) -> Result<(), AppError> {
    if documents.len() >= MAX_HOOK_DOCUMENTS {
        return Err(error(
            service,
            "agent hook discovery exceeded the document limit",
        ));
    }
    documents.push(document);
    Ok(())
}

pub(crate) fn read_optional_bounded(
    service: &'static str,
    path: &Path,
) -> Result<Option<Vec<u8>>, AppError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(AppError::io("inspect agent hook source", source)),
    }
    let file =
        fs::File::open(path).map_err(|source| AppError::io("open agent hook source", source))?;
    let metadata = file
        .metadata()
        .map_err(|source| AppError::io("inspect agent hook source", source))?;
    if !metadata.is_file() {
        return Err(error(
            service,
            format!(
                "agent hook source is not a regular file: {}",
                path.display()
            ),
        ));
    }
    if metadata.len() > MAX_HOOK_DOCUMENT_BYTES {
        return Err(error(
            service,
            format!(
                "agent hook source is unexpectedly large: {}",
                path.display()
            ),
        ));
    }
    let mut data = Vec::new();
    file.take(MAX_HOOK_DOCUMENT_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|source| AppError::io("read agent hook source", source))?;
    if data.len() as u64 > MAX_HOOK_DOCUMENT_BYTES {
        return Err(error(
            service,
            format!(
                "agent hook source is unexpectedly large: {}",
                path.display()
            ),
        ));
    }
    Ok(Some(data))
}

fn directory_json_files(service: &'static str, directory: &Path) -> Result<Vec<PathBuf>, AppError> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(AppError::io("inspect agent hook directory", source)),
    };
    if !metadata.is_dir() {
        return Err(error(
            service,
            format!(
                "agent hook directory is not a directory: {}",
                directory.display()
            ),
        ));
    }

    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|source| AppError::io("read agent hook directory", source))?
    {
        let path = entry
            .map_err(|source| AppError::io("read agent hook directory entry", source))?
            .path();
        if path.extension().and_then(std::ffi::OsStr::to_str) == Some("json") {
            paths.push(path);
        }
        if paths.len() > MAX_HOOK_DOCUMENTS {
            return Err(error(
                service,
                "agent hook directory exceeded the document limit",
            ));
        }
    }
    paths.sort();
    Ok(paths)
}

fn parse_json(
    service: &'static str,
    source: &ResolvedHookSource,
    path: PathBuf,
    data: &[u8],
) -> Result<JsonHookDocument, AppError> {
    let value = serde_json::from_slice(data).map_err(|parse_error| {
        error(
            service,
            format!(
                "cannot parse hook configuration {}: {parse_error}",
                path.display()
            ),
        )
    })?;
    Ok(JsonHookDocument {
        protocol: source.protocol,
        path,
        value,
    })
}

/// Returns only command fields owned by the nested agent hook protocol.
pub(crate) fn json_hook_commands(value: &Value) -> Option<Vec<JsonHookCommand<'_>>> {
    let Some(hooks) = value.get("hooks") else {
        return Some(Vec::new());
    };
    let hooks = hooks.as_object()?;
    let mut commands = Vec::new();
    for (event, groups) in hooks {
        let groups = groups.as_array()?;
        for group in groups {
            let handlers = group.get("hooks").and_then(Value::as_array)?;
            for handler in handlers {
                if handler.get("type").and_then(Value::as_str) == Some("command")
                    && let Some(command) = handler.get("command").and_then(Value::as_str)
                {
                    let invocation = match handler.get("args") {
                        None => JsonHookInvocation::Shell(command),
                        Some(arguments) => JsonHookInvocation::Direct {
                            program: command,
                            arguments: arguments
                                .as_array()?
                                .iter()
                                .map(Value::as_str)
                                .collect::<Option<Vec<_>>>()?,
                        },
                    };
                    commands.push(JsonHookCommand { event, invocation });
                }
            }
        }
    }
    Some(commands)
}

/// Splits one POSIX hook command without evaluating substitutions or shell
/// operators. Hook adapters still validate the resulting command grammar.
pub(crate) fn shell_words(command: &str) -> Option<Vec<String>> {
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

fn error(service: &'static str, message: impl Into<String>) -> AppError {
    AppError::runtime_control(service, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_parser_rejects_evaluation_and_preserves_quoted_paths() {
        assert_eq!(
            shell_words("'/opt/Tool Box/numbat' hook stop"),
            Some(vec![
                "/opt/Tool Box/numbat".to_owned(),
                "hook".to_owned(),
                "stop".to_owned(),
            ])
        );
        for command in ["numbat $(id)", "numbat `id`", "numbat hook stop | sh"] {
            assert!(shell_words(command).is_none());
        }
    }

    #[test]
    fn nested_parser_keeps_event_ownership() -> Result<(), Box<dyn std::error::Error>> {
        let value: Value = serde_json::from_str(
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/numbat hook pre-tool"}]}]}}"#,
        )?;
        let commands = json_hook_commands(&value).ok_or("unexpected hook shape")?;
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].event, "PreToolUse");
        assert!(matches!(
            commands[0].invocation,
            JsonHookInvocation::Shell("/opt/numbat hook pre-tool")
        ));
        Ok(())
    }

    #[test]
    fn nested_parser_preserves_direct_program_arguments() -> Result<(), Box<dyn std::error::Error>>
    {
        let value: Value = serde_json::from_str(
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/numbat","args":["hook","pre-tool","--installed-by=numbat"]}]}]}}"#,
        )?;
        let commands = json_hook_commands(&value).ok_or("unexpected hook shape")?;
        assert!(matches!(
            &commands[0].invocation,
            JsonHookInvocation::Direct { program, arguments }
                if *program == "/opt/numbat"
                    && arguments == &["hook", "pre-tool", "--installed-by=numbat"]
        ));
        Ok(())
    }

    #[test]
    fn exact_file_sources_share_the_global_document_bound() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let mut sources = Vec::new();
        for index in 0..=MAX_HOOK_DOCUMENTS {
            let path = root.path().join(format!("hook-{index}.json"));
            fs::write(&path, "{}")?;
            sources.push(ResolvedHookSource::fixed(
                HookProtocol::ClaudeSettings,
                path,
                HookSourceScope::File,
            ));
        }

        assert!(matches!(
            json_documents("test", &sources),
            Err(AppError::RuntimeControl { .. })
        ));
        Ok(())
    }
}
