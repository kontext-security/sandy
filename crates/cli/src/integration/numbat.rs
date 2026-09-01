use std::{collections::BTreeSet, ffi::OsString, fs, path::Path};

use sandy_core::{AccessMode, FileGrant, PathScope, WriteProtection};
#[cfg(any(target_os = "macos", test))]
use sandy_core::{LocalHostTcpGrant, LocalHostTcpOperation, TcpPort};

use super::{
    ImmutableExecutable, IntegrationMode, ResolvedRuntimeControl, RuntimeControlCapabilities,
    hook_source::{JsonHookInvocation, json_documents, json_hook_commands, read_optional_bounded},
};
use crate::{
    agent::{HookProtocol, HookSourceScope, ResolvedHookSource},
    error::AppError,
    resolve::{ResolvedUserPaths, resolve_command, scoped_write_protections, write_protections},
};

const SERVICE: &str = "Numbat";
const OWNERSHIP_MARKER: &str = "--installed-by=numbat";
const CODEX_BLOCK_START: &str = "# BEGIN numbat managed codex hooks";
const CODEX_BLOCK_END: &str = "# END numbat managed codex hooks";
const OPENCODE_PLUGIN_FILE: &str = "numbat.ts";
const OPENCODE_PLUGIN_MARKER: &str = "// numbat-managed plugin - do not edit";
const OPENCODE_PLUGIN_SENTINELS: &[&str] = &[
    "import { spawn } from \"node:child_process\";",
    "function forward(lifecycle, payload) {",
    "spawn(NUMBAT_BIN, [\"hook\", lifecycle, \"--agent\", \"opencode\", ...EXTRA_ARGS]",
    "export const NumbatPlugin = async ({ directory }) => {",
    "\"tool.execute.before\": async (input, output) => {",
    "forward(\"opencode-pre-tool\"",
    "export default NumbatPlugin;",
];

#[cfg(any(target_os = "macos", test))]
const COLLECTOR_SERVICE: &str = "Numbat collector";

mod protocol;

use protocol::{ConfiguredInvocation, ConfiguredSource, ParsedSource, parse_source};
#[cfg(test)]
use protocol::{HookRuntime, codex_hooks_feature_enabled, parse_command};

pub(crate) fn resolve(
    hook_sources: &[ResolvedHookSource],
    mode: IntegrationMode,
    paths: &ResolvedUserPaths,
) -> Result<ResolvedRuntimeControl, AppError> {
    if mode.is_disabled() {
        return Ok(ResolvedRuntimeControl::inactive(SERVICE));
    }
    let configured = discover(hook_sources)?;
    if configured.is_empty() {
        if mode.is_required() {
            return Err(error(
                "--numbat requires installed hooks; run sandy integrations setup numbat --agent <claude|codex|opencode>, or omit --numbat",
            ));
        }
        return Ok(ResolvedRuntimeControl::inactive(SERVICE));
    }

    match resolve_configured(&configured, paths) {
        Ok(runtime_control) => Ok(runtime_control),
        Err(error) if mode.is_required() => Err(error),
        Err(error) => Ok(ResolvedRuntimeControl::unavailable(
            SERVICE,
            unavailable_reason(&error),
        )),
    }
}

/// Resolves one IPv4 TCP port on the local Mac for an operator-managed
/// collector. This capability is independent from hook discovery: it neither
/// starts a process nor implies that Numbat hooks are installed.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn collector(port: u16) -> Result<ResolvedRuntimeControl, AppError> {
    let port = TcpPort::new(port).ok_or_else(|| {
        AppError::runtime_control(
            COLLECTOR_SERVICE,
            "collector port must be between 1 and 65535",
        )
    })?;
    ResolvedRuntimeControl::active(
        COLLECTOR_SERVICE,
        None,
        RuntimeControlCapabilities {
            local_host_tcp: vec![LocalHostTcpGrant {
                port,
                operation: LocalHostTcpOperation::Connect,
            }],
            ..RuntimeControlCapabilities::default()
        },
    )
}

fn discover(sources: &[ResolvedHookSource]) -> Result<Vec<ConfiguredSource>, AppError> {
    let mut configured = Vec::new();
    for document in json_documents(SERVICE, sources)? {
        let Some(commands) = json_hook_commands(&document.value) else {
            continue;
        };
        let owned = commands
            .into_iter()
            .map(|command| {
                let invocation = match command.invocation {
                    JsonHookInvocation::Shell(command) => {
                        ConfiguredInvocation::Shell(command.to_owned())
                    }
                    JsonHookInvocation::Direct { program, arguments } => {
                        ConfiguredInvocation::Direct {
                            program: program.to_owned(),
                            arguments: arguments.into_iter().map(str::to_owned).collect(),
                        }
                    }
                };
                (command.event.to_owned(), invocation)
            })
            .filter(|(_, invocation)| invocation.owns_numbat_registration())
            .collect::<Vec<_>>();
        if !owned.is_empty() {
            configured.push(ConfiguredSource::Json {
                protocol: document.protocol,
                path: document.path,
                commands: owned,
            });
        }
    }

    for source in sources {
        match (source.protocol, source.scope) {
            (HookProtocol::CodexRequirements, HookSourceScope::File) => {
                let Some(data) = read_optional_bounded(SERVICE, &source.path)? else {
                    continue;
                };
                if contains_bytes(&data, OWNERSHIP_MARKER.as_bytes()) {
                    let body = String::from_utf8(data)
                        .map_err(|_| error("managed Codex hook source is not valid UTF-8"))?;
                    configured.push(ConfiguredSource::CodexRequirements {
                        path: source.path.clone(),
                        body,
                    });
                }
            }
            (HookProtocol::OpenCodePlugin, HookSourceScope::Directory) => {
                let path = source.path.join(OPENCODE_PLUGIN_FILE);
                let Some(data) = read_optional_bounded(SERVICE, &path)? else {
                    continue;
                };
                if contains_bytes(&data, OPENCODE_PLUGIN_MARKER.as_bytes()) {
                    let body = String::from_utf8(data)
                        .map_err(|_| error("OpenCode plugin source is not valid UTF-8"))?;
                    configured.push(ConfiguredSource::OpenCodePlugin { path, body });
                }
            }
            (HookProtocol::CodexRequirements, HookSourceScope::Directory)
            | (HookProtocol::OpenCodePlugin, HookSourceScope::File) => {
                return Err(error(
                    "agent preset declares an incompatible hook-source scope",
                ));
            }
            (HookProtocol::ClaudeSettings | HookProtocol::CodexHooks, _) => {}
        }
    }
    Ok(configured)
}

fn resolve_configured(
    configured: &[ConfiguredSource],
    paths: &ResolvedUserPaths,
) -> Result<ResolvedRuntimeControl, AppError> {
    let home = paths
        .home
        .as_deref()
        .ok_or_else(|| error("cannot resolve the home directory for Numbat resources"))?;
    let mut parsed_sources = Vec::new();
    for source in configured {
        parsed_sources.push(parse_source(source, home)?);
    }
    validate_runtime_layout(&parsed_sources, paths)?;

    let mut executables = Vec::new();
    let mut files = Vec::new();
    let mut protections = Vec::new();
    for (source, parsed) in configured.iter().zip(&parsed_sources) {
        add_executable(&parsed.binary, &mut executables, &mut protections)?;
        add_readable_immutable(
            source.path(),
            PathScope::Exact,
            &mut files,
            &mut protections,
        )?;
        for directory in &parsed.runtime.rule_directories {
            add_readable_immutable(directory, PathScope::Subtree, &mut files, &mut protections)?;
        }
        if let Some(output) = &parsed.runtime.output_file {
            add_writable_file(output, &mut files, &mut protections)?;
        }
        if let Some(state) = &parsed.runtime.state_database {
            add_writable_file(state, &mut files, &mut protections)?;
        }
    }

    executables.sort();
    executables.dedup();
    if executables.len() != 1 {
        return Err(error(
            "configured hooks resolve to different Numbat executables; reinstall the hooks",
        ));
    }
    files.sort();
    files.dedup();
    protections.sort();
    protections.dedup();
    reject_globally_protected_resources(&parsed_sources, &executables, &files, &paths.protected)?;

    ResolvedRuntimeControl::active(
        SERVICE,
        None,
        RuntimeControlCapabilities {
            executables,
            files,
            write_protections: protections,
            unix_sockets: Vec::new(),
            local_host_tcp: Vec::new(),
        },
    )
}

#[derive(Default)]
struct RuntimeLayout {
    rule_directories: BTreeSet<sandy_core::AbsolutePath>,
    output_files: BTreeSet<sandy_core::AbsolutePath>,
    state_databases: BTreeSet<sandy_core::AbsolutePath>,
}

fn validate_runtime_layout(
    parsed_sources: &[ParsedSource],
    paths: &ResolvedUserPaths,
) -> Result<(), AppError> {
    let mut layout = RuntimeLayout::default();
    for parsed in parsed_sources {
        for directory in &parsed.runtime.rule_directories {
            // Read-only rule directories may be configured through a symlink. Follow it here
            // deliberately so the canonical target participates in the protected-data checks.
            // `resource_aliases` later emits both lexical and canonical grants/protections;
            // writable output and state leaves reject final-component symlinks separately.
            let metadata = fs::metadata(directory)
                .map_err(|source| AppError::io("inspect Numbat rules directory", source))?;
            if !metadata.is_dir() {
                return Err(error(format!(
                    "configured rules path is not a directory: {}",
                    directory.display()
                )));
            }
            let canonical = fs::canonicalize(directory)
                .map_err(|source| AppError::io("canonicalize Numbat rules directory", source))?;
            if canonical == Path::new("/")
                || paths.home.as_deref() == Some(canonical.as_path())
                || paths
                    .home
                    .as_deref()
                    .is_some_and(|home| home.starts_with(&canonical))
                || paths.protected.iter().any(|protected| {
                    canonical.starts_with(protected.as_path())
                        || protected.as_path().starts_with(&canonical)
                })
            {
                return Err(error(
                    "configured rules directory is too broad or overlaps Sandy-protected data",
                ));
            }
            layout
                .rule_directories
                .extend(resource_aliases(directory, PathScope::Subtree)?);
        }
        if let Some(output) = &parsed.runtime.output_file {
            layout
                .output_files
                .extend(resource_aliases(output, PathScope::Exact)?);
        }
        if let Some(state) = &parsed.runtime.state_database {
            layout
                .state_databases
                .extend(resource_aliases(state, PathScope::Exact)?);
        }
    }

    if !layout.output_files.is_disjoint(&layout.state_databases) {
        return Err(error(
            "Numbat output and sequence-state database must be different files",
        ));
    }
    for writable in layout.output_files.iter().chain(&layout.state_databases) {
        if layout
            .rule_directories
            .iter()
            .any(|rules| writable.as_path().starts_with(rules.as_path()))
        {
            return Err(error(
                "writable Numbat output or state must not be inside a read-only rules directory",
            ));
        }
    }
    Ok(())
}

fn resource_aliases(
    path: &Path,
    scope: PathScope,
) -> Result<Vec<sandy_core::AbsolutePath>, AppError> {
    Ok(scoped_write_protections([path.to_path_buf()], scope)?
        .into_iter()
        .map(|protection| protection.path)
        .collect())
}

fn reject_globally_protected_resources(
    parsed_sources: &[ParsedSource],
    executables: &[ImmutableExecutable],
    files: &[FileGrant],
    protected_paths: &[sandy_core::AbsolutePath],
) -> Result<(), AppError> {
    let resolved_overlap = executables.iter().any(|executable| {
        protected_paths
            .iter()
            .any(|protected| executable.path().as_path().starts_with(protected.as_path()))
    }) || files.iter().any(|grant| {
        protected_paths.iter().any(|protected| {
            grant.path.as_path().starts_with(protected.as_path())
                || (grant.scope == PathScope::Subtree
                    && protected.as_path().starts_with(grant.path.as_path()))
        })
    });
    let configured_executable_overlap = parsed_sources.iter().any(|parsed| {
        protected_paths
            .iter()
            .any(|protected| parsed.binary.starts_with(protected.as_path()))
    });
    if resolved_overlap || configured_executable_overlap {
        return Err(error(
            "a required Numbat resource overlaps Sandy-protected data",
        ));
    }
    Ok(())
}

fn add_executable(
    configured_path: &Path,
    executables: &mut Vec<ImmutableExecutable>,
    protections: &mut Vec<WriteProtection>,
) -> Result<(), AppError> {
    let resolved = resolve_command(&[OsString::from(configured_path)])?;
    executables.push(ImmutableExecutable::new(
        sandy_core::AbsolutePath::new(
            resolved
                .program
                .to_str()
                .ok_or_else(|| error("Numbat executable path is not valid UTF-8"))?
                .to_owned(),
        )
        .map_err(|_| error("Numbat executable path is not absolute"))?,
    ));
    protections.extend(write_protections([configured_path.to_path_buf()])?);
    Ok(())
}

fn add_readable_immutable(
    path: &Path,
    scope: PathScope,
    files: &mut Vec<FileGrant>,
    protections: &mut Vec<WriteProtection>,
) -> Result<(), AppError> {
    let resolved = scoped_write_protections([path.to_path_buf()], scope)?;
    files.extend(resolved.iter().cloned().map(|protection| FileGrant {
        path: protection.path,
        access: AccessMode::Read,
        scope: protection.scope,
    }));
    protections.extend(resolved);
    Ok(())
}

fn add_writable_file(
    path: &Path,
    files: &mut Vec<FileGrant>,
    protections: &mut Vec<WriteProtection>,
) -> Result<(), AppError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(error(format!(
                "configured writable Numbat resource is not a regular file: {}",
                path.display()
            )));
        }
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(AppError::runtime_control(
                SERVICE,
                format!("inspect configured writable Numbat resource: {source}"),
            ));
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| error("configured writable Numbat file has no parent directory"))?;
    let metadata = fs::symlink_metadata(parent).map_err(|source| {
        AppError::runtime_control(
            SERVICE,
            format!(
                "inspect configured writable-file directory {}: {source}; create it outside Sandy before launching the agent",
                parent.display()
            ),
        )
    })?;
    if !metadata.is_dir() {
        return Err(error(format!(
            "configured writable-file parent is not a directory: {}",
            parent.display()
        )));
    }

    let aliases = scoped_write_protections([path.to_path_buf()], PathScope::Exact)?;
    files.extend(aliases.into_iter().map(|alias| FileGrant {
        path: alias.path,
        access: AccessMode::ReadWrite,
        scope: PathScope::Exact,
    }));
    // The file itself stays writable, but its directory entry must not be
    // renamed or removed to redirect that exact capability after resolution.
    protections.extend(scoped_write_protections(
        [parent.to_path_buf()],
        PathScope::Exact,
    )?);
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn unavailable_reason(error: &AppError) -> String {
    match error {
        AppError::RuntimeControl { message, .. } => message.clone(),
        _ => error.to_string(),
    }
}

fn error(message: impl Into<String>) -> AppError {
    AppError::runtime_control(SERVICE, message)
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt as _, path::PathBuf};

    use sandy_core::AbsolutePath;

    use super::*;
    use crate::{agent::HookSourceScope, resolve::absolute_if_utf8};

    fn executable(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let binary = root.join("numbat-renamed");
        fs::write(&binary, "#!/bin/sh\nexit 0\n")?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
        Ok(binary)
    }

    fn paths(home: &Path) -> Result<ResolvedUserPaths, Box<dyn std::error::Error>> {
        Ok(ResolvedUserPaths {
            home: Some(fs::canonicalize(home)?),
            protected: Vec::new(),
        })
    }

    #[test]
    fn parses_current_codex_command_and_resources() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let rules = root.path().join("rules");
        fs::create_dir(&home)?;
        fs::create_dir(&rules)?;
        let binary = executable(root.path())?;
        let command = format!(
            "'{}' hook codex-pre-tool --agent codex {} --enforce --rules-dir '{}' --output=file --output-file '$HOME/.numbat/live.ndjson'",
            binary.display(),
            OWNERSHIP_MARKER,
            rules.display()
        );
        let parsed = parse_command(&command, "codex", "codex-pre-tool", &home)?;
        assert_eq!(parsed.binary, binary);
        assert_eq!(parsed.runtime.rule_directories, [rules]);
        assert_eq!(
            parsed.runtime.output_file,
            Some(home.join(".numbat/live.ndjson"))
        );
        assert_eq!(
            parsed.runtime.state_database,
            Some(home.join(".numbat/state.db"))
        );
        Ok(())
    }

    #[test]
    fn rejects_shell_evaluation_and_direct_http() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir(&home)?;
        let binary = executable(root.path())?;
        let evaluated = format!(
            "{} hook pre-tool --agent claude {} --output=file --output-file $(id)",
            binary.display(),
            OWNERSHIP_MARKER
        );
        assert!(parse_command(&evaluated, "claude", "pre-tool", &home).is_err());

        let http = format!(
            "{} hook pre-tool --agent claude {} --output=http --http-url https://example.test",
            binary.display(),
            OWNERSHIP_MARKER
        );
        assert!(parse_command(&http, "claude", "pre-tool", &home).is_err());
        Ok(())
    }

    #[test]
    fn requires_writable_resource_directories_to_exist() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let missing = root.path().join("missing/findings.ndjson");
        let mut files = Vec::new();
        let mut protections = Vec::new();

        let result = add_writable_file(&missing, &mut files, &mut protections);
        assert!(matches!(result, Err(AppError::RuntimeControl { .. })));
        assert!(files.is_empty());
        assert!(protections.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_existing_non_regular_writable_resources() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let directory = root.path().join("directory");
        let target = root.path().join("target");
        let link = root.path().join("link");
        fs::create_dir(&directory)?;
        fs::write(&target, "data")?;
        std::os::unix::fs::symlink(&target, &link)?;

        for path in [directory, link, PathBuf::from("/dev/null")] {
            assert!(add_writable_file(&path, &mut Vec::new(), &mut Vec::new()).is_err());
        }
        Ok(())
    }

    #[test]
    fn resolves_json_hooks_into_scoped_capabilities() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let working = root.path().join("project");
        let codex = home.join(".codex");
        let numbat = home.join(".numbat");
        let rules = root.path().join("rules");
        fs::create_dir_all(&codex)?;
        fs::create_dir(&numbat)?;
        fs::create_dir(&working)?;
        fs::create_dir(&rules)?;
        fs::write(rules.join("policy.json"), "{}")?;
        let binary = executable(root.path())?;
        let hooks = codex.join("hooks.json");
        let body = include_str!("../../tests/fixtures/numbat/codex-hooks.json")
            .replace("__NUMBAT_BIN__", &binary.to_string_lossy())
            .replace(
                "--output=file",
                &format!("--rules-dir '{}' --output=file", rules.display()),
            )
            .replace("__OUTPUT_FILE__", "$HOME/.numbat/live.ndjson");
        fs::write(&hooks, body)?;
        let source =
            ResolvedHookSource::fixed(HookProtocol::CodexHooks, hooks, HookSourceScope::File);
        let control = resolve(&[source], IntegrationMode::Required, &paths(&home)?)?;
        assert!(control.is_active());

        let controls = super::super::RuntimeControls::new(vec![control]);
        let canonical_home = fs::canonicalize(&home)?;
        let canonical_rules = fs::canonicalize(&rules)?;
        let policy = controls
            .contribute(sandy_core::ResolvedPolicyDraft::new(
                sandy_core::NetworkPolicy::BlockAll,
            ))?
            .finish()?
            .into_spec();
        assert!(policy.files.iter().any(|grant| {
            grant.path.as_path() == canonical_rules
                && grant.access == AccessMode::Read
                && grant.scope == PathScope::Subtree
        }));
        assert!(policy.files.iter().any(|grant| {
            grant.path.as_path() == canonical_home.join(".numbat/live.ndjson")
                && grant.access == AccessMode::ReadWrite
                && grant.scope == PathScope::Exact
        }));
        assert!(policy.write_protections.iter().any(|protection| {
            protection.path.as_path() == canonical_rules && protection.scope == PathScope::Subtree
        }));
        assert!(policy.unix_sockets.is_empty());
        assert!(policy.local_host_tcp.is_empty());
        Ok(())
    }

    #[test]
    fn collector_resolves_one_selected_local_host_port() -> Result<(), Box<dyn std::error::Error>> {
        let policy = super::super::RuntimeControls::new(vec![collector(4318)?])
            .contribute(sandy_core::ResolvedPolicyDraft::new(
                sandy_core::NetworkPolicy::BlockAll,
            ))?
            .finish()?
            .into_spec();

        assert_eq!(policy.local_host_tcp.len(), 1);
        assert_eq!(policy.local_host_tcp[0].port.get(), 4318);
        assert_eq!(
            policy.local_host_tcp[0].operation,
            LocalHostTcpOperation::Connect
        );
        assert!(collector(0).is_err());
        Ok(())
    }

    #[test]
    fn rejects_hooks_that_disagree_on_the_executable() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir(&home)?;
        let first = executable(root.path())?;
        let second = root.path().join("numbat-second");
        fs::copy(&first, &second)?;
        fs::set_permissions(&second, fs::Permissions::from_mode(0o700))?;
        let command = |binary: &Path| {
            format!(
                "'{}' hook stop --agent codex {} --output=file --output-file '$HOME/.numbat/findings.ndjson'",
                binary.display(),
                OWNERSHIP_MARKER
            )
        };
        let configured = vec![
            ConfiguredSource::Json {
                protocol: HookProtocol::CodexHooks,
                path: root.path().join("first.json"),
                commands: vec![(
                    "Stop".to_owned(),
                    ConfiguredInvocation::Shell(command(&first)),
                )],
            },
            ConfiguredSource::Json {
                protocol: HookProtocol::CodexHooks,
                path: root.path().join("second.json"),
                commands: vec![(
                    "Stop".to_owned(),
                    ConfiguredInvocation::Shell(command(&second)),
                )],
            },
        ];
        fs::write(configured[0].path(), "{}")?;
        fs::write(configured[1].path(), "{}")?;

        let result = resolve_configured(&configured, &paths(&home)?);
        assert!(matches!(result, Err(AppError::RuntimeControl { .. })));
        Ok(())
    }

    #[test]
    fn parses_managed_codex_and_opencode_formats() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir(&home)?;
        let binary = executable(root.path())?;
        let body = include_str!("../../tests/fixtures/numbat/codex-requirements.toml")
            .replace("__NUMBAT_BIN__", &binary.to_string_lossy())
            .replace("__OUTPUT_FILE__", "$HOME/.numbat/codex.ndjson");
        let managed = ConfiguredSource::CodexRequirements {
            path: root.path().join("requirements.toml"),
            body,
        };
        assert_eq!(
            parse_source(&managed, &home)?.runtime.output_file,
            Some(home.join(".numbat/codex.ndjson"))
        );

        let plugin = ConfiguredSource::OpenCodePlugin {
            path: root.path().join(OPENCODE_PLUGIN_FILE),
            body: include_str!("../../tests/fixtures/numbat/opencode-plugin.ts")
                .replace("__NUMBAT_BIN__", &binary.to_string_lossy())
                .replace("__OUTPUT_FILE__", "$HOME/.numbat/opencode.ndjson"),
        };
        assert_eq!(
            parse_source(&plugin, &home)?.runtime.output_file,
            Some(home.join(".numbat/opencode.ndjson"))
        );
        Ok(())
    }

    #[test]
    fn parses_current_claude_program_and_argument_array() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let claude = home.join(".claude");
        let numbat = home.join(".numbat");
        fs::create_dir_all(&claude)?;
        fs::create_dir(&numbat)?;
        let binary = executable(root.path())?;
        let settings = claude.join("settings.json");
        let output = numbat.join("claude.ndjson");
        let body = include_str!("../../tests/fixtures/numbat/claude-settings.json")
            .replace("__NUMBAT_BIN__", &binary.to_string_lossy())
            .replace("__OUTPUT_FILE__", &output.to_string_lossy());
        fs::write(&settings, body)?;

        let control = resolve(
            &[ResolvedHookSource::fixed(
                HookProtocol::ClaudeSettings,
                settings,
                HookSourceScope::File,
            )],
            IntegrationMode::Required,
            &paths(&home)?,
        )?;

        assert!(control.is_active());
        Ok(())
    }

    #[test]
    fn rejects_incomplete_opencode_plugin_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir(&home)?;
        let binary = executable(root.path())?;
        let incomplete = ConfiguredSource::OpenCodePlugin {
            path: root.path().join(OPENCODE_PLUGIN_FILE),
            body: format!(
                "{OPENCODE_PLUGIN_MARKER}\nconst NUMBAT_BIN = {};\nconst EXTRA_ARGS = [\"{OWNERSHIP_MARKER}\"];\n",
                serde_json::to_string(binary.to_str().ok_or("non-UTF-8 test path")?)?
            ),
        };
        assert!(parse_source(&incomplete, &home).is_err());
        Ok(())
    }

    #[test]
    fn codex_feature_detection_is_confined_to_the_features_table()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(codex_hooks_feature_enabled(
            "[features]\nhooks = true # numbat-managed\n[other]\nhooks = false\n"
        )?);
        assert!(!codex_hooks_feature_enabled(
            "[features]\nhooks = false\n[other]\nhooks = true\n"
        )?);
        assert!(!codex_hooks_feature_enabled("[other]\nhooks = true\n")?);
        assert!(codex_hooks_feature_enabled("[features]\nhooks = \"true\"\n").is_err());
        assert!(codex_hooks_feature_enabled("[features]\nhooks = true\nhooks = false\n").is_err());
        Ok(())
    }

    #[test]
    fn rejects_writable_resources_inside_rule_directories() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let working = root.path().join("working");
        let rules = root.path().join("rules");
        fs::create_dir(&home)?;
        fs::create_dir(&working)?;
        fs::create_dir(&rules)?;
        fs::create_dir(rules.join("nested"))?;
        let resolved_paths = paths(&home)?;

        for output in [
            rules.join("findings.ndjson"),
            rules.join("nested/findings.ndjson"),
        ] {
            let parsed = ParsedSource {
                binary: root.path().join("numbat"),
                runtime: HookRuntime {
                    rule_directories: vec![rules.clone()],
                    output_file: Some(output),
                    state_database: Some(root.path().join("state.db")),
                    outputs: BTreeSet::from(["file".to_owned()]),
                },
            };
            assert!(validate_runtime_layout(&[parsed], &resolved_paths).is_err());
        }
        Ok(())
    }

    #[test]
    fn rejects_one_file_as_both_output_and_sequence_state() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let working = root.path().join("working");
        fs::create_dir(&home)?;
        fs::create_dir(&working)?;
        let shared = root.path().join("shared.db");
        let parsed = ParsedSource {
            binary: root.path().join("numbat"),
            runtime: HookRuntime {
                output_file: Some(shared.clone()),
                state_database: Some(shared),
                outputs: BTreeSet::from(["file".to_owned()]),
                ..HookRuntime::default()
            },
        };
        assert!(validate_runtime_layout(&[parsed], &paths(&home)?).is_err());
        Ok(())
    }

    #[test]
    fn rejects_home_and_protected_ancestor_rule_directories()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let working = root.path().join("working");
        let ssh = home.join(".ssh");
        fs::create_dir_all(&ssh)?;
        fs::create_dir(&working)?;
        let mut resolved = paths(&home)?;
        resolved.protected = vec![absolute_if_utf8(&fs::canonicalize(&ssh)?)?];

        let protected_child = ssh.join("rules");
        fs::create_dir(&protected_child)?;
        for rules in [
            root.path().to_path_buf(),
            home.clone(),
            ssh,
            protected_child,
        ] {
            let parsed = ParsedSource {
                binary: root.path().join("numbat"),
                runtime: HookRuntime {
                    rule_directories: vec![rules],
                    ..HookRuntime::default()
                },
            };
            assert!(validate_runtime_layout(&[parsed], &resolved).is_err());
        }
        Ok(())
    }

    #[test]
    fn rejects_symlinked_rules_directory_inside_protected_data()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let protected = home.join(".ssh");
        let rules = protected.join("rules");
        let alias = root.path().join("rules-link");
        fs::create_dir_all(&rules)?;
        std::os::unix::fs::symlink(&rules, &alias)?;

        let mut resolved = paths(&home)?;
        resolved.protected = vec![absolute_if_utf8(&fs::canonicalize(&protected)?)?];
        let parsed = ParsedSource {
            binary: root.path().join("numbat"),
            runtime: HookRuntime {
                rule_directories: vec![alias],
                ..HookRuntime::default()
            },
        };

        assert!(validate_runtime_layout(&[parsed], &resolved).is_err());
        Ok(())
    }

    #[test]
    fn rejects_positive_resources_inside_globally_protected_data()
    -> Result<(), Box<dyn std::error::Error>> {
        let protected = AbsolutePath::new("/Users/example/.ssh")?;
        let files = vec![FileGrant {
            path: AbsolutePath::new("/Users/example/.ssh/findings.ndjson")?,
            access: AccessMode::ReadWrite,
            scope: PathScope::Exact,
        }];
        assert!(reject_globally_protected_resources(&[], &[], &files, &[protected]).is_err());
        Ok(())
    }
}
