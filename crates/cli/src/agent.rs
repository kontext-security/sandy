//! Small CLI-local presets for known agent compatibility.
//!
//! Presets are trusted product data, not a user-authored policy language. They
//! only select Sandy's default policy and known hook locations. Callers that
//! need their own authority use a complete [`sandy_core::SandboxPolicy`].

#[cfg(target_os = "macos")]
use std::fs;
use std::{
    env,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

use sandy_core::{AccessMode, NetworkPolicy, PathScope, SandboxPolicy};

#[cfg(target_os = "macos")]
use crate::resolve::{CliPolicyIntent, write_protections};
use crate::{
    error::AppError,
    resolve::{ResolvedUserPaths, absolute_if_utf8, protection_path_spellings},
};

const GENERIC_AGENT: &str = "generic";
const SENSITIVE_PATHS: &[&str] = &["~/.ssh", "~/.gnupg", "~/.aws", "~/Library/Keychains"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DefaultGrant {
    path: &'static str,
    access: AccessMode,
    scope: PathScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HookLocation {
    Fixed(&'static str),
    ClaudeUserSettings,
    CodexUserHooks,
    OpenCodeUserPlugins,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HookSourceSpec {
    protocol: HookProtocol,
    location: HookLocation,
    scope: HookSourceScope,
}

#[derive(Debug)]
struct AgentDefinition {
    name: &'static str,
    binary_names: &'static [&'static str],
    grants: &'static [DefaultGrant],
    deny_write_exact: &'static [&'static str],
    hook_sources: &'static [HookSourceSpec],
}

const CLAUDE_GRANTS: &[DefaultGrant] = &[
    DefaultGrant {
        path: "~/.claude",
        access: AccessMode::ReadWrite,
        scope: PathScope::Subtree,
    },
    DefaultGrant {
        path: "~/.claude.json",
        access: AccessMode::Read,
        scope: PathScope::Exact,
    },
];
const CLAUDE_HOOKS: &[HookSourceSpec] = &[
    HookSourceSpec {
        protocol: HookProtocol::ClaudeSettings,
        location: HookLocation::ClaudeUserSettings,
        scope: HookSourceScope::File,
    },
    HookSourceSpec {
        protocol: HookProtocol::ClaudeSettings,
        location: HookLocation::Fixed("/Library/Application Support/ClaudeCode/managed-settings.d"),
        scope: HookSourceScope::Directory,
    },
    HookSourceSpec {
        protocol: HookProtocol::ClaudeSettings,
        location: HookLocation::Fixed(
            "/Library/Application Support/ClaudeCode/managed-settings.json",
        ),
        scope: HookSourceScope::File,
    },
];
const CODEX_GRANTS: &[DefaultGrant] = &[DefaultGrant {
    path: "~/.codex",
    access: AccessMode::ReadWrite,
    scope: PathScope::Subtree,
}];
const CODEX_HOOKS: &[HookSourceSpec] = &[
    HookSourceSpec {
        protocol: HookProtocol::CodexHooks,
        location: HookLocation::CodexUserHooks,
        scope: HookSourceScope::File,
    },
    HookSourceSpec {
        protocol: HookProtocol::CodexRequirements,
        location: HookLocation::Fixed("/etc/codex/requirements.toml"),
        scope: HookSourceScope::File,
    },
];
const OPENCODE_GRANTS: &[DefaultGrant] = &[
    DefaultGrant {
        path: "~/.config/opencode",
        access: AccessMode::ReadWrite,
        scope: PathScope::Subtree,
    },
    DefaultGrant {
        path: "~/.local/share/opencode",
        access: AccessMode::ReadWrite,
        scope: PathScope::Subtree,
    },
];
const OPENCODE_HOOKS: &[HookSourceSpec] = &[HookSourceSpec {
    protocol: HookProtocol::OpenCodePlugin,
    location: HookLocation::OpenCodeUserPlugins,
    scope: HookSourceScope::Directory,
}];

const AGENTS: &[AgentDefinition] = &[
    AgentDefinition {
        name: "claude",
        binary_names: &["claude"],
        grants: CLAUDE_GRANTS,
        deny_write_exact: &["~/.claude/settings.json", "~/.claude.json"],
        hook_sources: CLAUDE_HOOKS,
    },
    AgentDefinition {
        name: "codex",
        binary_names: &["codex"],
        grants: CODEX_GRANTS,
        deny_write_exact: &["~/.codex/hooks.json", "~/.codex/config.toml"],
        hook_sources: CODEX_HOOKS,
    },
    AgentDefinition {
        name: "opencode",
        binary_names: &["opencode"],
        grants: OPENCODE_GRANTS,
        deny_write_exact: &[
            "~/.config/opencode/opencode.json",
            "~/.config/opencode/opencode.jsonc",
        ],
        hook_sources: OPENCODE_HOOKS,
    },
    AgentDefinition {
        name: GENERIC_AGENT,
        binary_names: &[],
        grants: &[],
        deny_write_exact: &[],
        hook_sources: &[],
    },
];

/// One selected built-in compatibility preset.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AgentPreset {
    definition: &'static AgentDefinition,
    detected: bool,
}

impl AgentPreset {
    #[must_use]
    pub(crate) fn name(self) -> &'static str {
        self.definition.name
    }

    #[must_use]
    pub(crate) fn detected(self) -> bool {
        self.detected
    }

    #[must_use]
    pub(crate) fn protected_templates(self) -> &'static [&'static str] {
        SENSITIVE_PATHS
    }

    /// Builds the complete default policy selected by this preset.
    pub(crate) fn policy(
        self,
        network: NetworkPolicy,
        paths: &ResolvedUserPaths,
    ) -> Result<SandboxPolicy, AppError> {
        let mut policy = SandboxPolicy::new(network).allow_subprocesses();
        for path in SENSITIVE_PATHS {
            if let Some(path) = expand(path, paths) {
                policy = policy.deny_subtree(path);
            }
        }
        for file in self.definition.grants {
            let Some(path) = expand(file.path, paths) else {
                continue;
            };
            if optional_path_exists(&path)? {
                policy = policy.grant(path, file.access, file.scope);
            }
        }
        for path in self.definition.deny_write_exact {
            if let Some(path) = expand(path, paths) {
                policy = policy.deny_write_exact(path);
            }
        }
        Ok(policy)
    }

    /// Resolves all terminal subtree protections through lexical and canonical
    /// spellings before positive launch paths are admitted.
    pub(crate) fn protected_paths(
        self,
        paths: &ResolvedUserPaths,
    ) -> Result<Vec<sandy_core::AbsolutePath>, AppError> {
        protection_path_spellings(
            SENSITIVE_PATHS
                .iter()
                .filter_map(|path| expand(path, paths)),
        )
    }

    pub(crate) fn hook_sources(
        self,
        paths: &ResolvedUserPaths,
    ) -> Result<Vec<ResolvedHookSource>, AppError> {
        self.definition
            .hook_sources
            .iter()
            .filter_map(|source| {
                resolve_hook_source(source, paths, &|key| env::var_os(key)).transpose()
            })
            .collect()
    }

    /// Grants configured agent roots and protects user-controlled hook leaves
    /// before any runtime-control resolver inspects their contents.
    #[cfg(target_os = "macos")]
    pub(crate) fn contribute_hook_source_policy(
        self,
        mut intent: CliPolicyIntent,
        sources: &[ResolvedHookSource],
        paths: &ResolvedUserPaths,
    ) -> Result<(CliPolicyIntent, Vec<sandy_core::WriteProtection>), AppError> {
        let mut protected = Vec::new();
        for source in sources.iter().filter(|source| source.user_source) {
            if let Some(root) = &source.additional_grant_root {
                let canonical = fs::canonicalize(root).map_err(|error| {
                    AppError::AgentPreset(format!(
                        "configured agent root {} is unavailable: {error}; create it outside Sandy or unset the override",
                        root.display()
                    ))
                })?;
                if paths.home.as_deref() == Some(canonical.as_path())
                    || paths.protected.iter().any(|item| {
                        canonical.starts_with(item.as_path())
                            || item.as_path().starts_with(&canonical)
                    })
                {
                    return Err(AppError::AgentPreset(
                        "configured agent root is too broad or overlaps protected data".to_owned(),
                    ));
                }
                intent = intent.grant_file(root.clone(), AccessMode::ReadWrite, PathScope::Subtree);
            }

            let hook_path = match (source.protocol, source.scope) {
                (HookProtocol::OpenCodePlugin, HookSourceScope::Directory) => {
                    source.path.join("numbat.ts")
                }
                (_, HookSourceScope::File) => source.path.clone(),
                (_, HookSourceScope::Directory) => continue,
            };
            protected.extend(write_protections([hook_path])?);
        }
        protected.sort();
        protected.dedup();
        Ok((intent, protected))
    }
}

/// Agent-owned hook configuration grammar understood by integration resolvers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum HookProtocol {
    ClaudeSettings,
    CodexHooks,
    CodexRequirements,
    OpenCodePlugin,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum HookSourceScope {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedHookSource {
    pub(crate) protocol: HookProtocol,
    pub(crate) path: PathBuf,
    pub(crate) scope: HookSourceScope,
    user_source: bool,
    additional_grant_root: Option<PathBuf>,
}

impl ResolvedHookSource {
    #[cfg(test)]
    pub(crate) fn fixed(protocol: HookProtocol, path: PathBuf, scope: HookSourceScope) -> Self {
        Self {
            protocol,
            path,
            scope,
            user_source: false,
            additional_grant_root: None,
        }
    }
}

/// Selects one fixed agent preset. Explicit selection wins; otherwise only an
/// exact target basename is considered before falling back to `generic`.
pub(crate) fn select(
    requested: Option<&str>,
    target_name: &OsStr,
) -> Result<AgentPreset, AppError> {
    if let Some(name) = requested {
        return definition(name)
            .map(|definition| AgentPreset {
                definition,
                detected: false,
            })
            .ok_or_else(|| AppError::UnknownAgent {
                name: name.to_owned(),
                available: available_names(),
            });
    }
    let basename = Path::new(target_name).file_name().and_then(OsStr::to_str);
    let detected = basename.and_then(|basename| {
        AGENTS
            .iter()
            .find(|agent| agent.binary_names.contains(&basename))
    });
    let definition = match detected {
        Some(definition) => definition,
        None => definition(GENERIC_AGENT).ok_or_else(|| {
            AppError::AgentPreset("generic agent definition is unavailable".to_owned())
        })?,
    };
    Ok(AgentPreset {
        definition,
        detected: detected.is_some(),
    })
}

fn definition(name: &str) -> Option<&'static AgentDefinition> {
    AGENTS.iter().find(|agent| agent.name == name)
}

fn available_names() -> Vec<&'static str> {
    AGENTS.iter().map(|agent| agent.name).collect()
}

fn expand(value: &str, paths: &ResolvedUserPaths) -> Option<PathBuf> {
    match value.strip_prefix("~/") {
        Some(rest) => Some(paths.home.as_deref()?.join(rest)),
        None => Some(PathBuf::from(value)),
    }
}

fn optional_path_exists(path: &Path) -> Result<bool, AppError> {
    path.try_exists()
        .map_err(|error| AppError::io("inspect optional agent path", error))
}

fn resolve_hook_source(
    source: &HookSourceSpec,
    paths: &ResolvedUserPaths,
    environment: &impl Fn(&str) -> Option<OsString>,
) -> Result<Option<ResolvedHookSource>, AppError> {
    let (path, user_source, additional_grant_root) = match source.location {
        HookLocation::Fixed(path) => (expand(path, paths), false, None),
        HookLocation::ClaudeUserSettings => {
            let configured = configured_root("CLAUDE_CONFIG_DIR", environment)?;
            let root = configured
                .clone()
                .or_else(|| paths.home.as_deref().map(|home| home.join(".claude")));
            (
                root.map(|root| root.join("settings.json")),
                true,
                configured,
            )
        }
        HookLocation::CodexUserHooks => {
            let configured = configured_root("CODEX_HOME", environment)?;
            let root = configured
                .clone()
                .or_else(|| paths.home.as_deref().map(|home| home.join(".codex")));
            (root.map(|root| root.join("hooks.json")), true, configured)
        }
        HookLocation::OpenCodeUserPlugins => {
            let configured = if let Some(root) =
                configured_root("OPENCODE_CONFIG_DIR", environment)?
            {
                Some(root)
            } else {
                configured_root("XDG_CONFIG_HOME", environment)?.map(|root| root.join("opencode"))
            };
            let root = configured.clone().or_else(|| {
                paths
                    .home
                    .as_deref()
                    .map(|home| home.join(".config/opencode"))
            });
            (root.map(|root| root.join("plugins")), true, configured)
        }
    };
    Ok(path.map(|path| ResolvedHookSource {
        protocol: source.protocol,
        path,
        scope: source.scope,
        user_source,
        additional_grant_root,
    }))
}

fn configured_root(
    variable: &'static str,
    environment: &impl Fn(&str) -> Option<OsString>,
) -> Result<Option<PathBuf>, AppError> {
    let Some(value) = environment(variable).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    let absolute = absolute_if_utf8(&path).map_err(|_| {
        AppError::AgentPreset(format!(
            "{variable} must name an absolute UTF-8 configuration directory"
        ))
    })?;
    if absolute.is_root() {
        return Err(AppError::AgentPreset(format!(
            "{variable} must not name the filesystem root"
        )));
    }
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::ffi::OsStringExt as _};

    use super::*;
    use crate::resolve::CliPolicyIntent;

    fn test_paths() -> ResolvedUserPaths {
        ResolvedUserPaths {
            home: Some(PathBuf::from("/Users/example")),
            protected: Vec::new(),
        }
    }

    #[test]
    fn definitions_are_small_closed_and_unambiguous() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            available_names(),
            ["claude", "codex", "opencode", "generic"]
        );
        for (position, agent) in AGENTS.iter().enumerate() {
            assert!(!agent.name.is_empty());
            assert!(
                !AGENTS[..position]
                    .iter()
                    .any(|other| other.name == agent.name)
            );
            for binary in agent.binary_names {
                assert!(
                    !AGENTS[..position]
                        .iter()
                        .flat_map(|other| other.binary_names)
                        .any(|other| other == binary)
                );
            }
        }

        let claude = definition("claude").ok_or("missing static definition")?;
        assert_eq!(
            (
                claude.grants.len(),
                claude.deny_write_exact.len(),
                claude.hook_sources.len()
            ),
            (2, 2, 3)
        );
        let codex = definition("codex").ok_or("missing static definition")?;
        assert_eq!(
            (
                codex.grants.len(),
                codex.deny_write_exact.len(),
                codex.hook_sources.len()
            ),
            (1, 2, 2)
        );
        let opencode = definition("opencode").ok_or("missing static definition")?;
        assert_eq!(
            (
                opencode.grants.len(),
                opencode.deny_write_exact.len(),
                opencode.hook_sources.len()
            ),
            (2, 2, 1)
        );
        Ok(())
    }

    #[test]
    fn detection_uses_only_exact_basenames_and_explicit_selection_wins()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(select(None, OsStr::new("claude"))?.name(), "claude");
        assert_eq!(select(None, OsStr::new("clauded"))?.name(), GENERIC_AGENT);
        assert_eq!(select(None, OsStr::new("/bin/claude"))?.name(), "claude");
        let explicit = select(Some(GENERIC_AGENT), OsStr::new("claude"))?;
        assert_eq!(explicit.name(), GENERIC_AGENT);
        assert!(!explicit.detected());
        Ok(())
    }

    #[test]
    fn default_policy_keeps_file_and_executable_authority_independent()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let state = root.path().join(".codex");
        fs::create_dir(&state)?;
        let paths = ResolvedUserPaths {
            home: Some(root.path().to_path_buf()),
            protected: Vec::new(),
        };
        let preset = select(Some("codex"), OsStr::new("anything"))?;
        let intent = CliPolicyIntent::new(preset.policy(NetworkPolicy::BlockAll, &paths)?);
        let policy = crate::resolve::resolve_policy(intent, &paths.protected)?
            .finish()?
            .into_spec();
        let state = fs::canonicalize(state)?;
        assert!(
            policy
                .files
                .iter()
                .any(|grant| grant.path.as_path() == state)
        );
        assert!(
            !policy
                .executables
                .iter()
                .any(|grant| grant.path.as_path() == state)
        );
        Ok(())
    }

    #[test]
    fn configured_hook_roots_are_validated() -> Result<(), Box<dyn std::error::Error>> {
        let preset = select(Some("codex"), OsStr::new("codex"))?;
        let source = preset.definition.hook_sources[0];
        let invalid = PathBuf::from(OsString::from_vec(b"relative\0root".to_vec()));
        assert!(
            resolve_hook_source(&source, &test_paths(), &|_| {
                Some(invalid.clone().into_os_string())
            })
            .is_err()
        );
        assert!(
            resolve_hook_source(&source, &test_paths(), &|_| Some(OsString::from("/"))).is_err()
        );
        Ok(())
    }

    #[test]
    fn hook_locations_honor_agent_configuration_roots() -> Result<(), Box<dyn std::error::Error>> {
        let paths = test_paths();
        let environment = |key: &str| match key {
            "CLAUDE_CONFIG_DIR" => Some(OsString::from("/agent-config/claude")),
            "CODEX_HOME" => Some(OsString::from("/agent-config/codex")),
            "OPENCODE_CONFIG_DIR" => Some(OsString::from("/agent-config/opencode")),
            _ => None,
        };
        for (name, expected) in [
            ("claude", "/agent-config/claude/settings.json"),
            ("codex", "/agent-config/codex/hooks.json"),
            ("opencode", "/agent-config/opencode/plugins"),
        ] {
            let preset = select(Some(name), OsStr::new(name))?;
            let source =
                resolve_hook_source(&preset.definition.hook_sources[0], &paths, &environment)?
                    .ok_or("hook source was not resolved")?;
            assert_eq!(source.path, PathBuf::from(expected));
        }
        Ok(())
    }
}
