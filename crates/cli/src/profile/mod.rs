use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use sandy_core::{
    AbsolutePath, AccessMode, GENERIC_PROFILE_NAME, HookProtocol, HookSourceLocation,
    HookSourceScope, HookSourceTemplate, PathScope, ProfileError, ProfileRegistry, ResolvedProfile,
    TemplatePath,
};

use crate::{
    error::AppError,
    resolve::{ResolvedPaths, absolute_if_utf8, grant, write_protections},
};

const EMBEDDED_PROFILES: &[(&str, &str)] = &[
    ("base", include_str!("../../profiles/base.json")),
    ("claude", include_str!("../../profiles/claude.json")),
    ("codex", include_str!("../../profiles/codex.json")),
    ("opencode", include_str!("../../profiles/opencode.json")),
    ("generic", include_str!("../../profiles/generic.json")),
];

fn registry() -> Result<&'static ProfileRegistry, AppError> {
    static REGISTRY: OnceLock<Result<ProfileRegistry, ProfileError>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| ProfileRegistry::build(EMBEDDED_PROFILES))
        .as_ref()
        .map_err(|error| AppError::Profile(error.to_string()))
}

#[derive(Clone, Debug)]
pub(crate) struct SelectedProfile {
    resolved: ResolvedProfile,
    detected: bool,
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

impl SelectedProfile {
    pub(crate) fn name(&self) -> &str {
        self.resolved.name()
    }

    pub(crate) fn detected(&self) -> bool {
        self.detected
    }

    /// Raw protected-path templates for early path resolution, before a
    /// `ResolvedPaths` exists.
    pub(crate) fn protected_templates(&self) -> &[TemplatePath] {
        self.resolved.protected_paths()
    }

    pub(crate) fn grants(
        &self,
        paths: &ResolvedPaths,
    ) -> Result<Vec<sandy_core::FileGrant>, AppError> {
        let mut resolved_grants = Vec::new();
        for template in self.resolved.grants() {
            let Some(path) = expand(&template.path, paths) else {
                continue;
            };
            if template.if_exists && !path.exists() {
                continue;
            }
            resolved_grants.push(grant(
                &path,
                template.access,
                template.scope,
                &paths.protected,
            )?);
        }
        Ok(resolved_grants)
    }

    pub(crate) fn protected_paths(&self, paths: &ResolvedPaths) -> Vec<AbsolutePath> {
        expand_all(self.resolved.protected_paths(), paths)
    }

    pub(crate) fn protected_write_paths(
        &self,
        paths: &ResolvedPaths,
    ) -> Result<Vec<sandy_core::WriteProtection>, AppError> {
        write_protections(
            self.resolved
                .protected_write_paths()
                .iter()
                .filter_map(|template| expand(template, paths)),
        )
    }

    pub(crate) fn hook_sources(
        &self,
        paths: &ResolvedPaths,
    ) -> Result<Vec<ResolvedHookSource>, AppError> {
        self.resolved
            .hook_sources()
            .iter()
            .filter_map(|source| {
                resolve_hook_source(source, paths, &|key| env::var_os(key)).transpose()
            })
            .collect()
    }

    /// Grants configured agent roots and protects user-controlled hook leaves
    /// before any runtime-control adapter inspects their contents.
    pub(crate) fn hook_source_policy(
        &self,
        sources: &[ResolvedHookSource],
        paths: &ResolvedPaths,
    ) -> Result<(Vec<sandy_core::FileGrant>, Vec<sandy_core::WriteProtection>), AppError> {
        let mut grants = Vec::new();
        let mut protected = Vec::new();
        for source in sources.iter().filter(|source| source.user_source) {
            if let Some(root) = &source.additional_grant_root {
                let canonical = fs::canonicalize(root).map_err(|error| {
                    AppError::Profile(format!(
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
                    return Err(AppError::Profile(format!(
                        "configured agent root {} is too broad or overlaps protected data",
                        root.display()
                    )));
                }
                grants.push(grant(
                    root,
                    AccessMode::ReadWrite,
                    PathScope::Subtree,
                    &paths.protected,
                )?);
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
        grants.sort();
        grants.dedup();
        protected.sort();
        protected.dedup();
        Ok((grants, protected))
    }
}

fn resolve_hook_source(
    source: &HookSourceTemplate,
    paths: &ResolvedPaths,
    environment: &impl Fn(&str) -> Option<OsString>,
) -> Result<Option<ResolvedHookSource>, AppError> {
    let (path, user_source, additional_grant_root) = match &source.location {
        HookSourceLocation::Fixed(template) => (expand(template, paths), false, None),
        HookSourceLocation::ClaudeUserSettings => {
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
        HookSourceLocation::CodexUserHooks => {
            let configured = configured_root("CODEX_HOME", environment)?;
            let root = configured
                .clone()
                .or_else(|| paths.home.as_deref().map(|home| home.join(".codex")));
            (root.map(|root| root.join("hooks.json")), true, configured)
        }
        HookSourceLocation::OpenCodeUserPlugins => {
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
        AppError::Profile(format!(
            "{variable} must name an absolute UTF-8 configuration directory"
        ))
    })?;
    if absolute.is_root() {
        return Err(AppError::Profile(format!(
            "{variable} must not name the filesystem root"
        )));
    }
    Ok(Some(path))
}

/// Selects the agent profile. An explicit `--profile` name always wins and
/// must exist. Otherwise the target basename is matched against profile
/// detection claims; unknown targets fall back to the generic profile.
pub(crate) fn select(
    requested: Option<&String>,
    target_name: &OsStr,
) -> Result<SelectedProfile, AppError> {
    if let Some(name) = requested {
        return Ok(SelectedProfile {
            resolved: resolve_by_name(name)?,
            detected: false,
        });
    }
    let detected_name = Path::new(target_name)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .and_then(|basename| {
            registry()
                .ok()
                .and_then(|registry| registry.detect(basename).map(str::to_owned))
        });
    let (name, detected) = match detected_name {
        Some(name) => (name, true),
        None => (GENERIC_PROFILE_NAME.to_owned(), false),
    };
    Ok(SelectedProfile {
        resolved: resolve_by_name(&name)?,
        detected,
    })
}

fn resolve_by_name(name: &str) -> Result<ResolvedProfile, AppError> {
    let available =
        || registry().map_or_else(|_| Vec::new(), |registry| registry.selectable_names());
    registry()?
        .resolve_selectable(name)
        .map_err(|error| match error {
            ProfileError::UnknownProfile(_) | ProfileError::AbstractProfile(_) => {
                AppError::UnknownProfile {
                    name: name.to_owned(),
                    available: available(),
                }
            }
            other => AppError::Profile(other.to_string()),
        })
}

fn expand(template: &TemplatePath, paths: &ResolvedPaths) -> Option<PathBuf> {
    let value = template.as_str();
    match value.strip_prefix("~/") {
        Some(rest) => Some(paths.home.as_deref()?.join(rest)),
        None => Some(PathBuf::from(value)),
    }
}

fn expand_all(templates: &[TemplatePath], paths: &ResolvedPaths) -> Vec<AbsolutePath> {
    templates
        .iter()
        .filter_map(|template| expand(template, paths))
        .filter_map(|path| absolute_if_utf8(&path).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_paths() -> Result<ResolvedPaths, sandy_core::PathValidationError> {
        Ok(ResolvedPaths {
            working_directory: AbsolutePath::new("/workspace")?,
            home: Some(PathBuf::from("/Users/example")),
            protected: Vec::new(),
        })
    }

    #[test]
    fn embedded_profiles_form_closed_registry() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            registry()?.names(),
            vec![
                "base".to_owned(),
                "claude".to_owned(),
                "codex".to_owned(),
                "generic".to_owned(),
                "opencode".to_owned(),
            ]
        );
        Ok(())
    }

    #[test]
    fn every_selectable_profile_inherits_protection_from_base()
    -> Result<(), Box<dyn std::error::Error>> {
        for name in ["generic", "claude", "codex", "opencode"] {
            let resolved = resolve_by_name(name)?;
            assert!(
                !resolved.protected_paths().is_empty(),
                "{name} must inherit protected paths from base"
            );
            assert_eq!(resolved.name(), name);
        }
        Ok(())
    }

    #[test]
    fn agent_profiles_declare_expected_surfaces() -> Result<(), Box<dyn std::error::Error>> {
        let claude = resolve_by_name("claude")?;
        assert_eq!(claude.binary_names(), ["claude"]);
        assert_eq!(claude.hook_sources().len(), 3);
        assert_eq!(claude.grants().len(), 2);
        assert_eq!(claude.protected_write_paths().len(), 2);

        let codex = resolve_by_name("codex")?;
        assert_eq!(codex.binary_names(), ["codex"]);
        assert_eq!(codex.hook_sources().len(), 2);
        assert_eq!(codex.grants().len(), 1);

        let opencode = resolve_by_name("opencode")?;
        assert_eq!(opencode.binary_names(), ["opencode"]);
        assert_eq!(opencode.hook_sources().len(), 1);
        assert_eq!(opencode.grants().len(), 2);
        assert_eq!(opencode.protected_write_paths().len(), 2);
        Ok(())
    }

    #[test]
    fn generic_profile_carries_no_extra_grants() -> Result<(), Box<dyn std::error::Error>> {
        assert!(resolve_by_name(GENERIC_PROFILE_NAME)?.grants().is_empty());
        Ok(())
    }

    #[test]
    fn detection_matches_only_exact_basenames() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(registry()?.detect("claude"), Some("claude"));
        assert_eq!(registry()?.detect("/usr/local/bin/claude"), None);
        assert_eq!(registry()?.detect("clauded"), None);
        Ok(())
    }

    #[test]
    fn unknown_profile_error_lists_available_names() {
        let error = select(Some(&"ghost".to_owned()), std::ffi::OsStr::new("anything"));
        assert!(error.is_err());
        if let Err(AppError::UnknownProfile { available, .. }) = error {
            assert!(available.contains(&"opencode".to_owned()));
            assert!(available.contains(&"codex".to_owned()));
            assert!(!available.contains(&"base".to_owned()));
        }
    }

    #[test]
    fn inheritance_only_profile_cannot_be_selected() {
        let error = select(Some(&"base".to_owned()), std::ffi::OsStr::new("anything"));
        assert!(matches!(error, Err(AppError::UnknownProfile { .. })));
    }

    #[test]
    fn explicit_selection_overrides_detection() {
        let selection = select(Some(&"generic".to_owned()), std::ffi::OsStr::new("claude"));
        assert!(selection.is_ok());
        if let Ok(selection) = selection {
            assert_eq!(selection.name(), "generic");
            assert!(!selection.detected());
        }
    }

    #[test]
    fn user_hook_locations_honor_agent_configuration_roots()
    -> Result<(), Box<dyn std::error::Error>> {
        let paths = test_paths()?;
        let environment = |key: &str| match key {
            "CLAUDE_CONFIG_DIR" => Some(OsString::from("/agent-config/claude")),
            "CODEX_HOME" => Some(OsString::from("/agent-config/codex")),
            "OPENCODE_CONFIG_DIR" => Some(OsString::from("/agent-config/opencode")),
            "XDG_CONFIG_HOME" => Some(OsString::from("/ignored/xdg")),
            _ => None,
        };

        let claude = resolve_by_name("claude")?;
        let claude_source = resolve_hook_source(&claude.hook_sources()[0], &paths, &environment)?
            .ok_or("Claude source was not resolved")?;
        assert_eq!(
            claude_source.path,
            PathBuf::from("/agent-config/claude/settings.json")
        );

        let codex = resolve_by_name("codex")?;
        let codex_source = resolve_hook_source(&codex.hook_sources()[0], &paths, &environment)?
            .ok_or("Codex source was not resolved")?;
        assert_eq!(
            codex_source.path,
            PathBuf::from("/agent-config/codex/hooks.json")
        );

        let opencode = resolve_by_name("opencode")?;
        let opencode_source =
            resolve_hook_source(&opencode.hook_sources()[0], &paths, &environment)?
                .ok_or("OpenCode source was not resolved")?;
        assert_eq!(
            opencode_source.path,
            PathBuf::from("/agent-config/opencode/plugins")
        );
        Ok(())
    }

    #[test]
    fn opencode_uses_xdg_root_only_without_its_direct_override()
    -> Result<(), Box<dyn std::error::Error>> {
        let paths = test_paths()?;
        let opencode = resolve_by_name("opencode")?;
        let source = resolve_hook_source(&opencode.hook_sources()[0], &paths, &|key| {
            (key == "XDG_CONFIG_HOME").then(|| OsString::from("/agent-config/xdg"))
        })?
        .ok_or("OpenCode source was not resolved")?;
        assert_eq!(
            source.path,
            PathBuf::from("/agent-config/xdg/opencode/plugins")
        );
        Ok(())
    }

    #[test]
    fn rejects_unsafe_configuration_root_overrides() -> Result<(), Box<dyn std::error::Error>> {
        let paths = test_paths()?;
        let codex = resolve_by_name("codex")?;
        for value in ["relative", "/"] {
            let result = resolve_hook_source(&codex.hook_sources()[0], &paths, &|key| {
                (key == "CODEX_HOME").then(|| OsString::from(value))
            });
            assert!(matches!(result, Err(AppError::Profile(_))));
        }
        Ok(())
    }

    #[test]
    fn protects_absent_user_hook_leaves_before_discovery() -> Result<(), Box<dyn std::error::Error>>
    {
        let paths = test_paths()?;
        for (profile, expected) in [
            ("claude", "/Users/example/.claude/settings.json"),
            ("codex", "/Users/example/.codex/hooks.json"),
            (
                "opencode",
                "/Users/example/.config/opencode/plugins/numbat.ts",
            ),
        ] {
            let selected = resolve_by_name(profile)?;
            let sources = selected
                .hook_sources()
                .iter()
                .filter_map(|source| resolve_hook_source(source, &paths, &|_| None).transpose())
                .collect::<Result<Vec<_>, _>>()?;
            let (_, protections) = SelectedProfile {
                resolved: selected,
                detected: false,
            }
            .hook_source_policy(&sources, &paths)?;
            assert!(
                protections
                    .iter()
                    .any(|item| item.path.as_str() == expected)
            );
        }
        Ok(())
    }

    #[test]
    fn configured_root_is_granted_and_its_hook_leaf_is_protected()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let project = root.path().join("project");
        let config = root.path().join("opencode-config");
        fs::create_dir(&home)?;
        fs::create_dir(&project)?;
        fs::create_dir(&config)?;
        let paths = ResolvedPaths {
            working_directory: absolute_if_utf8(&fs::canonicalize(&project)?)?,
            home: Some(fs::canonicalize(&home)?),
            protected: Vec::new(),
        };
        let resolved = resolve_by_name("opencode")?;
        let source = resolve_hook_source(&resolved.hook_sources()[0], &paths, &|key| {
            (key == "OPENCODE_CONFIG_DIR").then(|| config.clone().into_os_string())
        })?
        .ok_or("OpenCode source was not resolved")?;
        let selected = SelectedProfile {
            resolved,
            detected: false,
        };
        let (grants, protections) = selected.hook_source_policy(&[source], &paths)?;
        let canonical = fs::canonicalize(&config)?;
        assert!(grants.iter().any(|grant| {
            grant.path.as_path() == canonical && grant.scope == PathScope::Subtree
        }));
        assert!(
            protections
                .iter()
                .any(|item| { item.path.as_path() == canonical.join("plugins/numbat.ts") })
        );
        Ok(())
    }
}
