use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use sandy_core::{
    AbsolutePath, GENERIC_PROFILE_NAME, HookProtocol, ProfileError, ProfileRegistry,
    ResolvedProfile, TemplatePath,
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
    ) -> Result<Vec<AbsolutePath>, AppError> {
        write_protections(
            self.resolved
                .protected_write_paths()
                .iter()
                .filter_map(|template| expand(template, paths)),
        )
    }

    pub(crate) fn hook_sources(&self, paths: &ResolvedPaths) -> Vec<ResolvedHookSource> {
        self.resolved
            .hook_sources()
            .iter()
            .filter_map(|source| {
                Some(ResolvedHookSource {
                    protocol: source.protocol,
                    path: expand(&source.path, paths)?,
                })
            })
            .collect()
    }
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
        assert_eq!(codex.hook_sources().len(), 1);
        assert_eq!(codex.grants().len(), 1);

        let opencode = resolve_by_name("opencode")?;
        assert_eq!(opencode.binary_names(), ["opencode"]);
        assert!(opencode.hook_sources().is_empty());
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
}
