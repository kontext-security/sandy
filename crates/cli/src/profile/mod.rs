use std::{
    borrow::Cow,
    env,
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::Read as _,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use sandy_core::{
    AbsolutePath, GENERIC_PROFILE_NAME, HookProtocol, HookSourceLocation, HookSourceScope,
    HookSourceTemplate, MAX_USER_PROFILE_SOURCE_BYTES, ProfileError, ProfileRegistry,
    ResolvedProfile, ResolvedUserProfile, TemplatePath, UserProfileDocumentV1,
};
#[cfg(any(target_os = "macos", test))]
use sandy_core::{AccessMode, PathScope};

use crate::{
    error::AppError,
    resolve::{
        CliPolicyIntent, ResolvedUserPaths, absolute_if_utf8, protection_path_spellings,
        write_protections,
    },
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
pub(crate) enum SelectedProfile {
    Embedded {
        profile: ResolvedProfile,
        detected: bool,
    },
    UserFile {
        profile: ResolvedUserProfile,
        source_paths: Vec<AbsolutePath>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedProfileProtections {
    paths: Vec<AbsolutePath>,
    required_user_paths: Vec<(usize, AbsolutePath)>,
}

impl ResolvedProfileProtections {
    pub(crate) fn paths(&self) -> &[AbsolutePath] {
        &self.paths
    }

    pub(crate) fn user_entry_containing(&self, path: &Path) -> Option<usize> {
        self.required_user_paths
            .iter()
            .find_map(|(position, protected)| {
                path.starts_with(protected.as_path()).then_some(*position)
            })
    }

    pub(crate) fn redact_conflict(&self, error: AppError) -> AppError {
        let AppError::ProtectedPath(path) = error else {
            return error;
        };
        match self.user_entry_containing(&path) {
            Some(position) => AppError::UserProfilePath {
                section: "deny_subtrees",
                position,
                reason: "overlaps a required launch path",
            },
            None => AppError::ProtectedPath(path),
        }
    }
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
    fn embedded(profile: ResolvedProfile, detected: bool) -> Self {
        Self::Embedded { profile, detected }
    }

    fn user_file(profile: ResolvedUserProfile, source_paths: Vec<AbsolutePath>) -> Self {
        Self::UserFile {
            profile,
            source_paths,
        }
    }

    fn profile(&self) -> &ResolvedProfile {
        match self {
            Self::Embedded { profile, .. } => profile,
            Self::UserFile { profile, .. } => profile.profile(),
        }
    }

    fn user_profile(&self) -> Option<&ResolvedUserProfile> {
        match self {
            Self::Embedded { .. } => None,
            Self::UserFile { profile, .. } => Some(profile),
        }
    }

    pub(crate) fn name(&self) -> &str {
        self.profile().name()
    }

    pub(crate) fn detected(&self) -> bool {
        matches!(self, Self::Embedded { detected: true, .. })
    }

    pub(crate) fn source_name(&self) -> &'static str {
        match self {
            Self::Embedded { .. } => "embedded",
            Self::UserFile { .. } => "user_file",
        }
    }

    pub(crate) fn base_name(&self) -> Option<&str> {
        self.user_profile().map(ResolvedUserProfile::base_name)
    }

    /// Rejects omission of any home-relative path in a user-file composition
    /// when the CLI cannot establish a canonical home directory. Embedded
    /// selections retain their existing compatibility behavior.
    pub(crate) fn validate_user_paths(&self, paths: &ResolvedUserPaths) -> Result<(), AppError> {
        if self
            .user_profile()
            .is_some_and(ResolvedUserProfile::requires_home)
            && paths.home.as_deref().and_then(Path::to_str).is_none()
        {
            return Err(AppError::UserProfile(
                "user profile contains a home-relative path, but HOME is unavailable or invalid"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Adds terminal denial of each path spelling used to load a user profile.
    /// Embedded profiles have no runtime source file.
    pub(crate) fn protect_source(&self, mut intent: CliPolicyIntent) -> CliPolicyIntent {
        if let Self::UserFile { source_paths, .. } = self {
            for path in source_paths {
                intent = intent.deny_subtree(path.as_path());
            }
        }
        intent
    }

    /// Returns only inherited protected-path templates for ambient user-path
    /// discovery. Required user-file entries retain provenance and are
    /// resolved separately by [`Self::protected_paths`].
    pub(crate) fn inherited_protected_templates(&self) -> Cow<'_, [TemplatePath]> {
        let Some(user_profile) = self.user_profile() else {
            return Cow::Borrowed(self.profile().protected_paths());
        };
        let required = user_profile.required_deny_subtrees().collect::<Vec<_>>();
        Cow::Owned(
            self.profile()
                .protected_paths()
                .iter()
                .filter(|template| !required.iter().any(|(_, required)| *required == *template))
                .cloned()
                .collect(),
        )
    }

    /// Adds this profile's typed filesystem intent after expanding path templates.
    ///
    /// Missing optional embedded entries are filtered here. User-authored
    /// grants retain source positions and remain required. Positive path
    /// canonicalization stays centralized in `resolve_policy`.
    pub(crate) fn contribute_grants(
        &self,
        mut intent: CliPolicyIntent,
        paths: &ResolvedUserPaths,
    ) -> Result<CliPolicyIntent, AppError> {
        let required_grants = self
            .user_profile()
            .map(|profile| profile.required_grants().collect::<Vec<_>>())
            .unwrap_or_default();
        for template in self.profile().grants().iter().filter(|template| {
            !required_grants
                .iter()
                .any(|(_, required)| required.same_capability(template))
        }) {
            let Some(path) = expand(&template.path, paths) else {
                continue;
            };
            if template.if_exists && !optional_path_exists(&path)? {
                continue;
            }
            intent = intent.grant_file(path, template.access, template.scope);
        }
        for (position, template) in required_grants {
            let path = expand(&template.path, paths).ok_or(AppError::UserProfileGrant {
                position,
                reason: "could not be expanded",
            })?;
            intent =
                intent.grant_user_profile_file(path, template.access, template.scope, position);
        }
        Ok(intent)
    }

    /// Adds executable-mapping intent independently from ordinary file access.
    pub(crate) fn contribute_executable_grants(
        &self,
        mut intent: CliPolicyIntent,
        paths: &ResolvedUserPaths,
    ) -> Result<CliPolicyIntent, AppError> {
        let required_grants = self
            .user_profile()
            .map(|profile| profile.required_executable_grants().collect::<Vec<_>>())
            .unwrap_or_default();
        for template in self
            .profile()
            .executable_grants()
            .iter()
            .filter(|template| {
                !required_grants
                    .iter()
                    .any(|(_, required)| required.same_capability(template))
            })
        {
            let Some(path) = expand(&template.path, paths) else {
                continue;
            };
            if template.if_exists && !optional_path_exists(&path)? {
                continue;
            }
            intent = intent.allow_execute(path, template.scope);
        }
        for (position, template) in required_grants {
            let path = expand(&template.path, paths).ok_or(AppError::UserProfilePath {
                section: "executable_grants",
                position,
                reason: "could not be expanded",
            })?;
            intent = intent.allow_user_profile_execute(path, template.scope, position);
        }
        Ok(intent)
    }

    pub(crate) fn protected_paths(
        &self,
        paths: &ResolvedUserPaths,
    ) -> Result<ResolvedProfileProtections, AppError> {
        let required_paths = self
            .user_profile()
            .map(|profile| profile.required_deny_subtrees().collect::<Vec<_>>())
            .unwrap_or_default();
        let mut protected = expand_all(
            &self
                .profile()
                .protected_paths()
                .iter()
                .filter(|template| {
                    !required_paths
                        .iter()
                        .any(|(_, required)| *required == *template)
                })
                .cloned()
                .collect::<Vec<_>>(),
            paths,
        );
        let mut required_user_paths = Vec::new();
        for (position, template) in required_paths {
            let path = expand(template, paths).ok_or(AppError::UserProfilePath {
                section: "deny_subtrees",
                position,
                reason: "could not be expanded",
            })?;
            let mut resolved =
                protection_path_spellings([path]).map_err(|_| AppError::UserProfilePath {
                    section: "deny_subtrees",
                    position,
                    reason: "could not be resolved safely",
                })?;
            required_user_paths.extend(resolved.iter().cloned().map(|path| (position, path)));
            protected.append(&mut resolved);
        }
        protected.sort();
        protected.dedup();
        Ok(ResolvedProfileProtections {
            paths: protected,
            required_user_paths,
        })
    }

    pub(crate) fn protected_write_paths(
        &self,
        paths: &ResolvedUserPaths,
    ) -> Result<Vec<sandy_core::WriteProtection>, AppError> {
        let required_paths = self
            .user_profile()
            .map(|profile| profile.required_deny_write_exact().collect::<Vec<_>>())
            .unwrap_or_default();
        let mut protected = write_protections(
            self.profile()
                .protected_write_paths()
                .iter()
                .filter(|template| {
                    !required_paths
                        .iter()
                        .any(|(_, required)| *required == *template)
                })
                .filter_map(|template| expand(template, paths)),
        )?;
        for (position, template) in required_paths {
            let path = expand(template, paths).ok_or(AppError::UserProfilePath {
                section: "deny_write_exact",
                position,
                reason: "could not be expanded",
            })?;
            let mut resolved =
                write_protections([path]).map_err(|_| AppError::UserProfilePath {
                    section: "deny_write_exact",
                    position,
                    reason: "could not be resolved safely",
                })?;
            protected.append(&mut resolved);
        }
        protected.sort();
        protected.dedup();
        Ok(protected)
    }

    pub(crate) fn hook_sources(
        &self,
        paths: &ResolvedUserPaths,
    ) -> Result<Vec<ResolvedHookSource>, AppError> {
        self.profile()
            .hook_sources()
            .iter()
            .filter_map(|source| {
                resolve_hook_source(source, paths, &|key| env::var_os(key)).transpose()
            })
            .collect()
    }

    /// Grants configured agent roots and protects user-controlled hook leaves
    /// before any runtime-control resolver inspects their contents.
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn contribute_hook_source_policy(
        &self,
        mut intent: CliPolicyIntent,
        sources: &[ResolvedHookSource],
        paths: &ResolvedUserPaths,
    ) -> Result<(CliPolicyIntent, Vec<sandy_core::WriteProtection>), AppError> {
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
                    return Err(AppError::Profile(
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

fn resolve_hook_source(
    source: &HookSourceTemplate,
    paths: &ResolvedUserPaths,
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
        return Ok(SelectedProfile::embedded(resolve_by_name(name)?, false));
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
    Ok(SelectedProfile::embedded(resolve_by_name(&name)?, detected))
}

/// Loads exactly one explicit user profile file and composes it with its
/// selectable embedded base.
pub(crate) fn load_user(path: &Path) -> Result<SelectedProfile, AppError> {
    let (source, source_paths) = read_user_profile(path)?;
    let document = UserProfileDocumentV1::parse(&source)
        .map_err(|error| AppError::UserProfile(error.to_string()))?;
    let resolved = registry()?
        .resolve_user_profile(document)
        .map_err(|error| AppError::UserProfile(error.to_string()))?;
    Ok(SelectedProfile::user_file(resolved, source_paths))
}

/// Reads from the canonical path selected before opening while retaining
/// the user's absolute lexical spelling for terminal source protection.
fn read_user_profile(path: &Path) -> Result<(String, Vec<AbsolutePath>), AppError> {
    let lexical_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| AppError::io("read working directory for user profile", error))?
            .join(path)
    };
    let lexical = absolute_if_utf8(&lexical_path).map_err(|_| {
        AppError::UserProfile(
            "user profile path must be absolute UTF-8 without parent traversal".to_owned(),
        )
    })?;

    let canonical_path = fs::canonicalize(&lexical_path)
        .map_err(|error| AppError::io("resolve user profile file", error))?;
    // The pathname check rejects steady FIFOs and devices before `open` can
    // block. The opened-handle check below narrows replacement races.
    let metadata = fs::metadata(&canonical_path)
        .map_err(|error| AppError::io("inspect user profile file", error))?;
    if !metadata.is_file() {
        return Err(AppError::UserProfile(
            "user profile source must be a regular file".to_owned(),
        ));
    }
    if metadata.len() > MAX_USER_PROFILE_SOURCE_BYTES as u64 {
        return Err(AppError::UserProfile(
            "user profile exceeds the source-size limit".to_owned(),
        ));
    }
    let file = File::open(&canonical_path)
        .map_err(|error| AppError::io("open user profile file", error))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| AppError::io("inspect opened user profile file", error))?;
    if !opened_metadata.is_file() {
        return Err(AppError::UserProfile(
            "user profile source must be a regular file".to_owned(),
        ));
    }
    if opened_metadata.len() > MAX_USER_PROFILE_SOURCE_BYTES as u64 {
        return Err(AppError::UserProfile(
            "user profile exceeds the source-size limit".to_owned(),
        ));
    }
    let mut source = Vec::new();
    file.take((MAX_USER_PROFILE_SOURCE_BYTES as u64) + 1)
        .read_to_end(&mut source)
        .map_err(|error| AppError::io("read user profile file", error))?;
    if source.len() > MAX_USER_PROFILE_SOURCE_BYTES {
        return Err(AppError::UserProfile(
            "user profile exceeds the source-size limit".to_owned(),
        ));
    }
    let source = String::from_utf8(source)
        .map_err(|_| AppError::UserProfile("source must be strict UTF-8 JSON".to_owned()))?;
    let canonical = absolute_if_utf8(&canonical_path)
        .map_err(|_| AppError::UserProfile("canonical path must be absolute UTF-8".to_owned()))?;
    let mut source_paths = vec![lexical];
    if canonical != source_paths[0] {
        source_paths.push(canonical);
    }
    Ok((source, source_paths))
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

fn expand(template: &TemplatePath, paths: &ResolvedUserPaths) -> Option<PathBuf> {
    let value = template.as_str();
    match value.strip_prefix("~/") {
        Some(rest) => Some(paths.home.as_deref()?.join(rest)),
        None => Some(PathBuf::from(value)),
    }
}

fn optional_path_exists(path: &Path) -> Result<bool, AppError> {
    path.try_exists()
        .map_err(|error| AppError::io("inspect optional profile path", error))
}

fn expand_all(templates: &[TemplatePath], paths: &ResolvedUserPaths) -> Vec<AbsolutePath> {
    templates
        .iter()
        .filter_map(|template| expand(template, paths))
        .filter_map(|path| absolute_if_utf8(&path).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStringExt as _;

    use sandy_core::SandboxPolicy;

    use super::*;

    fn test_paths() -> Result<ResolvedUserPaths, sandy_core::PathValidationError> {
        Ok(ResolvedUserPaths {
            home: Some(PathBuf::from("/Users/example")),
            protected: Vec::new(),
        })
    }

    #[test]
    fn optional_profile_paths_skip_only_confirmed_absence() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        assert!(matches!(
            optional_path_exists(&root.path().join("missing")),
            Ok(false)
        ));

        let invalid = PathBuf::from(OsString::from_vec(b"/tmp/invalid\0path".to_vec()));
        assert!(matches!(
            optional_path_exists(&invalid),
            Err(AppError::Io { .. })
        ));
        Ok(())
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
            let (_, protections) = SelectedProfile::embedded(selected, false)
                .contribute_hook_source_policy(
                    CliPolicyIntent::new(SandboxPolicy::new(sandy_core::NetworkPolicy::BlockAll)),
                    &sources,
                    &paths,
                )?;
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
        let paths = ResolvedUserPaths {
            home: Some(fs::canonicalize(&home)?),
            protected: Vec::new(),
        };
        let resolved = resolve_by_name("opencode")?;
        let source = resolve_hook_source(&resolved.hook_sources()[0], &paths, &|key| {
            (key == "OPENCODE_CONFIG_DIR").then(|| config.clone().into_os_string())
        })?
        .ok_or("OpenCode source was not resolved")?;
        let selected = SelectedProfile::embedded(resolved, false);
        let (intent, protections) = selected.contribute_hook_source_policy(
            CliPolicyIntent::new(SandboxPolicy::new(sandy_core::NetworkPolicy::BlockAll)),
            &[source],
            &paths,
        )?;
        let policy = crate::resolve::resolve_policy(intent, &paths.protected)?
            .finish()?
            .into_spec();
        let canonical = fs::canonicalize(&config)?;
        assert!(policy.files.iter().any(|grant| {
            grant.path.as_path() == canonical
                && grant.access == AccessMode::ReadWrite
                && grant.scope == PathScope::Subtree
        }));
        assert!(
            !policy
                .executables
                .iter()
                .any(|grant| grant.path.as_path() == canonical)
        );
        assert!(
            protections
                .iter()
                .any(|item| { item.path.as_path() == canonical.join("plugins/numbat.ts") })
        );
        Ok(())
    }

    #[test]
    fn profile_file_grants_do_not_add_executable_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let codex = home.join(".codex");
        fs::create_dir_all(&codex)?;
        let paths = ResolvedUserPaths {
            home: Some(home),
            protected: Vec::new(),
        };
        let selected = SelectedProfile::embedded(resolve_by_name("codex")?, false);

        let intent = selected.contribute_grants(
            CliPolicyIntent::new(SandboxPolicy::new(sandy_core::NetworkPolicy::BlockAll)),
            &paths,
        )?;
        let policy = crate::resolve::resolve_policy(intent, &paths.protected)?
            .finish()?
            .into_spec();
        let codex = fs::canonicalize(codex)?;

        assert!(policy.files.iter().any(|grant| {
            grant.path.as_path() == codex
                && grant.access == AccessMode::ReadWrite
                && grant.scope == PathScope::Subtree
        }));
        assert!(
            !policy
                .executables
                .iter()
                .any(|grant| grant.path.as_path() == codex)
        );
        Ok(())
    }

    #[test]
    fn user_profile_preserves_base_hooks_and_protections() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let source = root.path().join("session.json");
        fs::write(
            &source,
            r#"{
                "schema_version": 1,
                "name": "session",
                "extends": "codex"
            }"#,
        )?;

        let selected = load_user(&source)?;
        let embedded = resolve_by_name("codex")?;
        assert_eq!(selected.name(), "session");
        assert_eq!(selected.base_name(), Some("codex"));
        assert_eq!(selected.source_name(), "user_file");
        assert_eq!(selected.profile().hook_sources(), embedded.hook_sources());
        assert_eq!(
            selected.profile().protected_paths(),
            embedded.protected_paths()
        );
        Ok(())
    }

    #[test]
    fn user_profile_source_protects_lexical_and_canonical_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let target = root.path().join("stored-profile.json");
        let lexical = root.path().join("session.json");
        let adjacent = root.path().join("adjacent.json");
        fs::write(
            &target,
            r#"{
                "schema_version": 1,
                "name": "session",
                "extends": "generic"
            }"#,
        )?;
        fs::write(&adjacent, "{}")?;
        std::os::unix::fs::symlink(&target, &lexical)?;

        let selected = load_user(&lexical)?;
        let intent = selected.protect_source(CliPolicyIntent::new(SandboxPolicy::new(
            sandy_core::NetworkPolicy::BlockAll,
        )));
        let policy = crate::resolve::resolve_policy(intent, &[])?
            .finish()?
            .into_spec();
        let target = fs::canonicalize(target)?;

        assert!(
            policy
                .protected_paths
                .iter()
                .any(|path| path.as_path() == lexical)
        );
        assert!(
            policy
                .protected_paths
                .iter()
                .any(|path| path.as_path() == target)
        );
        assert!(
            !policy
                .protected_paths
                .iter()
                .any(|path| path.as_path() == adjacent)
        );
        Ok(())
    }

    #[test]
    fn user_protected_alias_blocks_a_grant_to_its_canonical_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let target = root.path().join("protected-target");
        let alias = root.path().join("protected-alias");
        let source = root.path().join("session.json");
        fs::create_dir(&home)?;
        fs::create_dir(&target)?;
        std::os::unix::fs::symlink(&target, &alias)?;
        fs::write(
            &source,
            format!(
                r#"{{
                    "schema_version": 1,
                    "name": "session",
                    "extends": "generic",
                    "grants": [{{
                        "path": "{}",
                        "access": "read",
                        "scope": "subtree"
                    }}],
                    "deny_subtrees": ["{}"]
                }}"#,
                target.display(),
                alias.display(),
            ),
        )?;

        let selected = load_user(&source)?;
        let paths = ResolvedUserPaths {
            home: Some(home),
            protected: Vec::new(),
        };
        let protected = selected.protected_paths(&paths)?;
        let canonical = fs::canonicalize(&target)?;
        assert!(protected.paths().iter().any(|path| path.as_path() == alias));
        assert!(
            protected
                .paths()
                .iter()
                .any(|path| path.as_path() == canonical)
        );

        let intent = selected.contribute_grants(
            CliPolicyIntent::new(SandboxPolicy::new(sandy_core::NetworkPolicy::BlockAll)),
            &paths,
        )?;
        assert!(matches!(
            crate::resolve::resolve_policy(intent, protected.paths()),
            Err(AppError::UserProfileGrant {
                position: 1,
                reason: "overlaps protected data"
            })
        ));
        Ok(())
    }

    #[test]
    fn user_home_templates_require_a_resolved_home() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let source = root.path().join("session.json");
        fs::write(
            &source,
            r#"{
                "schema_version": 1,
                "name": "session",
                "extends": "generic",
                "grants": [{
                    "path": "~/.required",
                    "access": "read",
                    "scope": "subtree"
                }]
            }"#,
        )?;

        let selected = load_user(&source)?;
        let paths = ResolvedUserPaths {
            home: None,
            protected: Vec::new(),
        };
        assert!(matches!(
            selected.validate_user_paths(&paths),
            Err(AppError::UserProfile(_))
        ));

        let paths = ResolvedUserPaths {
            home: Some(PathBuf::from(OsString::from_vec(
                b"/tmp/non-utf8-\xff".to_vec(),
            ))),
            protected: Vec::new(),
        };
        assert!(matches!(
            selected.validate_user_paths(&paths),
            Err(AppError::UserProfile(_))
        ));
        Ok(())
    }
}
