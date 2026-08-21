use std::path::Path;

use sandy_core::{AbsolutePath, AccessMode, FileGrant, PathScope};

use crate::{
    error::AppError,
    resolve::{ResolvedPaths, absolute_if_utf8, grant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Preset {
    Claude,
    Codex,
    Minimal,
}

pub(crate) fn protected_write_paths(
    preset: Preset,
    paths: &ResolvedPaths,
) -> Result<Vec<AbsolutePath>, AppError> {
    let Some(home) = &paths.home else {
        return Ok(Vec::new());
    };
    let candidates = match preset {
        Preset::Claude => vec![
            home.join(".claude/settings.json"),
            home.join(".claude.json"),
        ],
        Preset::Codex => vec![
            home.join(".codex/hooks.json"),
            home.join(".codex/config.toml"),
        ],
        Preset::Minimal => Vec::new(),
    };
    candidates
        .into_iter()
        .map(|path| absolute_if_utf8(&path))
        .collect()
}

pub(crate) fn select(requested_name: &std::ffi::OsStr) -> Preset {
    match Path::new(requested_name)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
    {
        Some("claude") => Preset::Claude,
        Some("codex") => Preset::Codex,
        _ => Preset::Minimal,
    }
}

pub(crate) fn grants(preset: Preset, paths: &ResolvedPaths) -> Result<Vec<FileGrant>, AppError> {
    let Some(home) = &paths.home else {
        return Ok(Vec::new());
    };
    let candidates = match preset {
        Preset::Claude => vec![home.join(".claude"), home.join(".claude.json")],
        Preset::Codex => vec![home.join(".codex")],
        Preset::Minimal => Vec::new(),
    };
    candidates
        .into_iter()
        .filter(|path| path.exists())
        .map(|path| grant(&path, AccessMode::ReadWrite, PathScope::Subtree, &[]))
        .collect()
}
