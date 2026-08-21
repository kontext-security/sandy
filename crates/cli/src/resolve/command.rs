use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use crate::error::AppError;

#[derive(Debug)]
pub(crate) struct ResolvedCommand {
    pub(crate) program: PathBuf,
    pub(crate) arguments: Vec<OsString>,
    pub(crate) requested_name: OsString,
}

pub(crate) fn resolve_command(target: &[OsString]) -> Result<ResolvedCommand, AppError> {
    let Some(requested) = target.first() else {
        return Err(AppError::CommandNotFound(PathBuf::new()));
    };
    let candidate = Path::new(requested);
    let program = if candidate.is_absolute() || candidate.components().count() > 1 {
        executable(candidate)?
    } else {
        find_on_path(requested)?
    };

    Ok(ResolvedCommand {
        program,
        arguments: target.iter().skip(1).cloned().collect(),
        requested_name: requested.clone(),
    })
}

fn find_on_path(name: &OsStr) -> Result<PathBuf, AppError> {
    let Some(path) = env::var_os("PATH") else {
        return Err(AppError::CommandNotFound(PathBuf::from(name)));
    };
    for directory in env::split_paths(&path) {
        let candidate = directory.join(name);
        if let Ok(path) = executable(&candidate) {
            return Ok(path);
        }
    }
    Err(AppError::CommandNotFound(PathBuf::from(name)))
}

fn executable(path: &Path) -> Result<PathBuf, AppError> {
    let metadata = fs::metadata(path).map_err(|_| AppError::CommandNotFound(path.to_path_buf()))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(AppError::CommandNotFound(path.to_path_buf()));
    }
    fs::canonicalize(path).map_err(|error| AppError::io("canonicalize target command", error))
}
