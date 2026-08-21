use std::{
    env, fs,
    path::{Path, PathBuf},
};

use sandy_core::{AbsolutePath, AccessMode, FileGrant, PathScope};

use crate::error::AppError;

#[derive(Debug)]
pub(crate) struct ResolvedPaths {
    pub(crate) working_directory: AbsolutePath,
    pub(crate) home: Option<PathBuf>,
    pub(crate) protected: Vec<AbsolutePath>,
}

pub(crate) fn resolve_paths() -> Result<ResolvedPaths, AppError> {
    let working_directory = fs::canonicalize(
        env::current_dir().map_err(|error| AppError::io("read working directory", error))?,
    )
    .map_err(|error| AppError::io("canonicalize working directory", error))?;
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .and_then(|path| fs::canonicalize(path).ok());

    if working_directory == Path::new("/") || home.as_ref() == Some(&working_directory) {
        return Err(AppError::UnsafeWorkingDirectory);
    }

    let protected_paths: Vec<AbsolutePath> = home
        .as_ref()
        .map(|home| {
            [
                home.join(".ssh"),
                home.join(".gnupg"),
                home.join(".aws"),
                home.join("Library/Keychains"),
            ]
        })
        .into_iter()
        .flatten()
        .filter_map(|path| absolute_if_utf8(&path).ok())
        .collect();

    for path in &protected_paths {
        if working_directory.starts_with(path.as_path()) {
            return Err(AppError::ProtectedPath(working_directory));
        }
    }

    Ok(ResolvedPaths {
        working_directory: absolute_if_utf8(&working_directory)?,
        home,
        protected: protected_paths,
    })
}

pub(crate) fn grant(
    path: &Path,
    access: AccessMode,
    scope: PathScope,
    protected: &[AbsolutePath],
) -> Result<FileGrant, AppError> {
    if !path.exists() {
        return Err(AppError::MissingPath(path.to_path_buf()));
    }
    let path = fs::canonicalize(path).map_err(|error| AppError::io("canonicalize grant", error))?;
    if path == Path::new("/") {
        return Err(AppError::UnsafeWorkingDirectory);
    }
    if protected
        .iter()
        .any(|item| path.starts_with(item.as_path()))
    {
        return Err(AppError::ProtectedPath(path));
    }
    Ok(FileGrant {
        path: absolute_if_utf8(&path)?,
        access,
        scope,
    })
}

pub(crate) fn absolute_if_utf8(path: &Path) -> Result<AbsolutePath, AppError> {
    let Some(value) = path.to_str() else {
        return Err(AppError::NonUtf8Path(path.to_path_buf()));
    };
    AbsolutePath::new(value.to_owned()).map_err(|_| AppError::NonUtf8Path(path.to_path_buf()))
}
