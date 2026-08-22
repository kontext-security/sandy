use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use sandy_core::{AbsolutePath, AccessMode, FileGrant, PathScope, TemplatePath};

use crate::error::AppError;

#[derive(Debug)]
pub(crate) struct ResolvedPaths {
    pub(crate) working_directory: AbsolutePath,
    pub(crate) home: Option<PathBuf>,
    pub(crate) protected: Vec<AbsolutePath>,
}

pub(crate) fn resolve_paths(
    protected_templates: &[TemplatePath],
) -> Result<ResolvedPaths, AppError> {
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

    let mut protected: Vec<AbsolutePath> = Vec::new();
    for template in protected_templates {
        let candidate = match template.as_str().strip_prefix("~/") {
            Some(rest) => home.as_deref().map(|home| home.join(rest)),
            None => Some(PathBuf::from(template.as_str())),
        };
        let Some(candidate) = candidate else {
            continue;
        };
        if let Ok(candidate) = absolute_if_utf8(&candidate)
            && !protected.contains(&candidate)
        {
            protected.push(candidate);
        }
    }

    for path in &protected {
        if working_directory.starts_with(path.as_path()) {
            return Err(AppError::ProtectedPath(working_directory));
        }
    }

    Ok(ResolvedPaths {
        working_directory: absolute_if_utf8(&working_directory)?,
        home,
        protected,
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

/// Resolves paths whose contents must remain readable but immutable inside the
/// sandbox. Both the lexical entry and its canonical target are protected so a
/// pre-existing symlink cannot redirect writes around the deny rule.
pub(crate) fn write_protections(
    paths: impl IntoIterator<Item = PathBuf>,
) -> Result<Vec<AbsolutePath>, AppError> {
    let mut protected = BTreeSet::new();
    for path in paths {
        if !path.is_absolute() || path == Path::new("/") {
            return Err(AppError::InvalidWriteProtection(path));
        }
        protected.insert(absolute_if_utf8(&path)?);
        protected.insert(absolute_if_utf8(&resolve_existing_ancestor(&path)?)?);
    }
    Ok(protected.into_iter().collect())
}

fn resolve_existing_ancestor(path: &Path) -> Result<PathBuf, AppError> {
    if fs::symlink_metadata(path).is_ok() {
        return fs::canonicalize(path)
            .map_err(|error| AppError::io("canonicalize write-protected path", error));
    }

    let mut cursor = path;
    let mut missing = Vec::<OsString>::new();
    loop {
        let Some(name) = cursor.file_name() else {
            return Err(AppError::MissingPath(path.to_path_buf()));
        };
        missing.push(name.to_os_string());
        cursor = cursor
            .parent()
            .ok_or_else(|| AppError::MissingPath(path.to_path_buf()))?;
        if fs::symlink_metadata(cursor).is_ok() {
            break;
        }
    }

    let mut resolved = fs::canonicalize(cursor)
        .map_err(|error| AppError::io("canonicalize write-protected path parent", error))?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

pub(crate) fn absolute_if_utf8(path: &Path) -> Result<AbsolutePath, AppError> {
    let Some(value) = path.to_str() else {
        return Err(AppError::NonUtf8Path(path.to_path_buf()));
    };
    AbsolutePath::new(value.to_owned()).map_err(|_| AppError::NonUtf8Path(path.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn protects_lexical_symlink_and_canonical_target() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let target = root.path().join("target.json");
        let link = root.path().join("settings.json");
        fs::write(&target, "{}")?;
        symlink(&target, &link)?;
        let canonical_target = fs::canonicalize(&target)?;

        let protected = write_protections([link.clone()])?;
        assert!(protected.iter().any(|path| path.as_path() == link));
        assert!(
            protected
                .iter()
                .any(|path| path.as_path() == canonical_target)
        );
        Ok(())
    }

    #[test]
    fn resolves_missing_leaf_through_canonical_parent() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let real = root.path().join("real");
        let alias = root.path().join("alias");
        fs::create_dir(&real)?;
        symlink(&real, &alias)?;
        let canonical_real = fs::canonicalize(&real)?;

        let lexical = alias.join("future/settings.json");
        let protected = write_protections([lexical.clone()])?;
        assert!(protected.iter().any(|path| path.as_path() == lexical));
        assert!(
            protected
                .iter()
                .any(|path| path.as_path() == canonical_real.join("future/settings.json"))
        );
        Ok(())
    }

    #[test]
    fn rejects_invalid_write_protection_paths_with_a_precise_error() {
        for path in [PathBuf::from("relative.json"), PathBuf::from("/")] {
            assert!(matches!(
                write_protections([path]),
                Err(AppError::InvalidWriteProtection(_))
            ));
        }
    }
}
