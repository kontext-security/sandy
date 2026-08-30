use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use sandy_core::{AbsolutePath, AccessMode, FileGrant, PathScope, TemplatePath, WriteProtection};

use crate::error::AppError;

#[derive(Debug)]
pub(crate) struct ResolvedUserPaths {
    pub(crate) home: Option<PathBuf>,
    pub(crate) protected: Vec<AbsolutePath>,
}

#[derive(Debug)]
pub(crate) struct ResolvedPaths {
    pub(crate) working_directory: AbsolutePath,
    pub(crate) user: ResolvedUserPaths,
}

pub(crate) fn resolve_user_paths(
    protected_templates: &[TemplatePath],
) -> Result<ResolvedUserPaths, AppError> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .and_then(|path| fs::canonicalize(path).ok());
    let mut protected = Vec::new();
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
    Ok(ResolvedUserPaths { home, protected })
}

pub(crate) fn resolve_paths(
    protected_templates: &[TemplatePath],
) -> Result<ResolvedPaths, AppError> {
    let working_directory = fs::canonicalize(
        env::current_dir().map_err(|error| AppError::io("read working directory", error))?,
    )
    .map_err(|error| AppError::io("canonicalize working directory", error))?;
    let user = resolve_user_paths(protected_templates)?;

    if working_directory == Path::new("/") || user.home.as_ref() == Some(&working_directory) {
        return Err(AppError::UnsafeWorkingDirectory);
    }

    for path in &user.protected {
        if working_directory.starts_with(path.as_path()) {
            return Err(AppError::ProtectedPath(working_directory));
        }
    }

    Ok(ResolvedPaths {
        working_directory: absolute_if_utf8(&working_directory)?,
        user,
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
    if path == Path::new("/") && (access != AccessMode::Read || scope != PathScope::Exact) {
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
) -> Result<Vec<WriteProtection>, AppError> {
    scoped_write_protections(paths, PathScope::Exact)
}

/// Resolves exact or recursive write protections through both lexical and
/// canonical path spellings.
pub(crate) fn scoped_write_protections(
    paths: impl IntoIterator<Item = PathBuf>,
    scope: PathScope,
) -> Result<Vec<WriteProtection>, AppError> {
    Ok(protection_path_spellings(paths)?
        .into_iter()
        .map(|path| WriteProtection { path, scope })
        .collect())
}

/// Resolves terminal protection paths through both their lexical spelling and
/// canonical target. A missing leaf remains protected through the canonical
/// spelling of its nearest existing ancestor rather than being omitted.
pub(crate) fn protection_path_spellings(
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
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return fs::canonicalize(path)
                .map_err(|error| AppError::io("canonicalize write-protected path", error));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(AppError::io("inspect write-protected path", error)),
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
        match fs::symlink_metadata(cursor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(AppError::io("inspect write-protected path ancestor", error));
            }
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
    use std::os::unix::{ffi::OsStringExt as _, fs::symlink};

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
        assert!(
            protected
                .iter()
                .any(|protection| protection.path.as_path() == link)
        );
        assert!(
            protected
                .iter()
                .any(|protection| protection.path.as_path() == canonical_target)
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
        assert!(
            protected
                .iter()
                .any(|protection| protection.path.as_path() == lexical)
        );
        assert!(protected.iter().any(|protection| {
            protection.path.as_path() == canonical_real.join("future/settings.json")
        }));
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

    #[test]
    fn non_missing_metadata_errors_are_not_treated_as_absent_paths() {
        let path = PathBuf::from(OsString::from_vec(b"/tmp/invalid-\0-path".to_vec()));
        assert!(matches!(
            resolve_existing_ancestor(&path),
            Err(AppError::Io { context, .. }) if context == "inspect write-protected path"
        ));
    }
}
