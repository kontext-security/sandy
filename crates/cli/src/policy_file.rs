//! Explicit loading for complete caller-controlled policy documents.

use std::{
    fs,
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
};

use sandy_core::{AbsolutePath, MAX_POLICY_DOCUMENT_SOURCE_BYTES, SandboxPolicy, policy_network};

use crate::{
    error::AppError,
    resolve::{CliPolicyIntent, absolute_if_utf8},
};

/// One parsed policy and the safe path spellings that must remain inaccessible
/// to the launched process.
pub(crate) struct LoadedPolicy {
    policy: SandboxPolicy,
    source_paths: Vec<AbsolutePath>,
}

impl LoadedPolicy {
    #[must_use]
    pub(crate) fn network(&self) -> sandy_core::NetworkPolicy {
        policy_network(&self.policy)
    }

    pub(crate) fn into_parts(self) -> (SandboxPolicy, Vec<AbsolutePath>) {
        (self.policy, self.source_paths)
    }
}

pub(crate) fn protect_source(
    mut intent: CliPolicyIntent,
    source_paths: &[AbsolutePath],
) -> CliPolicyIntent {
    for path in source_paths {
        intent = intent.deny_resolved_subtree(path.clone());
    }
    intent
}

/// Loads exactly one bounded regular file and parses it through the shared
/// policy document contract. No directory search, fallback, or interpolation
/// is performed.
pub(crate) fn load(path: &Path, working_directory: &Path) -> Result<LoadedPolicy, AppError> {
    let lexical_path = absolute_lexical_path(path, working_directory);
    let lexical = absolute_if_utf8(&lexical_path).map_err(|_| {
        AppError::PolicyFile(
            "source path must be absolute UTF-8 without parent traversal".to_owned(),
        )
    })?;
    let canonical_path = fs::canonicalize(&lexical_path)
        .map_err(|error| AppError::io("resolve sandbox policy file", error))?;

    inspect_regular_file(&canonical_path)?;
    let file = File::open(&canonical_path)
        .map_err(|error| AppError::io("open sandbox policy file", error))?;
    let metadata = file
        .metadata()
        .map_err(|error| AppError::io("inspect opened sandbox policy file", error))?;
    if !metadata.is_file() {
        return Err(not_regular());
    }
    if metadata.len() > MAX_POLICY_DOCUMENT_SOURCE_BYTES as u64 {
        return Err(AppError::from(sandy_core::PolicyDocumentError::TooLarge));
    }

    let mut source = Vec::new();
    file.take((MAX_POLICY_DOCUMENT_SOURCE_BYTES as u64) + 1)
        .read_to_end(&mut source)
        .map_err(|error| AppError::io("read sandbox policy file", error))?;
    let policy = SandboxPolicy::from_json(&source)?;
    let canonical = absolute_if_utf8(&canonical_path).map_err(|_| {
        AppError::PolicyFile("canonical source path must be absolute UTF-8".to_owned())
    })?;
    let mut source_paths = vec![lexical];
    if canonical != source_paths[0] {
        source_paths.push(canonical);
    }

    Ok(LoadedPolicy {
        policy,
        source_paths,
    })
}

fn absolute_lexical_path(path: &Path, working_directory: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    working_directory.join(path)
}

fn inspect_regular_file(path: &Path) -> Result<(), AppError> {
    let metadata =
        fs::metadata(path).map_err(|error| AppError::io("inspect sandbox policy file", error))?;
    if !metadata.is_file() {
        return Err(not_regular());
    }
    if metadata.len() > MAX_POLICY_DOCUMENT_SOURCE_BYTES as u64 {
        return Err(AppError::from(sandy_core::PolicyDocumentError::TooLarge));
    }
    Ok(())
}

fn not_regular() -> AppError {
    AppError::PolicyFile("source must be a regular file".to_owned())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use sandy_core::NetworkPolicy;

    use super::*;

    #[test]
    fn loads_a_complete_document_and_protects_both_source_spellings()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let real = root.path().join("policy.json");
        let alias = root.path().join("alias.json");
        fs::write(&real, r#"{"schema_version":1,"network":"block_all"}"#)?;
        std::os::unix::fs::symlink(&real, &alias)?;

        let loaded = load(&alias, root.path())?;
        let canonical = fs::canonicalize(real)?;
        assert_eq!(loaded.network(), NetworkPolicy::BlockAll);
        assert_eq!(loaded.source_paths.len(), 2);
        assert!(
            loaded
                .source_paths
                .iter()
                .any(|path| path.as_path() == alias)
        );
        assert!(
            loaded
                .source_paths
                .iter()
                .any(|path| path.as_path() == canonical)
        );
        Ok(())
    }

    #[test]
    fn rejects_non_regular_and_oversized_sources() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        assert!(matches!(
            load(root.path(), root.path()),
            Err(AppError::PolicyFile(_))
        ));

        let oversized = root.path().join("oversized.json");
        fs::write(&oversized, vec![b' '; MAX_POLICY_DOCUMENT_SOURCE_BYTES + 1])?;
        assert!(matches!(
            load(&oversized, root.path()),
            Err(AppError::PolicyDocument(
                sandy_core::PolicyDocumentError::TooLarge
            ))
        ));
        Ok(())
    }
}
