use std::{
    ffi::OsString,
    fs::{self, DirBuilder, File},
    io::Read as _,
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use sha2::{Digest as _, Sha256};
use tempfile::Builder;

use crate::{
    cli::SupportedAgent,
    error::AppError,
    integration::{IntegrationMode, ResolvedRuntimeControl, numbat},
};

use super::{SetupContext, SetupProvider, find_executable, resolve_executable};

const SERVICE: &str = "Numbat";
const VERSION: &str = "0.2.0";
const MAX_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 64 * 1024 * 1024;

struct ReleaseAsset {
    url: &'static str,
    sha256: &'static str,
}

pub(super) struct NumbatSetup;

impl SetupProvider for NumbatSetup {
    fn service(&self) -> &'static str {
        SERVICE
    }

    fn validate_agent(&self, _agent: SupportedAgent) -> Result<(), AppError> {
        Ok(())
    }

    fn resolve(
        &self,
        context: &SetupContext,
        mode: IntegrationMode,
    ) -> Result<ResolvedRuntimeControl, AppError> {
        numbat::resolve(&context.hook_sources, mode, &context.paths)
    }

    fn locate(&self, context: &SetupContext) -> Result<Option<PathBuf>, AppError> {
        if let Some(executable) = find_executable("numbat")? {
            return Ok(Some(executable));
        }
        let Some(home) = context.paths.home.as_deref() else {
            return Err(error("cannot resolve the home directory"));
        };
        resolve_executable(&managed_executable(home))
    }

    fn install(&self, context: &SetupContext) -> Result<PathBuf, AppError> {
        let home = context
            .paths
            .home
            .as_deref()
            .ok_or_else(|| error("cannot resolve the home directory"))?;
        install_release(home, release_asset()?)
    }

    fn configure(&self, executable: &Path, context: &SetupContext) -> Result<(), AppError> {
        let home = context
            .paths
            .home
            .as_deref()
            .ok_or_else(|| error("cannot resolve the home directory"))?;
        let state_directory = home.join(".numbat");
        ensure_private_directory(&state_directory)?;
        let output = state_directory.join("findings.ndjson");
        let status = Command::new(executable)
            .args([
                OsString::from("hook"),
                OsString::from("install"),
                OsString::from("--agent"),
                OsString::from(context.agent.profile_name()),
                OsString::from("--output=file"),
                OsString::from("--output-file"),
                output.into_os_string(),
            ])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|source| AppError::io("run Numbat hook installation", source))?;
        if !status.success() {
            return Err(error(format!("hook installation exited with {status}")));
        }
        Ok(())
    }
}

fn release_asset() -> Result<ReleaseAsset, AppError> {
    release_asset_for(std::env::consts::ARCH)
}

fn release_asset_for(architecture: &str) -> Result<ReleaseAsset, AppError> {
    match architecture {
        "aarch64" => Ok(ReleaseAsset {
            url: "https://github.com/perplexityai/numbat/releases/download/v0.2.0/numbat_0.2.0_darwin_arm64.tar.gz",
            sha256: "192512a128d3cb845f104ecddc885639ffb99d5fd9ac0249a217612b65a1ff32",
        }),
        "x86_64" => Ok(ReleaseAsset {
            url: "https://github.com/perplexityai/numbat/releases/download/v0.2.0/numbat_0.2.0_darwin_amd64.tar.gz",
            sha256: "541092d606f014e2d7ee2d6a4ebfbf018e3924a9167183d1486ed6b805675192",
        }),
        architecture => Err(error(format!(
            "the pinned Numbat release has no macOS asset for architecture {architecture:?}"
        ))),
    }
}

fn managed_executable(home: &Path) -> PathBuf {
    home.join("Library/Application Support/Sandy/integrations/numbat")
        .join(format!("v{VERSION}"))
        .join("numbat")
}

fn install_release(home: &Path, asset: ReleaseAsset) -> Result<PathBuf, AppError> {
    let destination = managed_executable(home);
    if destination.to_str().is_none() {
        return Err(error(
            "managed executable path is not valid UTF-8 and cannot be represented in a hook",
        ));
    }
    // This early check improves the error for a pre-existing path. Publication
    // still relies on `hard_link` below as the authoritative atomic,
    // no-overwrite operation, so a concurrent creator makes setup fail closed.
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            return Err(error(format!(
                "managed executable already exists but is not usable: {}; remove it outside Sandy and retry",
                destination.display()
            )));
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(AppError::io("inspect managed Numbat executable", source));
        }
    }
    let version_directory = destination
        .parent()
        .ok_or_else(|| error("managed executable has no parent directory"))?;
    ensure_managed_tree(home, version_directory)?;

    let temporary = Builder::new()
        .prefix("install-")
        .tempdir_in(version_directory)
        .map_err(|source| AppError::io("create private Numbat installation directory", source))?;
    let archive = temporary.path().join("release.tar.gz");
    download(&asset, &archive)?;
    verify_digest(&archive, asset.sha256)?;

    let unpacked = temporary.path().join("unpacked");
    install_archive(&archive, &unpacked, &destination)
}

fn install_archive(
    archive: &Path,
    unpacked: &Path,
    destination: &Path,
) -> Result<PathBuf, AppError> {
    let extracted = extract_release(archive, unpacked)?;
    validate_extracted_executable(&extracted)?;
    fs::set_permissions(&extracted, fs::Permissions::from_mode(0o755))
        .map_err(|source| AppError::io("set Numbat executable permissions", source))?;
    publish_executable(&extracted, destination)
}

fn extract_release(archive: &Path, unpacked: &Path) -> Result<PathBuf, AppError> {
    create_private_directory(unpacked)?;
    let status = Command::new("/usr/bin/tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(unpacked)
        .arg("--")
        .arg("numbat")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|source| AppError::io("extract pinned Numbat release", source))?;
    if !status.success() {
        return Err(error(format!("release extraction exited with {status}")));
    }
    Ok(unpacked.join("numbat"))
}

fn validate_extracted_executable(extracted: &Path) -> Result<(), AppError> {
    let metadata = fs::symlink_metadata(extracted)
        .map_err(|source| AppError::io("inspect extracted Numbat executable", source))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_BINARY_BYTES {
        return Err(error(
            "release member is not a non-empty bounded regular executable",
        ));
    }
    Ok(())
}

fn publish_executable(extracted: &Path, destination: &Path) -> Result<PathBuf, AppError> {
    // The temporary directory is on the destination filesystem. A hard link
    // gives us an atomic, no-overwrite publish operation; cleanup removes only
    // the temporary name, leaving the verified inode at its stable path.
    fs::hard_link(extracted, destination)
        .map_err(|source| AppError::io("publish verified Numbat executable", source))?;
    resolve_executable(destination)?
        .ok_or_else(|| error("the published Numbat executable did not pass executable validation"))
}

fn download(asset: &ReleaseAsset, destination: &Path) -> Result<(), AppError> {
    let status = Command::new("/usr/bin/curl")
        .arg("--disable")
        .args([
            "--fail",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--silent",
            "--show-error",
            "--max-filesize",
        ])
        .arg(MAX_ARCHIVE_BYTES.to_string())
        .arg("--output")
        .arg(destination)
        .arg(asset.url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|source| AppError::io("download pinned Numbat release", source))?;
    if !status.success() {
        return Err(error(format!("release download exited with {status}")));
    }
    Ok(())
}

fn verify_digest(path: &Path, expected: &str) -> Result<(), AppError> {
    let file = File::open(path)
        .map_err(|source| AppError::io("open downloaded Numbat release", source))?;
    let mut bounded = file.take(MAX_ARCHIVE_BYTES + 1);
    let mut hasher = Sha256::new();
    let copied = std::io::copy(&mut bounded, &mut hasher)
        .map_err(|source| AppError::io("hash downloaded Numbat release", source))?;
    if copied == 0 || copied > MAX_ARCHIVE_BYTES {
        return Err(error(
            "downloaded release size is outside the allowed bound",
        ));
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != expected {
        return Err(error(
            "downloaded release failed pinned SHA-256 verification",
        ));
    }
    Ok(())
}

fn ensure_managed_tree(home: &Path, destination: &Path) -> Result<(), AppError> {
    let relative = destination
        .strip_prefix(home)
        .map_err(|_| error("managed installation path escaped the home directory"))?;
    let mut current = home.to_path_buf();
    for (index, component) in relative.components().enumerate() {
        current.push(component);
        // Preserve the user's normal Library and Application Support modes.
        // Sandy owns every component below those two conventional roots.
        ensure_directory(&current, index >= 2)?;
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), AppError> {
    ensure_directory(path, true)
}

fn create_private_directory(path: &Path) -> Result<(), AppError> {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|source| AppError::io("create private integration directory", source))
}

fn ensure_directory(path: &Path, private: bool) -> Result<(), AppError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() {
                return Err(error(format!(
                    "integration directory is not a real directory: {}",
                    path.display()
                )));
            }
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(path)?;
        }
        Err(source) => {
            return Err(AppError::io("inspect integration directory", source));
        }
    }
    if private {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|source| AppError::io("secure integration directory", source))?;
    }
    Ok(())
}

fn error(message: impl Into<String>) -> AppError {
    AppError::integration_setup(SERVICE, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_archive(
        root: &Path,
        member_is_directory: bool,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let source = root.join("source");
        fs::create_dir(&source)?;
        let member = source.join("numbat");
        if member_is_directory {
            fs::create_dir(&member)?;
        } else {
            fs::write(&member, "#!/bin/sh\nexit 0\n")?;
        }
        let archive = root.join("release.tar.gz");
        let status = Command::new("/usr/bin/tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&source)
            .arg("--")
            .arg("numbat")
            .env("LC_ALL", "C")
            .status()?;
        if !status.success() {
            return Err(format!("test archive creation exited with {status}").into());
        }
        Ok(archive)
    }

    #[test]
    fn managed_path_is_versioned_below_sandy_state() {
        assert_eq!(
            managed_executable(Path::new("/Users/example")),
            Path::new(
                "/Users/example/Library/Application Support/Sandy/integrations/numbat/v0.2.0/numbat"
            )
        );
    }

    #[test]
    fn release_assets_cover_both_supported_macos_architectures() -> Result<(), AppError> {
        for (architecture, suffix) in [
            ("aarch64", "darwin_arm64.tar.gz"),
            ("x86_64", "darwin_amd64.tar.gz"),
        ] {
            let asset = release_asset_for(architecture)?;
            assert!(asset.url.starts_with("https://github.com/"));
            assert!(asset.url.ends_with(suffix));
            assert_eq!(asset.sha256.len(), 64);
            assert!(asset.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
        assert!(release_asset_for("unsupported").is_err());
        Ok(())
    }

    #[test]
    fn digest_verification_is_bounded_and_exact() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let archive = root.path().join("archive");
        fs::write(&archive, b"abc")?;
        verify_digest(
            &archive,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )?;
        assert!(verify_digest(&archive, &"0".repeat(64)).is_err());
        fs::write(&archive, [])?;
        assert!(verify_digest(&archive, &"0".repeat(64)).is_err());
        Ok(())
    }

    #[test]
    fn private_directory_setup_rejects_symlinks() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let target = root.path().join("target");
        fs::create_dir(&target)?;
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(&target, &alias)?;
        assert!(ensure_private_directory(&alias).is_err());
        Ok(())
    }

    #[test]
    fn managed_tree_rejects_an_intermediate_symlink() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let target = root.path().join("target");
        fs::create_dir(&home)?;
        fs::create_dir(&target)?;
        std::os::unix::fs::symlink(&target, home.join("Library"))?;

        let destination = managed_executable(&home);
        let parent = destination.parent().ok_or("managed path has no parent")?;
        assert!(ensure_managed_tree(&home, parent).is_err());
        assert!(!destination.exists());
        Ok(())
    }

    #[test]
    fn local_archive_is_extracted_and_published_without_network()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let archive = create_archive(root.path(), false)?;
        let destination_directory = root.path().join("destination");
        fs::create_dir(&destination_directory)?;
        let destination = destination_directory.join("numbat");

        let published = install_archive(&archive, &root.path().join("unpacked"), &destination)?;
        assert_eq!(published, fs::canonicalize(&destination)?);
        assert!(published.is_file());
        Ok(())
    }

    #[test]
    fn publication_never_overwrites_an_existing_executable()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let archive = create_archive(root.path(), false)?;
        let destination = root.path().join("numbat");
        fs::write(&destination, "operator-owned")?;

        assert!(install_archive(&archive, &root.path().join("unpacked"), &destination).is_err());
        assert_eq!(fs::read_to_string(destination)?, "operator-owned");
        Ok(())
    }

    #[test]
    fn nonregular_archive_member_fails_without_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let archive = create_archive(root.path(), true)?;
        let destination = root.path().join("destination");

        assert!(install_archive(&archive, &root.path().join("unpacked"), &destination).is_err());
        assert!(!destination.exists());
        Ok(())
    }

    #[test]
    fn extracted_executable_validation_rejects_empty_symlink_and_oversized_nodes()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let empty = root.path().join("empty");
        fs::write(&empty, [])?;
        let oversized = root.path().join("oversized");
        File::create(&oversized)?.set_len(MAX_BINARY_BYTES + 1)?;
        let target = root.path().join("target");
        fs::write(&target, "data")?;
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&target, &link)?;

        for path in [empty, link, oversized] {
            assert!(validate_extracted_executable(&path).is_err());
        }
        Ok(())
    }
}
