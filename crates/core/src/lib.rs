//! Platform-neutral contracts shared by Sandy's resolver and enforcement backend.
//!
//! The crate deliberately contains no ambient discovery and no native sandbox code. The CLI
//! resolves profiles, paths, and integrations into a [`LaunchManifestV2`], then treats that
//! manifest as untrusted input when it crosses the bootstrap wire boundary. Only
//! [`ValidatedLaunch`] and its [`ValidatedPolicy`] may proceed to policy compilation.
//!
//! The main data flow is:
//!
//! ```text
//! embedded profile documents -> ResolvedProfile
//! CLI filesystem resolution  -> LaunchManifestV2
//! bounded wire decode        -> ValidatedLaunch -> ValidatedPolicy
//! ```
//!
//! Keeping those states as different types makes it difficult to accidentally compile or apply
//! a policy that has not passed the complete launch validation step.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod capability;
mod manifest;
mod path;
mod profile;
mod validation;
mod wire;

pub use capability::{
    AccessMode, FileGrant, NetworkPolicy, PathScope, PolicySpec, UnixSocketGrant,
    UnixSocketOperation, WriteProtection,
};
pub use manifest::{
    CommandSpec, EnvironmentEntry, LaunchManifestV2, MANIFEST_SCHEMA_V2, OsValue, OsValueError,
};
pub use path::{AbsolutePath, PathValidationError};
pub use profile::{
    GENERIC_PROFILE_NAME, GrantTemplate, HookProtocol, HookSourceLocation, HookSourceScope,
    HookSourceTemplate, PROFILE_SCHEMA_V4, ProfileDocumentV4, ProfileError, ProfileRegistry,
    ResolvedProfile, TemplatePath,
};
pub use validation::{ValidatedLaunch, ValidatedPolicy, ValidationError};
pub use wire::{MAX_WIRE_BYTES, WireError, decode_launch, encode_launch};
