//! Platform-neutral contracts shared by Sandy's resolver and enforcement backend.
//!
//! The crate deliberately contains no ambient discovery and no native sandbox code. The CLI
//! resolves paths and integrations into a [`LaunchManifestV2`], then treats that
//! manifest as untrusted input when it crosses the bootstrap wire boundary. Only
//! [`ValidatedLaunch`] or a directly validated [`ValidatedPolicy`] may proceed
//! to policy compilation.
//!
//! The main data flow is:
//!
//! ```text
//! CLI policy resolution      -> LaunchManifestV2
//! bounded wire decode        -> ValidatedLaunch -> ValidatedPolicy
//! SandboxPolicy resolution   -> ResolvedPolicyDraft -> ValidatedPolicy
//! ```
//!
//! Keeping those states as different types makes it difficult to accidentally compile or apply
//! a policy that has not passed the complete launch validation step.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod capability;
mod manifest;
mod path;
mod policy_draft;
mod sandbox_policy;
mod validation;
mod wire;

pub use capability::{
    AccessMode, ExecutableGrant, FileGrant, FileMetadataPolicy, LocalHostTcpGrant,
    LocalHostTcpOperation, NetworkPolicy, PathScope, PolicySpec, RuntimeCompatibility, TcpPort,
    UnixSocketGrant, UnixSocketOperation, WriteProtection,
};
pub use manifest::{
    CommandSpec, EnvironmentEntry, LaunchManifestV2, MANIFEST_SCHEMA_V2, OsValue, OsValueError,
};
pub use path::{AbsolutePath, PathValidationError};
#[doc(hidden)]
pub use policy_draft::{FileGrantConflict, ResolvedPolicyDraft};
pub use sandbox_policy::{
    MAX_POLICY_DOCUMENT_SOURCE_BYTES, PolicyDocumentError, PolicyIntentError, SandboxPolicy,
    SandboxPolicyParts, UnresolvedExecutable, UnresolvedGrant, allow_file_metadata,
    allow_foreground_cli_compatibility, into_policy_parts, policy_allows_subprocesses,
    policy_network,
};
pub use validation::{ValidatedLaunch, ValidatedPolicy, ValidationError};
pub use wire::{MAX_WIRE_BYTES, WireError, decode_launch, encode_launch};
