#![forbid(unsafe_code)]

mod capability;
mod command;
mod manifest;
mod os_value;
mod path;
mod profile;
mod validation;
mod wire;

pub use capability::{AccessMode, FileGrant, NetworkPolicy, PathScope, PolicySpec};
pub use command::{CommandSpec, EnvironmentEntry};
pub use manifest::{LaunchManifestV1, MANIFEST_SCHEMA_V1};
pub use os_value::{OsValue, OsValueError};
pub use path::{AbsolutePath, PathValidationError};
pub use profile::{
    GENERIC_PROFILE_NAME, GrantTemplate, PROFILE_SCHEMA_V1, ProfileDocumentV1, ProfileError,
    ProfileRegistry, ResolvedProfile, TemplatePath,
};
pub use validation::{ValidatedLaunch, ValidatedPolicy, ValidationError};
pub use wire::{MAX_WIRE_BYTES, WireError, decode_launch, encode_launch};
