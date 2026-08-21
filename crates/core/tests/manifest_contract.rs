use std::ffi::OsStr;

use sandy_core::{
    AbsolutePath, CommandSpec, LaunchManifestV1, MANIFEST_SCHEMA_V1, NetworkPolicy, OsValue,
    PolicySpec, ValidatedLaunch,
};

fn manifest() -> Result<LaunchManifestV1, Box<dyn std::error::Error>> {
    Ok(LaunchManifestV1 {
        schema_version: MANIFEST_SCHEMA_V1,
        command: CommandSpec {
            program: OsValue::from_os_str(OsStr::new("/bin/echo")),
            arguments: Vec::new(),
        },
        working_directory: AbsolutePath::new("/tmp/project")?,
        environment: Vec::new(),
        policy: PolicySpec {
            network: NetworkPolicy::BlockAll,
            ..PolicySpec::default()
        },
    })
}

#[test]
fn validates_a_minimal_manifest() -> Result<(), Box<dyn std::error::Error>> {
    assert!(ValidatedLaunch::try_from(manifest()?).is_ok());
    Ok(())
}

#[test]
fn rejects_unknown_schema_versions() -> Result<(), Box<dyn std::error::Error>> {
    let mut value = manifest()?;
    value.schema_version = 99;
    assert!(ValidatedLaunch::try_from(value).is_err());
    Ok(())
}
