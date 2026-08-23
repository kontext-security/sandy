use std::ffi::OsStr;

use sandy_core::{
    AbsolutePath, CommandSpec, LaunchManifestV1, MANIFEST_SCHEMA_V1, NetworkPolicy, OsValue,
    PolicySpec, UnixSocketGrant, UnixSocketOperation, ValidatedLaunch, ValidationError, WireError,
    decode_launch, encode_launch,
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

#[test]
fn rejects_root_and_duplicate_protected_paths() -> Result<(), Box<dyn std::error::Error>> {
    let mut root = manifest()?;
    root.policy
        .protected_write_paths
        .push(AbsolutePath::new("/")?);
    assert!(ValidatedLaunch::try_from(root).is_err());

    let mut duplicate = manifest()?;
    let path = AbsolutePath::new("/tmp/project/settings.json")?;
    duplicate.policy.protected_write_paths = vec![path.clone(), path];
    assert!(ValidatedLaunch::try_from(duplicate).is_err());
    Ok(())
}

#[test]
fn validates_exact_socket_grants_and_rejects_duplicates_and_root()
-> Result<(), Box<dyn std::error::Error>> {
    let socket = UnixSocketGrant {
        path: AbsolutePath::new("/private/tmp/control.sock")?,
        operation: UnixSocketOperation::Connect,
    };
    let mut valid = manifest()?;
    valid.policy.unix_sockets.push(socket.clone());
    let decoded = decode_launch(&encode_launch(&valid)?)?;
    assert_eq!(
        decoded.manifest().policy.unix_sockets.as_slice(),
        std::slice::from_ref(&socket)
    );
    assert!(ValidatedLaunch::try_from(valid).is_ok());

    let mut duplicate = manifest()?;
    duplicate.policy.unix_sockets = vec![socket.clone(), socket];
    assert!(ValidatedLaunch::try_from(duplicate).is_err());

    let mut root = manifest()?;
    root.policy.unix_sockets.push(UnixSocketGrant {
        path: AbsolutePath::new("/")?,
        operation: UnixSocketOperation::Connect,
    });
    assert!(ValidatedLaunch::try_from(root).is_err());
    Ok(())
}

#[test]
fn manifest_v1_without_socket_grants_remains_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let encoded = br#"{
        "schema_version": 1,
        "command": { "program": [47, 98, 105, 110, 47, 101, 99, 104, 111], "arguments": [] },
        "working_directory": "/tmp/project",
        "environment": [],
        "policy": { "files": [], "protected_paths": [], "protected_write_paths": [], "network": "block_all" }
    }"#;
    let launch = decode_launch(encoded)?;
    assert!(launch.manifest().policy.unix_sockets.is_empty());
    Ok(())
}

#[test]
fn rejects_malformed_socket_grants_from_the_wire() {
    let unknown_operation = br#"{
        "schema_version": 1,
        "command": { "program": [47, 98, 105, 110, 47, 101, 99, 104, 111], "arguments": [] },
        "working_directory": "/tmp/project",
        "environment": [],
        "policy": {
            "files": [],
            "protected_paths": [],
            "protected_write_paths": [],
            "unix_sockets": [{ "path": "/private/tmp/control.sock", "operation": "bind" }],
            "network": "block_all"
        }
    }"#;
    assert!(matches!(
        decode_launch(unknown_operation),
        Err(WireError::Decode(_))
    ));

    let relative_path = br#"{
        "schema_version": 1,
        "command": { "program": [47, 98, 105, 110, 47, 101, 99, 104, 111], "arguments": [] },
        "working_directory": "/tmp/project",
        "environment": [],
        "policy": {
            "files": [],
            "protected_paths": [],
            "protected_write_paths": [],
            "unix_sockets": [{ "path": "relative.sock", "operation": "connect" }],
            "network": "block_all"
        }
    }"#;
    assert!(matches!(
        decode_launch(relative_path),
        Err(WireError::Decode(_))
    ));
}

#[test]
fn bounds_unix_socket_grants() -> Result<(), Box<dyn std::error::Error>> {
    let mut oversized = manifest()?;
    oversized.policy.unix_sockets = (0..129)
        .map(|index| {
            Ok(UnixSocketGrant {
                path: AbsolutePath::new(format!("/private/tmp/control-{index}.sock"))?,
                operation: UnixSocketOperation::Connect,
            })
        })
        .collect::<Result<Vec<_>, sandy_core::PathValidationError>>()?;

    assert!(matches!(
        ValidatedLaunch::try_from(oversized),
        Err(ValidationError::TooManyUnixSocketGrants)
    ));
    Ok(())
}
