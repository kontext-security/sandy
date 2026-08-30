use sandy::{PolicyDocumentError, SandboxPolicy};

#[test]
fn parses_a_policy_through_the_supported_facade() -> Result<(), PolicyDocumentError> {
    let policy = SandboxPolicy::from_json(
        br#"{
            "schema_version": 1,
            "network": "block_all",
            "grants": [
                {"path": "workspace", "access": "read_write", "scope": "subtree"}
            ],
            "executable_grants": [
                {"path": "workspace/tool", "scope": "exact"}
            ]
        }"#,
    )?;

    drop(policy);
    Ok(())
}
