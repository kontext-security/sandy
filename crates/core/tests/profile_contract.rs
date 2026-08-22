use sandy_core::{
    AccessMode, GrantTemplate, PathScope, ProfileError, ProfileRegistry, TemplatePath,
};

const BASE: &str = r#"{
    "schema_version": 2,
    "name": "base",
    "abstract": true,
    "protected_paths": ["~/.ssh", "~/Library/Keychains"],
    "protected_write_paths": ["~/.base-config"]
}"#;

const AGENT: &str = r#"{
    "schema_version": 2,
    "name": "agent",
    "extends": ["base"],
    "detect": { "binary_names": ["agent"] },
    "grants": [
        { "path": "~/.agent", "access": "read_write", "scope": "subtree" },
        { "path": "~/.agent/config.toml", "access": "read_write", "scope": "exact" }
    ],
    "protected_write_paths": ["~/.agent/config.toml"],
    "hook_sources": [
        { "protocol": "codex_hooks", "path": "~/.agent/hooks.json" }
    ]
}"#;

fn registry() -> Result<ProfileRegistry, ProfileError> {
    ProfileRegistry::build(&[("base", BASE), ("agent", AGENT)])
}

#[test]
fn resolves_inheritance_base_first() -> Result<(), Box<dyn std::error::Error>> {
    let resolved = registry()?.resolve("agent")?;
    assert_eq!(resolved.name(), "agent");
    assert_eq!(resolved.protected_paths().len(), 2);
    assert_eq!(resolved.protected_write_paths().len(), 2);
    assert_eq!(resolved.hook_sources().len(), 1);
    assert_eq!(
        resolved.grants(),
        &[
            GrantTemplate {
                path: TemplatePath::new("~/.agent")?,
                access: AccessMode::ReadWrite,
                scope: PathScope::Subtree,
                if_exists: true,
            },
            GrantTemplate {
                path: TemplatePath::new("~/.agent/config.toml")?,
                access: AccessMode::ReadWrite,
                scope: PathScope::Exact,
                if_exists: true,
            },
        ]
    );
    Ok(())
}

#[test]
fn inheritance_only_profiles_are_not_selectable() -> Result<(), Box<dyn std::error::Error>> {
    let registry = registry()?;
    assert_eq!(registry.selectable_names(), vec!["agent".to_owned()]);
    assert!(matches!(
        registry.resolve_selectable("base"),
        Err(ProfileError::AbstractProfile(name)) if name == "base"
    ));
    assert_eq!(registry.resolve_selectable("agent")?.name(), "agent");
    Ok(())
}

#[test]
fn abstract_profiles_cannot_claim_detection_names() {
    let source = r#"{
        "schema_version": 2,
        "name": "base",
        "abstract": true,
        "detect": { "binary_names": ["base"] }
    }"#;
    assert!(matches!(
        ProfileRegistry::build(&[("base", source)]),
        Err(ProfileError::AbstractDetection(name)) if name == "base"
    ));
}

#[test]
fn if_exists_defaults_to_true_and_accepts_false() -> Result<(), Box<dyn std::error::Error>> {
    let document = r#"{
        "schema_version": 2,
        "name": "flags",
        "grants": [
            { "path": "/opt/a", "access": "read", "scope": "exact" },
            { "path": "/opt/b", "access": "read", "scope": "exact", "if_exists": false }
        ]
    }"#;
    let resolved = ProfileRegistry::build(&[("flags", document)])?.resolve("flags")?;
    assert!(resolved.grants()[0].if_exists);
    assert!(!resolved.grants()[1].if_exists);
    Ok(())
}

#[test]
fn detects_by_binary_basename_only() -> Result<(), Box<dyn std::error::Error>> {
    let registry = registry()?;
    assert_eq!(registry.detect("agent"), Some("agent"));
    assert_eq!(registry.detect("./agent"), None);
    assert_eq!(registry.detect("other"), None);
    Ok(())
}

#[test]
fn rejects_unknown_fields_and_bad_versions() {
    let unknown_field = r#"{
        "schema_version": 2,
        "name": "bad",
        "network": "allow"
    }"#;
    assert!(matches!(
        ProfileRegistry::build(&[("bad", unknown_field)]),
        Err(ProfileError::Parse(_, _))
    ));
    let bad_version = format!(
        r#"{{ "schema_version": {}, "name": "bad" }}"#,
        sandy_core::PROFILE_SCHEMA_V2 + 1
    );
    assert!(matches!(
        ProfileRegistry::build(&[("bad", bad_version.as_str())]),
        Err(ProfileError::UnsupportedSchema { version: 3, .. })
    ));
}

#[test]
fn rejects_parent_traversal_and_relative_templates() {
    for candidate in ["~/.x/../secret", "../etc/passwd", "~user/x"] {
        assert!(
            matches!(
                TemplatePath::new(candidate),
                Err(ProfileError::InvalidTemplate(_))
            ),
            "{candidate} should be rejected"
        );
    }
}

fn err_of<T>(result: Result<T, ProfileError>) -> Result<ProfileError, Box<dyn std::error::Error>> {
    match result {
        Ok(_) => Err("expected the operation to fail".into()),
        Err(error) => Ok(error),
    }
}

#[test]
fn rejects_cycles_and_depth_exceeded() -> Result<(), Box<dyn std::error::Error>> {
    let a_source = r#"{ "schema_version": 2, "name": "a", "extends": ["b"] }"#;
    let b_source = r#"{ "schema_version": 2, "name": "b", "extends": ["a"] }"#;
    let error = err_of(
        ProfileRegistry::build(&[("a", a_source), ("b", b_source)])
            .and_then(|registry| registry.resolve("a")),
    )?;
    assert!(matches!(error, ProfileError::Cycle(_)));

    const CHAIN_DEPTH: usize = 12;
    let mut sources: Vec<(String, String)> = Vec::with_capacity(CHAIN_DEPTH);
    sources.push((
        "p00".to_owned(),
        r#"{ "schema_version": 2, "name": "p00" }"#.to_owned(),
    ));
    for index in 1..CHAIN_DEPTH {
        sources.push((
            format!("p{index:02}"),
            format!(
                r#"{{ "schema_version": 2, "name": "p{index:02}", "extends": ["p{:02}"] }}"#,
                index - 1
            ),
        ));
    }
    let borrowed: Vec<(&str, &str)> = sources
        .iter()
        .map(|(name, body)| (name.as_str(), body.as_str()))
        .collect();
    let error =
        err_of(ProfileRegistry::build(&borrowed).and_then(|registry| registry.resolve("p11")))?;
    assert!(matches!(error, ProfileError::DepthExceeded(_)));
    Ok(())
}

#[test]
fn duplicate_profile_names_fail_closed() {
    let first = r#"{ "schema_version": 2, "name": "same" }"#;
    let second = r#"{ "schema_version": 2, "name": "same" }"#;
    assert!(matches!(
        ProfileRegistry::build(&[("same", first), ("same", second)]),
        Err(ProfileError::DuplicateProfile(_))
    ));
}

#[test]
fn conflicting_detection_claims_fail_closed() {
    let first =
        r#"{ "schema_version": 2, "name": "first", "detect": { "binary_names": ["dup"] } }"#;
    let second =
        r#"{ "schema_version": 2, "name": "second", "detect": { "binary_names": ["dup"] } }"#;
    assert!(matches!(
        ProfileRegistry::build(&[("first", first), ("second", second)]),
        Err(ProfileError::DuplicateDetection { .. })
    ));
}

#[test]
fn unknown_base_or_target_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let orphan = r#"{ "schema_version": 2, "name": "orphan", "extends": ["missing"] }"#;
    let registry = ProfileRegistry::build(&[("orphan", orphan)])?;
    assert!(matches!(
        registry.resolve("orphan"),
        Err(ProfileError::UnknownProfile(_))
    ));
    assert!(matches!(
        registry.resolve("ghost"),
        Err(ProfileError::UnknownProfile(_))
    ));
    Ok(())
}
