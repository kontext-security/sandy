use sandy_core::{
    AccessMode, ExecutableTemplate, GrantTemplate, PathScope, ProfileError, ProfileRegistry,
    TemplatePath, USER_PROFILE_SCHEMA_V1, UserProfileDocumentV1, UserProfileError,
};

const BASE: &str = r#"{
    "schema_version": 4,
    "name": "base",
    "abstract": true,
    "protected_paths": ["~/.ssh", "~/Library/Keychains"],
    "protected_write_paths": ["~/.base-config"]
}"#;

const AGENT: &str = r#"{
    "schema_version": 4,
    "name": "agent",
    "extends": ["base"],
    "detect": { "binary_names": ["agent"] },
    "grants": [
        { "path": "~/.agent", "access": "read_write", "scope": "subtree" },
        { "path": "~/.agent/config.toml", "access": "read_write", "scope": "exact" }
    ],
    "executable_grants": [
        { "path": "~/.agent/bin", "scope": "subtree" }
    ],
    "protected_write_paths": ["~/.agent/config.toml"],
    "hook_sources": [
        { "protocol": "codex_hooks", "location": "fixed", "path": "~/.agent/hooks.json" }
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
    assert_eq!(
        resolved.executable_grants(),
        &[ExecutableTemplate {
            path: TemplatePath::new("~/.agent/bin")?,
            scope: PathScope::Subtree,
            if_exists: true,
        }]
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
        "schema_version": 4,
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
        "schema_version": 4,
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
        "schema_version": 4,
        "name": "bad",
        "network": "allow"
    }"#;
    assert!(matches!(
        ProfileRegistry::build(&[("bad", unknown_field)]),
        Err(ProfileError::Parse(_, _))
    ));
    let bad_version = format!(
        r#"{{ "schema_version": {}, "name": "bad" }}"#,
        sandy_core::PROFILE_SCHEMA_V4 + 1
    );
    assert!(matches!(
        ProfileRegistry::build(&[("bad", bad_version.as_str())]),
        Err(ProfileError::UnsupportedSchema { version, .. })
            if version == sandy_core::PROFILE_SCHEMA_V4 + 1
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

#[test]
fn rejects_incompatible_hook_protocol_locations_and_scopes() {
    let cases = [
        r#"{
            "schema_version": 4,
            "name": "bad",
            "hook_sources": [{
                "protocol": "codex_hooks",
                "location": "claude_user_settings"
            }]
        }"#,
        r#"{
            "schema_version": 4,
            "name": "bad",
            "hook_sources": [{
                "protocol": "codex_hooks",
                "location": "fixed",
                "path": "/etc/codex/hooks",
                "scope": "directory"
            }]
        }"#,
        r#"{
            "schema_version": 4,
            "name": "bad",
            "hook_sources": [{
                "protocol": "open_code_plugin",
                "location": "fixed",
                "path": "/etc/opencode/plugin.ts"
            }]
        }"#,
    ];
    for source in cases {
        assert!(matches!(
            ProfileRegistry::build(&[("bad", source)]),
            Err(ProfileError::InvalidHookSource)
        ));
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
    let a_source = r#"{ "schema_version": 4, "name": "a", "extends": ["b"] }"#;
    let b_source = r#"{ "schema_version": 4, "name": "b", "extends": ["a"] }"#;
    let error = err_of(
        ProfileRegistry::build(&[("a", a_source), ("b", b_source)])
            .and_then(|registry| registry.resolve("a")),
    )?;
    assert!(matches!(error, ProfileError::Cycle(_)));

    const CHAIN_DEPTH: usize = 12;
    let mut sources: Vec<(String, String)> = Vec::with_capacity(CHAIN_DEPTH);
    sources.push((
        "p00".to_owned(),
        r#"{ "schema_version": 4, "name": "p00" }"#.to_owned(),
    ));
    for index in 1..CHAIN_DEPTH {
        sources.push((
            format!("p{index:02}"),
            format!(
                r#"{{ "schema_version": 4, "name": "p{index:02}", "extends": ["p{:02}"] }}"#,
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
    let first = r#"{ "schema_version": 4, "name": "same" }"#;
    let second = r#"{ "schema_version": 4, "name": "same" }"#;
    assert!(matches!(
        ProfileRegistry::build(&[("same", first), ("same", second)]),
        Err(ProfileError::DuplicateProfile(_))
    ));
}

#[test]
fn conflicting_detection_claims_fail_closed() {
    let first =
        r#"{ "schema_version": 4, "name": "first", "detect": { "binary_names": ["dup"] } }"#;
    let second =
        r#"{ "schema_version": 4, "name": "second", "detect": { "binary_names": ["dup"] } }"#;
    assert!(matches!(
        ProfileRegistry::build(&[("first", first), ("second", second)]),
        Err(ProfileError::DuplicateDetection { .. })
    ));
}

#[test]
fn unknown_base_or_target_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let orphan = r#"{ "schema_version": 4, "name": "orphan", "extends": ["missing"] }"#;
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

#[test]
fn user_profile_adds_policy_without_removing_base_behavior()
-> Result<(), Box<dyn std::error::Error>> {
    let source = r#"{
        "schema_version": 1,
        "name": "session",
        "extends": "agent",
        "grants": [{
            "path": "/workspace/cache",
            "access": "read",
            "scope": "subtree"
        }],
        "executable_grants": [{
            "path": "/workspace/bin",
            "scope": "subtree"
        }],
        "deny_subtrees": ["/workspace/private"],
        "deny_write_exact": ["/workspace/config.json"]
    }"#;
    let resolved = registry()?.resolve_user_profile(UserProfileDocumentV1::parse(source)?)?;
    assert_eq!(resolved.base_name(), "agent");
    assert_eq!(
        resolved
            .required_executable_grants()
            .map(|(position, grant)| (position, grant.path.as_str()))
            .collect::<Vec<_>>(),
        vec![(1, "/workspace/bin")]
    );
    let profile = resolved.profile();

    assert_eq!(profile.name(), "session");
    assert_eq!(profile.binary_names(), ["agent"]);
    assert_eq!(profile.hook_sources().len(), 1);
    assert!(profile.grants().iter().any(|grant| {
        grant.path.as_str() == "/workspace/cache"
            && grant.access == AccessMode::Read
            && grant.scope == PathScope::Subtree
            && !grant.if_exists
    }));
    assert!(profile.executable_grants().iter().any(|grant| {
        grant.path.as_str() == "/workspace/bin"
            && grant.scope == PathScope::Subtree
            && !grant.if_exists
    }));
    assert!(
        !profile
            .grants()
            .iter()
            .any(|grant| grant.path.as_str() == "/workspace/bin")
    );
    assert!(
        !profile
            .executable_grants()
            .iter()
            .any(|grant| grant.path.as_str() == "/workspace/cache")
    );
    assert!(
        profile
            .protected_paths()
            .iter()
            .any(|path| path.as_str() == "~/.ssh")
    );
    assert!(
        profile
            .protected_paths()
            .iter()
            .any(|path| path.as_str() == "/workspace/private")
    );
    Ok(())
}

#[test]
fn user_profile_home_requirement_tracks_only_required_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let source = r#"{
        "schema_version": 1,
        "name": "session",
        "extends": "agent"
    }"#;
    let resolved = registry()?.resolve_user_profile(UserProfileDocumentV1::parse(source)?)?;

    assert!(!resolved.requires_home());

    let required = r#"{
        "schema_version": 1,
        "name": "required-session",
        "extends": "agent",
        "executable_grants": [{ "path": "~/.required/bin", "scope": "subtree" }]
    }"#;
    let resolved = registry()?.resolve_user_profile(UserProfileDocumentV1::parse(required)?)?;
    assert!(resolved.requires_home());
    Ok(())
}

#[test]
fn user_profile_rejects_fields_outside_its_narrow_grammar() {
    for field in [
        r#""abstract": false"#,
        r#""detect": { "binary_names": ["session"] }"#,
        r#""hook_sources": []"#,
        r#""network": "allow_all""#,
        r#""protected_paths": []"#,
        r#""protected_write_paths": []"#,
    ] {
        let source = format!(
            r#"{{
                "schema_version": 1,
                "name": "session",
                "extends": "agent",
                {field}
            }}"#
        );
        assert!(matches!(
            UserProfileDocumentV1::parse(&source),
            Err(UserProfileError::Parse { .. })
        ));
    }

    let optional_grant = r#"{
        "schema_version": 1,
        "name": "session",
        "extends": "agent",
        "grants": [{
            "path": "/optional",
            "access": "read",
            "scope": "exact",
            "if_exists": true
        }]
    }"#;
    assert!(matches!(
        UserProfileDocumentV1::parse(optional_grant),
        Err(UserProfileError::Parse { .. })
    ));

    let executable_with_access = r#"{
        "schema_version": 1,
        "name": "session",
        "extends": "agent",
        "executable_grants": [{
            "path": "/workspace/bin",
            "scope": "subtree",
            "access": "read"
        }]
    }"#;
    assert!(matches!(
        UserProfileDocumentV1::parse(executable_with_access),
        Err(UserProfileError::Parse { .. })
    ));

    for grant in [
        r#"{"path":"/workspace","access":"write","scope":"exact"}"#,
        r#"{"path":"/workspace","access":"read","scope":"recursive"}"#,
    ] {
        let source = format!(
            r#"{{
                "schema_version": 1,
                "name": "session",
                "extends": "agent",
                "grants": [{grant}]
            }}"#
        );
        assert!(matches!(
            UserProfileDocumentV1::parse(&source),
            Err(UserProfileError::Parse { .. })
        ));
    }
}

#[test]
fn user_profile_requires_version_one_and_one_named_base() {
    let bad_version = format!(
        r#"{{ "schema_version": {}, "name": "session", "extends": "agent", "future_field": true }}"#,
        USER_PROFILE_SCHEMA_V1 + 1
    );
    assert!(matches!(
        UserProfileDocumentV1::parse(&bad_version),
        Err(UserProfileError::UnsupportedSchema(version)) if version == USER_PROFILE_SCHEMA_V1 + 1
    ));
    for source in [
        r#"{ "schema_version": 1, "name": "session" }"#,
        r#"{ "schema_version": 1, "name": "session", "extends": ["agent"] }"#,
    ] {
        assert!(matches!(
            UserProfileDocumentV1::parse(source),
            Err(UserProfileError::Parse { .. })
        ));
    }
}

#[test]
fn user_profile_resolution_rechecks_the_schema_version() -> Result<(), Box<dyn std::error::Error>> {
    let unsupported_version = USER_PROFILE_SCHEMA_V1 + 1;
    let source = format!(
        r#"{{ "schema_version": {unsupported_version}, "name": "session", "extends": "agent" }}"#
    );
    let document: UserProfileDocumentV1 = serde_json::from_str(&source)?;

    assert!(matches!(
        registry()?.resolve_user_profile(document),
        Err(UserProfileError::UnsupportedSchema(version)) if version == unsupported_version
    ));
    Ok(())
}

#[test]
fn user_profile_rejects_unknown_abstract_and_colliding_names()
-> Result<(), Box<dyn std::error::Error>> {
    let registry = registry()?;
    for (name, base, expected) in [
        ("session", "missing", "unknown"),
        ("session", "base", "abstract"),
        ("agent", "agent", "collision"),
    ] {
        let source = format!(r#"{{ "schema_version": 1, "name": "{name}", "extends": "{base}" }}"#);
        let error = registry
            .resolve_user_profile(UserProfileDocumentV1::parse(&source)?)
            .err()
            .ok_or("user profile should be rejected")?;
        assert!(matches!(
            (expected, error),
            ("unknown", UserProfileError::UnknownBase(_))
                | ("abstract", UserProfileError::AbstractBase(_))
                | ("collision", UserProfileError::NameCollision(_))
        ));
    }
    Ok(())
}

#[test]
fn user_profile_bounds_each_additive_section_before_resolution()
-> Result<(), Box<dyn std::error::Error>> {
    let grants = (0..257)
        .map(|index| {
            serde_json::json!({
                "path": format!("/workspace/grant-{index}"),
                "access": "read",
                "scope": "exact",
            })
        })
        .collect::<Vec<_>>();
    let source = serde_json::json!({
        "schema_version": 1,
        "name": "session",
        "extends": "agent",
        "grants": grants,
    })
    .to_string();
    assert!(matches!(
        UserProfileDocumentV1::parse(&source),
        Err(UserProfileError::TooManyGrants)
    ));

    let executable_grants = (0..257)
        .map(|index| {
            serde_json::json!({
                "path": format!("/workspace/bin-{index}"),
                "scope": "exact",
            })
        })
        .collect::<Vec<_>>();
    let source = serde_json::json!({
        "schema_version": 1,
        "name": "session",
        "extends": "agent",
        "executable_grants": executable_grants,
    })
    .to_string();
    assert!(matches!(
        UserProfileDocumentV1::parse(&source),
        Err(UserProfileError::TooManyExecutables)
    ));

    let protected = (0..509)
        .map(|index| format!("/workspace/protected-{index}"))
        .collect::<Vec<_>>();
    for field in ["deny_subtrees", "deny_write_exact"] {
        let mut document = serde_json::json!({
            "schema_version": 1,
            "name": "session",
            "extends": "agent",
        });
        document[field] = serde_json::json!(protected);
        assert!(matches!(
            UserProfileDocumentV1::parse(&document.to_string()),
            Err(UserProfileError::TooManyPaths)
        ));
    }
    Ok(())
}

#[test]
fn user_profile_rechecks_bounds_after_composing_with_the_base()
-> Result<(), Box<dyn std::error::Error>> {
    let base_grants = (0..200)
        .map(|index| {
            serde_json::json!({
                "path": format!("/base/grant-{index}"),
                "access": "read",
                "scope": "exact",
            })
        })
        .collect::<Vec<_>>();
    let base_source = serde_json::json!({
        "schema_version": 4,
        "name": "large-base",
        "grants": base_grants,
    })
    .to_string();
    let registry = ProfileRegistry::build(&[("large-base", &base_source)])?;

    let user_grants = (0..100)
        .map(|index| {
            serde_json::json!({
                "path": format!("/user/grant-{index}"),
                "access": "read",
                "scope": "exact",
            })
        })
        .collect::<Vec<_>>();
    let user_source = serde_json::json!({
        "schema_version": 1,
        "name": "session",
        "extends": "large-base",
        "grants": user_grants,
    })
    .to_string();
    assert!(matches!(
        registry.resolve_user_profile(UserProfileDocumentV1::parse(&user_source)?),
        Err(UserProfileError::Profile(ProfileError::TooManyGrants(name))) if name == "session"
    ));

    let base_executables = (0..200)
        .map(|index| {
            serde_json::json!({
                "path": format!("/base/bin-{index}"),
                "scope": "exact",
            })
        })
        .collect::<Vec<_>>();
    let base_source = serde_json::json!({
        "schema_version": 4,
        "name": "large-exec-base",
        "executable_grants": base_executables,
    })
    .to_string();
    let registry = ProfileRegistry::build(&[("large-exec-base", &base_source)])?;
    let user_executables = (0..100)
        .map(|index| {
            serde_json::json!({
                "path": format!("/user/bin-{index}"),
                "scope": "exact",
            })
        })
        .collect::<Vec<_>>();
    let user_source = serde_json::json!({
        "schema_version": 1,
        "name": "exec-session",
        "extends": "large-exec-base",
        "executable_grants": user_executables,
    })
    .to_string();
    assert!(matches!(
        registry.resolve_user_profile(UserProfileDocumentV1::parse(&user_source)?),
        Err(UserProfileError::Profile(ProfileError::TooManyExecutables(name)))
            if name == "exec-session"
    ));
    Ok(())
}

#[test]
fn duplicate_user_grants_remain_required_but_resolve_once() -> Result<(), Box<dyn std::error::Error>>
{
    let source = r#"{
        "schema_version": 1,
        "name": "session",
        "extends": "agent",
        "grants": [
            { "path": "/required", "access": "read", "scope": "exact" },
            { "path": "/required", "access": "read", "scope": "exact" },
            { "path": "/second", "access": "read", "scope": "exact" }
        ]
    }"#;
    let resolved = registry()?.resolve_user_profile(UserProfileDocumentV1::parse(source)?)?;
    assert_eq!(
        resolved
            .required_grants()
            .map(|(position, grant)| (position, grant.path.as_str()))
            .collect::<Vec<_>>(),
        vec![(1, "/required"), (3, "/second")]
    );
    assert_eq!(
        resolved
            .profile()
            .grants()
            .iter()
            .filter(|grant| grant.path.as_str() == "/required")
            .count(),
        1
    );
    Ok(())
}

#[test]
fn required_entries_replace_matching_optional_base_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let source = r#"{
        "schema_version": 1,
        "name": "session",
        "extends": "agent",
        "grants": [
            { "path": "~/.agent", "access": "read_write", "scope": "subtree" }
        ],
        "executable_grants": [
            { "path": "~/.agent/bin", "scope": "subtree" }
        ]
    }"#;
    let resolved = registry()?.resolve_user_profile(UserProfileDocumentV1::parse(source)?)?;

    let files = resolved
        .profile()
        .grants()
        .iter()
        .filter(|grant| grant.path.as_str() == "~/.agent")
        .collect::<Vec<_>>();
    assert_eq!(files.len(), 1);
    assert!(!files[0].if_exists);
    let executables = resolved
        .profile()
        .executable_grants()
        .iter()
        .filter(|grant| grant.path.as_str() == "~/.agent/bin")
        .collect::<Vec<_>>();
    assert_eq!(executables.len(), 1);
    assert!(!executables[0].if_exists);
    assert_eq!(resolved.required_grants().len(), 1);
    assert_eq!(resolved.required_executable_grants().len(), 1);
    Ok(())
}
