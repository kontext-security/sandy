# sandy-sandbox

Typed, caller-policy-only current-process sandboxing for Rust applications.

The package exports the `sandy` library. It applies an explicit filesystem and
network policy directly to the calling process without requiring a Sandy
executable, daemon, or bootstrap hook.

```toml
[dependencies]
sandy = { package = "sandy-sandbox", version = "0.1" }
```

```rust,no_run
use sandy::{AccessMode, NetworkPolicy, PathScope, SandboxPolicy};

let workspace = std::env::current_dir()?;
let policy = SandboxPolicy::new(NetworkPolicy::BlockAll).grant(
    &workspace,
    AccessMode::ReadWrite,
    PathScope::Subtree,
);

sandy::apply(policy)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The same typed policy can be loaded from strict, versioned JSON:

```rust,no_run
use sandy::SandboxPolicy;

let source = std::fs::read("sandbox.json")?;
let policy = SandboxPolicy::from_json(&source)?;
sandy::apply(policy)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

JSON parsing performs no filesystem access. Paths are resolved and required to
exist only when `apply` prepares the policy.

Application is irreversible. Call `apply` before creating threads, opening
sensitive resources, or starting untrusted work. Sandy has native macOS and
Linux backends; unsupported hosts and policy combinations return
`ErrorKind::Unsupported` rather than falling back to weaker enforcement. The
Linux backend requires user and mount namespaces plus Landlock ABI 9.

See the repository's [public API contract][api], security documentation, and
threat model before embedding Sandy.

[api]: https://github.com/kontext-security/sandy/blob/main/docs/PUBLIC_API.md
