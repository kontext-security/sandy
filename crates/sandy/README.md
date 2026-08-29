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

Application is irreversible. Call `apply` before creating threads, opening
sensitive resources, or starting untrusted work. The initial enforcement
backend is macOS; unsupported platforms return `ErrorKind::Unsupported`.

See the repository's [public API contract][api], security documentation, and
threat model before embedding Sandy.

[api]: https://github.com/kontext-security/sandy/blob/main/docs/PUBLIC_API.md
