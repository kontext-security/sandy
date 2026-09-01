![Sandy wordmark](assets/sandy-wordmark-dotbuild.gif)

# Sandy

[![Follow Sandy on X](https://img.shields.io/badge/X-Follow-000000?logo=x&logoColor=white)](https://x.com/kontextsecurity)
[![Follow Sandy on LinkedIn](https://img.shields.io/badge/LinkedIn-Follow-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/company/kontextdev)

Kernel-enforced sandboxing for AI coding agents.

Sandy gives an agent access to your project without giving it unrestricted
access to your computer. The sandbox applies to the agent and every command it
starts. If Sandy cannot enforce the requested policy, the agent does not run.

Sandy is a foreground process sandbox, not a container, VM, daemon, or modified
copy of the agent.

## Quick Start

Install Sandy on macOS with Homebrew:

```bash
brew install kontext-security/tap/sandy
```

Linux x86-64 and arm64 archives and their SHA-256 checksums are available from
[GitHub Releases](https://github.com/kontext-security/sandy/releases). Unpack
the archive and place `sandy` on your `PATH`.

Verify that the native sandbox is available:

```bash
sandy doctor
```

Then run an agent from your project:

```bash
# macOS
sandy run -- claude
sandy run -- codex --sandbox danger-full-access
sandy run -- opencode

# Linux 0.2 (after the one-time setup below)
sandy run -- codex --sandbox danger-full-access
```

On Linux, create Codex's protected control files before the first Sandy launch.
Sandy does not create or overwrite agent configuration during `run`:

```bash
mkdir -p ~/.codex
test -e ~/.codex/config.toml || touch ~/.codex/config.toml
test -e ~/.codex/hooks.json || printf '{}\n' > ~/.codex/hooks.json
```

Linux CI launches a pinned native Codex release under the built-in profile on
x86-64 and arm64 and checks `codex --version`. This qualifies binary startup;
it does not cover the TUI, configuration lifecycle, tool execution,
authentication, or provider sessions. Claude Code and OpenCode native Linux
releases require dynamic `/proc/self` interfaces that Sandy's private root
intentionally omits, so they are outside the Linux 0.2 compatibility contract.

The current project is writable. Network access is allowed unless you block it
explicitly:

```bash
sandy run --block-net -- claude
```

Grant additional filesystem access with Sandy options before `--`. Everything
after `--` is passed to the target unchanged.

```bash
sandy run --read ../shared --read-write ~/Downloads/output -- claude
sandy run --dry-run -- claude
```

## Use As a Library

The Rust library restricts the calling process directly. It does not require
the Sandy executable, a daemon, or a bootstrap hook.

```toml
[dependencies]
sandy = { package = "sandy-sandbox", version = "0.2" }
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
run_untrusted_work();

# fn run_untrusted_work() {}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`apply` is irreversible. Call it before starting threads, opening sensitive
resources, or running untrusted work. The caller owns the complete policy;
Sandy adds no implicit application baseline.

## Customize

Policies can live outside application code as strict, versioned JSON. This
policy makes the current workspace writable, blocks network access, permits
subprocesses and tools below `./tools`, and keeps `settings.json` read-only:

```json
{
  "schema_version": 1,
  "network": "block_all",
  "allow_subprocesses": true,
  "grants": [
    {
      "path": ".",
      "access": "read_write",
      "scope": "subtree"
    }
  ],
  "executable_grants": [
    {
      "path": "./tools",
      "scope": "subtree"
    }
  ],
  "deny_write_exact": [
    "./settings.json"
  ]
}
```

Embed the document in a Rust binary and apply it without reading policy from
the host at runtime:

```rust,no_run
use sandy::SandboxPolicy;

let policy = SandboxPolicy::from_json(include_bytes!("sandbox.json"))?;
sandy::apply(policy)?;
run_untrusted_work();

# fn run_untrusted_work() {}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Policy paths are resolved when `apply` runs and must already exist. File access
does not imply executable access. Unknown fields, unsupported versions, and
unrepresentable policy combinations are rejected rather than approximated.
This complete library policy is not a CLI `--profile-file`: the CLI format is
an additive extension of one built-in profile and cannot set network or process
policy. See the [public Rust API](docs/PUBLIC_API.md) and [CLI profile
format](docs/PROFILE_FORMAT.md) for the two contracts.

## Behavioral Security

Kernel enforcement is foundational, but it cannot determine whether an
otherwise permitted action is suspicious, whether a sequence of actions forms
an attack, or which policy should govern a specific agent decision. Sandy
therefore keeps behavioral detection and authorization separate and
composable:

- [Numbat](https://github.com/perplexityai/numbat) provides endpoint visibility,
  on-device detection, optional pre-action blocking, and forensic
  reconstruction across hooks, session artifacts, and telemetry from
  OpenTelemetry exporters over OTLP/HTTP.
- [Kontext](https://github.com/kontext-security/kontext) adds identity-aware,
  pre-action authorization with Cedar policies at supported agent hooks and
  records the decision and available outcome in an authorization ledger.

These controls reason about behavior and intent. Sandy remains the native
boundary that limits what the process can physically access. On macOS, Sandy
can preserve verified existing hooks for these tools; neither is required to
use the sandbox.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Changes
to enforcement must update behavior, tests, and documentation together.

```bash
make check
```

## Security

Sandy is experimental security software and has not completed an independent
audit. It is a process sandbox, not a separate kernel, user account, or memory
boundary. The macOS backend uses Apple's private, deprecated Seatbelt
interface. Linux has an explicit host and compatibility contract documented in
the [Linux security model](docs/LINUX_SECURITY_MODEL.md).

Read the [threat model](THREAT_MODEL.md) before relying on Sandy for a security
boundary. Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md); do not open a public issue for an unpatched
vulnerability.

## License

[MIT](LICENSE)
