![Sandy wordmark](assets/sandy-wordmark-dotbuild.gif)

# Sandy

[![Follow Sandy on X](https://img.shields.io/badge/X-Follow-000000?logo=x&logoColor=white)](https://x.com/kontextsecurity)
[![Follow Sandy on LinkedIn](https://img.shields.io/badge/LinkedIn-Follow-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/company/kontextdev)

> [!WARNING]
> Sandy `0.1.x` is experimental and has not completed an independent security
> audit. See [Security and support](#security-and-support).

Run AI coding agents in a sandbox.

Sandy gives an agent access to your project without giving it unrestricted
access to your computer. The sandbox also applies to every command and tool the
agent starts.

```bash
sandy run -- claude
```

The goal is simple: running an agent through Sandy should feel like running it
directly, except its access is explicitly limited.

## Design

Sandy does one job: sandbox processes. Credential brokering, behavioral
monitoring, approvals, and audit logs remain separate tools that can be used
alongside it.

All permissions are resolved before the agent starts. The agent cannot grant
itself more access while it is running.

If Sandy cannot validate or apply the sandbox, the agent does not run. There is
no fallback to unrestricted execution.

Sandy runs locally as a normal foreground command. It does not require a
container, VM, background service, or modified copy of the agent.

## Install

```bash
brew install kontext-security/tap/sandy
```

Check that sandboxing works:

```bash
sandy doctor
```

### Use from Rust

The Rust package applies a typed policy directly to the calling process. It has
no Sandy executable dependency and adds no application compatibility baseline.

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
// Start the restricted application here.
# Ok::<(), Box<dyn std::error::Error>>(())
```

Applications may instead load the same typed policy from strict, versioned
JSON:

```rust,no_run
use sandy::SandboxPolicy;

let source = std::fs::read("sandbox.json")?;
let policy = SandboxPolicy::from_json(&source)?;
sandy::apply(policy)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Reading a path does not make it executable. Chain `allow_execute(path, scope)`
for programs, libraries, or generated code. Launching one also requires the
policy to select `allow_subprocesses()`.

`apply` is irreversible. Call it before creating threads, opening sensitive
resources, or starting untrusted work. If native enforcement fails, terminate
the process instead of continuing with a weaker boundary. The library has
native macOS and Linux backends. Unsupported hosts and policy combinations
return `ErrorKind::Unsupported` without weakening the requested boundary.

## Run

Sandy recognizes Claude Code, Codex, and OpenCode:

```bash
sandy run -- claude
sandy run -- codex --sandbox danger-full-access
sandy run -- opencode
```

Codex's internal sandbox cannot be nested reliably inside Sandy. The
`danger-full-access` setting makes Sandy the single sandbox and does not disable
Codex's approval flow.

Other commands work too:

```bash
sandy run -- cargo test
sandy run -- python script.py
```

The current project is read/write by default.

Grant access to another directory:

```bash
sandy run --read ../shared-library -- claude
sandy run --read-write ~/Downloads/output -- codex --sandbox danger-full-access
```

File grants do not make content executable. Grant executable mapping and
launch separately when a target must run programs or generated code from an
additional path:

```bash
sandy run --read ../shared-tools --execute ../shared-tools -- \
  /bin/sh -c '../shared-tools/build'
```

Block network access:

```bash
sandy run --block-net -- cargo test
```

Review the resolved sandbox without starting the command:

```bash
sandy run --dry-run -- claude
```

Dry-run output is a versioned JSON document. `dry_run_schema_version` identifies
its public schema independently from the internal launch-manifest protocol.
Schema version 5 identifies the selected profile's `source` as `embedded` or
`user_file`; user-file selections also report their built-in `base` without
placing the source path or document contents in profile metadata.
The resolved policy includes the CLI's explicit runtime baseline and reports
its filesystem metadata, executable, subprocess, and foreground compatibility
behavior.
Optional host integrations are reported in the canonical `runtime_controls`
array, with one object per resolved runtime control containing `service`,
`enabled`, and nullable `version` fields.

All Sandy options go before `--`. Everything after `--` is passed to the target
unchanged.

## Profiles

Sandy uses built-in profiles to give supported agents access to the files they
need while protecting sensitive configuration.

Known agents are detected from the command name. Everything else uses the
generic profile. You can also select a profile explicitly:

```bash
sandy run --profile codex -- my-codex-wrapper
```

Profiles are versioned documents built into Sandy. They use Sandy's supported
permissions and cannot contain raw sandbox rules.

For one explicit session policy, load a user-authored profile file:

```bash
sandy run --profile-file ./project-sandbox.json -- codex --sandbox danger-full-access
```

The strict JSON document extends one selectable built-in profile and may add
typed filesystem grants, executable grants, and terminal filesystem denials.
Filesystem and executable authority are independent and must be requested
separately. Sandy does not discover profile files automatically. See [User
profile files](docs/PROFILE_FORMAT.md) for the complete format and security
semantics.

## How it works

Sandy resolves the command, paths, profile, environment, and permissions before
launch.

It then starts a small bootstrap process that validates the launch, applies the
sandbox, and replaces itself with the target command. The original Sandy
process waits outside the sandbox and returns the target's exit status.

The target never runs before the sandbox is active. Every process it starts
inherits the same restrictions.

## Other security tools

Sandy does not store credentials, inspect behavior, approve tool calls, or keep
an audit ledger.

Those functions can be provided by separate tools. Sandy can preserve supported
hooks and local services without making them part of its sandboxing core.

Current optional integrations can be required explicitly:

```bash
sandy integrations setup kontext --agent claude
sandy run --kontext -- claude

sandy integrations setup numbat --agent codex
sandy run --numbat -- codex --sandbox danger-full-access
```

For known agent profiles, Sandy automatically preserves verified existing
Kontext hooks and ownership-marked Numbat registrations whose complete
generated shape it recognizes. The explicit flag makes that integration
mandatory; without it, a missing integration has no effect on standalone
sandboxing.

`sandy integrations setup` is the explicit host-configuration path. It first
checks the selected agent's existing registration. A healthy integration is
left untouched; an installed provider is configured with its official setup
command; and a missing provider is installed before configuration. Kontext is
installed through its Homebrew tap and continues to own authentication, daemon
setup, and hook registration. For Kontext, `--agent` selects the registration
Sandy must verify; the provider-wide `kontext setup` command may configure
other supported agents as well. Numbat uses a versioned Sandy-managed executable
whose public macOS release archive is bounded and verified against a SHA-256
digest embedded in Sandy before it is published. Sandy then invokes Numbat's
official idempotent hook installer in file-output mode.

This command changes persistent host configuration and runs outside the
sandbox. Ordinary `sandy run` and `sandy doctor` never install, update, or
repair either provider. Existing installations on `PATH` are reused, and an
already active registration is authoritative even if its executable is not on
`PATH`.

Numbat hooks currently run inside the same sandbox as the agent. Sandy keeps
their registration, executable, and rule directories readable but immutable,
while the hook's record output and sequence-state database remain writable.
Direct HTTP delivery from a Numbat hook is not supported; use file output. See
[RUNTIME_CONTROLS.md](RUNTIME_CONTROLS.md) for the architecture, trust boundary,
and deferred outside-sandbox decision model.

Hook discovery honors `CLAUDE_CONFIG_DIR`, `CODEX_HOME`,
`OPENCODE_CONFIG_DIR`, and OpenCode's `XDG_CONFIG_HOME` fallback when those
variables name absolute configuration roots.

An operator can run Numbat's OTLP/HTTP collector outside Sandy and preserve
only its default local-host port while all other networking is blocked:

```bash
numbat collect --addr 127.0.0.1:4318
sandy run --block-net --numbat-collector -- codex --sandbox danger-full-access
```

`--numbat-collector=PORT` selects a different nonzero port and requires
`--block-net`. Sandy does not start or probe the collector and does not
configure the agent's telemetry exporter. It authorizes TCP connect to the
selected port on IPv4 addresses belonging to this Mac, including loopback and
other local interfaces; it does not authorize external addresses or other
ports.

## Security and support

Sandy is a process sandbox, not a container or VM. It reduces what a process can
access but does not provide a separate kernel, user account, or memory boundary.

Network access is allowed by default and can be blocked with `--block-net`.
Known-agent profiles may grant access to agent state directories for
compatibility.

The `sandy` CLI currently supports macOS; the Rust current-process library also
supports Linux on hosts that satisfy its native requirements. Version `0.1.x`
is experimental and has not completed an independent security audit. The
macOS backend uses Apple's private, deprecated Seatbelt interface.

Read [THREAT_MODEL.md](THREAT_MODEL.md) for the full security model and
[SECURITY.md](SECURITY.md) for vulnerability reporting.

## Development

```bash
make check
```

See [AGENTS.md](AGENTS.md) and [CONTRIBUTING.md](CONTRIBUTING.md) before changing
enforcement code.

## License

[MIT](LICENSE)
