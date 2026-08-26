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
sandy run --kontext -- claude
install -d -m 700 ~/.numbat
numbat hook install --agent codex
sandy run --numbat -- codex --sandbox danger-full-access
```

For known agent profiles, Sandy automatically preserves verified existing
Kontext hooks and ownership-marked Numbat registrations whose complete
generated shape it recognizes. The explicit flag makes that integration
mandatory; without it, a missing integration has no effect on standalone
sandboxing. Sandy never installs, updates, or repairs either service.

Numbat hooks currently run inside the same sandbox as the agent. Sandy keeps
their registration, executable, and rule directories readable but immutable,
while the hook's record output and sequence-state database remain writable.
Direct HTTP delivery from a Numbat hook is not supported; use file output. See
[RUNTIME_CONTROLS.md](RUNTIME_CONTROLS.md) for the architecture, trust boundary,
and deferred outside-sandbox decision model.

Hook discovery honors `CLAUDE_CONFIG_DIR`, `CODEX_HOME`,
`OPENCODE_CONFIG_DIR`, and OpenCode's `XDG_CONFIG_HOME` fallback when those
variables name absolute configuration roots.

## Security and support

Sandy is a process sandbox, not a container or VM. It reduces what a process can
access but does not provide a separate kernel, user account, or memory boundary.

Network access is allowed by default and can be blocked with `--block-net`.
Known-agent profiles may grant access to agent state directories for
compatibility.

Sandy currently supports macOS. Version `0.1.x` is experimental, has not
completed an independent security audit, and uses Apple's private, deprecated
Seatbelt interface.

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
