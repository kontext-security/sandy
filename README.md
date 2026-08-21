# Sandy

Experimental, native macOS sandboxing for AI coding agents. The installed
command is `sandy`.

Sandy uses macOS Seatbelt to restrict a foreground process and all of its
descendants. It is a process sandbox, not a container or VM.

## Quick start

Install the private preview with Homebrew after authenticating with an account
that can read this repository:

```bash
HOMEBREW_GITHUB_API_TOKEN="$(gh auth token)" \
  brew install kontext-security/tap/sandy
```

Sandy remains independent of Kontext; this token is only needed because the
Sandy release assets are private. You can also install from source with Rust
1.91.1 using `cargo install --path crates/cli --locked` from a checkout.

Run an agent with read/write access to the current project:

```bash
sandy doctor
sandy run -- claude
sandy run -- codex
sandy run -- opencode
```

Sandy recognizes known agents from the command name and applies a matching
profile; anything else runs with the generic profile. Force a profile with
`--profile claude|codex|opencode|generic`. Detection is announced on standard
error so it is never silent.

Profiles are versioned typed documents compiled into the binary
(`crates/cli/profiles/*.json`) and listed in the CLI's embedded registry. They
declare filesystem grants, protected paths, and Kontext hook locations; they
never carry raw Seatbelt source.

Sandy is standalone by default. It does not require Kontext, a daemon, an
account, or a second copy of the target agent.

```bash
# Grant another directory read access.
sandy run --read ../shared-library -- claude

# Grant an output directory read/write access.
sandy run --read-write ~/Downloads/output -- codex

# Block network access for the complete child process tree.
sandy run --block-net -- cargo test

# Inspect the resolved manifest and Seatbelt profile without executing.
sandy run --dry-run -- claude
```

All Sandy options precede `--`. Everything after it is passed to the target
unchanged.

## Optional Kontext compatibility

Sandy and [Kontext](https://github.com/kontext-security/kontext) are installed
and updated independently:

```bash
# Sandy works without these steps.
brew install kontext-security/tap/kontext
kontext setup

sandy run --kontext -- claude
```

`--kontext` requires an existing, configured, healthy host installation. Sandy
does not download Kontext, run setup, repair it, or embed its daemon. When a
known Claude Code or Codex profile already contains a verified Kontext hook,
Sandy automatically preserves that host configuration; a broken configured
hook fails before the agent starts. Generic commands do not trigger discovery.

The host-installed hook executable runs as a sandboxed descendant, while the
existing LaunchAgent daemon remains outside:

```text
user
  |
  v
sandy (trusted foreground parent)
  |
  v
bootstrap -- apply Seatbelt -- exec agent -- existing Kontext hook
                                               |
                                               v
                                     host LaunchAgent daemon
```

Sandy grants only the resolved hook executable, selected hook/configuration
files, cached policy needed for outage behavior, and the local daemon socket.
It does not install Kontext in the child or grant its token, Keychain items,
ledger database, or logs. Kontext hook coverage remains cooperative and is
separate from the kernel-enforced process boundary.

## Architecture

The repository is a Rust workspace with three boundaries:

```text
crates/core       validated capabilities, launch manifest, bounded wire format
crates/seatbelt   typed Seatbelt compiler and the sole native/unsafe boundary
crates/cli        `sandy` UX, resolution, bootstrap, supervision, integrations
```

`sandy run` resolves paths and the complete launch policy in an unsandboxed
parent. It writes a mode-`0600` bounded manifest into a private session
directory and starts the same executable in a hidden bootstrap mode. The
bootstrap reads, validates, and removes the manifest, applies Seatbelt, then
replaces itself with the target. The target never executes after an apply or
validation failure.

There is no Sandy daemon, PTY proxy, detached session, runtime downloader, or
unrestricted fallback.

## Current security model

- Filesystem policy is deny-first. The current project is read/write; explicit
  additional grants are canonicalized before compilation.
- SSH, cloud credential, Keychain, and other protected home locations remain
  denied even when a broader grant overlaps them.
- A private per-session `TMPDIR` is read/write. Broad temporary directories are
  not granted.
- `DYLD_*`, `SSH_AUTH_SOCK`, askpass, and Kontext routing overrides are removed
  from the child environment.
- Network is allowed by default for agent compatibility. `--block-net` blocks
  it for the sandboxed process tree. Network-enabled mode can also reach other
  same-user local services.
- Standard input, output, and error are inherited. Deliberately redirecting an
  already-open descriptor into Sandy can carry that capability across launch.
- Descendants inherit the sandbox. Sandy returns normal target exit codes and
  `128 + signal` for signal termination.

The policy permits broad Mach service lookup for application compatibility,
with explicit Keychain/security-service denies. Mach/XPC confused-deputy risk
is not eliminated. Kontext's current local socket is also not a
cryptographically authenticated Sandy session, so this release does not claim
authenticated process-to-hook provenance.

Apple's raw Seatbelt profile interface is private and deprecated. `sandy
doctor` probes it in a sacrificial process and fails closed on unsupported or
already-sandboxed environments.

See [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md) before
depending on Sandy as a security boundary.

## `v0.1.0` scope

Included in this first implementation:

- a standalone macOS runner for generic commands, Claude Code, Codex, and
  OpenCode;
- typed filesystem grants and network allow/block;
- byte-preserving arguments and a bounded, versioned launch manifest;
- a fresh apply-before-exec bootstrap;
- resolved-policy dry runs and a Seatbelt doctor;
- optional compatibility with existing self-serve Kontext hooks; and
- unit, CLI, renderer-injection, and sacrificial live Seatbelt tests.

Deferred: Linux and Windows, organization-managed Kontext, domain-filtered
networking, credential brokering, dynamic grants, filesystem rollback,
resource limits, detached sessions, PTY attachment, and VM isolation.

## Development

```bash
make check

# Must run on a host, not from inside another sandbox:
cargo test -p sandy-cli --test live_macos -- --ignored
```

`make check` expects `cargo-deny` 0.20.2 to be installed.

Only `crates/seatbelt/src/platform/macos/ffi.rs` may contain unsafe Rust or
native declarations. See [AGENTS.md](AGENTS.md) for repository invariants.

Sandy is licensed under the [MIT License](LICENSE).
