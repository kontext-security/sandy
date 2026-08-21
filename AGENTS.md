# AGENTS.md

This file governs the entire repository.

## Project

Sandy is a macOS-native process sandbox for AI coding agents. Its canonical
executable is `sandy`.

Standalone sandboxing is the product default:

```bash
sandy run -- claude
sandy run -- codex
```

Kontext is an optional compatibility integration:

```bash
sandy run --kontext -- claude
```

Do not introduce a runtime dependency on Kontext for ordinary Sandy commands.
Do not modify the separate Kontext repository as part of Sandy changes.

## Supported scope

Version `0.1.x` is macOS-only and uses Seatbelt to restrict the target process
and its descendants. It is a process sandbox, not a container, VM, endpoint
monitor, or always-on daemon.

Keep the first release deliberately small:

- one foreground `run` execution mode;
- Claude Code, Codex, and generic/minimal profiles;
- current-working-directory and explicit filesystem grants;
- network allowed or fully blocked;
- resolved-manifest and dry-run output;
- optional self-serve Kontext compatibility.

Do not add Linux support, detached sessions, a PTY proxy, domain filtering,
credential brokering, dynamic grants, rollback, resource limits, arbitrary raw
Seatbelt input, or organization-managed Kontext support without an explicit
scope decision.

## Required architecture

Use a small Rust workspace:

- the root package owns the CLI, resolution, policy model, profiles, execution,
  and integrations;
- a private `crates/seatbelt` package owns the narrow macOS FFI wrapper.

Do not split the CLI and core model into separate public crates until a real
consumer requires it.

`sandy run` must:

1. resolve the command, environment, paths, profile, and optional integrations
   in the trusted parent;
2. spawn the same executable in a hidden bootstrap mode using
   `std::process::Command`;
3. send a bounded, versioned launch manifest over inherited close-on-exec
   pipes;
4. apply Seatbelt in the fresh bootstrap process;
5. report sandbox-application failure to the parent; and
6. `execve` the target only after Seatbelt succeeds.

Do not use Rust `pre_exec` callbacks or run general Rust code in a
fork-after-threads child. Prefer the normal macOS `posix_spawn` path used by
`std::process::Command`.

The parent remains outside the sandbox, supervises only the launched session,
and returns the target's exact exit status. Sandy must not install or start an
always-on Sandy daemon.

## Security invariants

These are release-blocking requirements:

- The target executable must never run when manifest validation, profile
  generation, the runtime probe, or Seatbelt application fails.
- Unsupported and already-incompatible sandbox environments fail closed.
- Seatbelt restrictions must be inherited by every target descendant.
- User-controlled values must never be concatenated into Seatbelt source
  without type-appropriate escaping and validation.
- Filesystem grants must be absolute, resolved, bounded, and inspectable.
- Sensitive terminal deny rules must override broader grants.
- Close all inherited file descriptors other than standard input, output, and
  error plus the bootstrap protocol descriptors.
- Create a private per-session temporary directory with mode `0700`, expose
  only that directory as `TMPDIR`, and clean it after the process tree exits.
- Strip `DYLD_*`, `SSH_AUTH_SOCK`, and security-sensitive routing overrides
  unless a reviewed feature explicitly requires them.
- Do not silently grant Keychain databases, SSH material, Docker sockets,
  unrelated Unix sockets, or the user's entire home directory.
- Never fall back to unrestricted execution after a sandbox error.

Treat the Seatbelt raw-profile interface as private, deprecated macOS SPI.
Probe support in a sacrificial subprocess and test it live on every supported
macOS release.

## Unsafe Rust

The root package must use:

```rust
#![forbid(unsafe_code)]
```

The Seatbelt crate must deny unsafe code globally and allow it only in a private
`ffi` module. Every unsafe block requires a local `SAFETY:` explanation that
states pointer ownership, lifetime, nullability, and cleanup assumptions.

Do not expose raw pointers or unsafe functions from the safe Seatbelt wrapper.
Convert native errors into owned Rust errors at the boundary.

## Launch manifest and paths

Use a versioned manifest model. Preserve command arguments and environment
values as `OsString` bytes on macOS rather than forcing UTF-8. Reject embedded
NUL only where required by `execve`. Paths inserted into Seatbelt source must
meet its encoding requirements or be rejected with a clear error.

Bound the serialized manifest and bootstrap error frames. Reject unknown
manifest versions. Do not deserialize unbounded attacker-controlled data.

Canonicalize existing grant paths and handle macOS aliases such as
`/tmp` and `/private/tmp` deliberately. Reject nonexistent grants in
`v0.1.x`. Add regression tests before changing symlink behavior.

## CLI contract

Keep the basic interface unsurprising:

```bash
sandy run [SANDY OPTIONS] -- COMMAND [ARGUMENTS...]
```

All Sandy options precede `--`. Pass everything after `--` to the target
without rewriting it.

Initial options may include:

- `--read PATH`;
- `--read-write PATH`;
- `--block-net`;
- `--preset NAME`;
- `--dry-run`;
- `--kontext`.

Do not add command shorthand that makes the option boundary ambiguous. Error
messages must identify the failed capability or path and provide a safe
remediation when one exists.

Dry-run output must describe the fully resolved manifest and must not start the
target or contact Kontext unless the user explicitly selected `--kontext`.
Never print secrets or full sensitive environment values.

## Process and terminal behavior

In `v0.1.x`, inherit standard input, output, error, terminal, and the foreground
process group. Do not introduce a PTY proxy.

Handle `INT`, `TERM`, `HUP`, and `QUIT` without leaving an unrestricted or
orphaned target. Close the spawn-to-handler race by controlling the signal mask
around bootstrap creation. Restore default dispositions and the signal mask
before target execution.

Return normal exit codes unchanged and use the conventional `128 + signal`
result for signal termination. Retry interrupted waits.

## Kontext integration

Keep integration behind the runtime `--kontext` branch, not a Cargo feature or
linked Kontext dependency. The host-installed `kontext` binary and existing
LaunchAgent daemon remain outside the sandbox.

`--kontext` must fail before target execution when its preflight cannot
establish a supported configuration. In particular:

- parse `kontext doctor --json`; do not infer health from its exit code;
- tolerate unknown additive JSON fields but reject malformed or missing
  required fields;
- validate the selected agent's hooks rather than relying only on aggregate
  health;
- start an already-configured self-serve LaunchAgent from the trusted parent
  when needed, but do not run automatic repair;
- resolve the executable used by the actual hook configuration, including its
  stable Homebrew path and resolved Cellar target;
- grant only the exact required read-only configuration and policy-cache files
  and the exact managed Unix socket;
- retain write-denies for hook configuration, policy files, Kontext databases,
  installation identity, logs, and Keychain material;
- strip or validate `KONTEXT_*` routing overrides and non-default
  `CODEX_HOME`.

The current Kontext socket is a same-user compatibility channel, not an
authenticated binding between the sandboxed process and hook events. Do not
claim complete tool coverage, cryptographic provenance, or that Kontext
supervises the Sandy process.

## Dependencies and Rust style

Target Rust edition 2024 with MSRV 1.85 unless a documented dependency requires
a deliberate change. Commit `Cargo.lock`.

Prefer a small synchronous dependency set. Expected dependencies include
`clap`, `serde`, `serde_json`, `toml`, `thiserror`, `tracing`,
`rustix` or narrowly scoped `libc`, and `signal-hook`.

Do not add Tokio, an HTTP client, a keyring library, a proxy stack, or a general
async runtime for `v0.1.x`.

Use structured error types and add context at subsystem boundaries. Avoid
`unwrap`, `expect`, unchecked indexing, and panics in production paths.
Keep platform-specific code behind explicit `cfg(target_os = "macos")`
boundaries.

Before committing Rust changes, run:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

## Tests

Pure policy rendering and resolution tests may run in-process. Every live
Seatbelt test must run in a sacrificial subprocess because applying a sandbox
is irreversible.

At minimum, cover:

- sandbox initialization failure never executes the target;
- current-project reads and writes;
- denial outside declared grants;
- denial of SSH, Keychain, and Kontext-sensitive state;
- child and grandchild inheritance;
- canonical paths, macOS path aliases, and symlink escape attempts;
- quotes, backslashes, newlines, control characters, and profile injection;
- private temporary-directory behavior;
- network allow and block behavior, including loopback and Unix sockets;
- exact Kontext socket access when integration is selected;
- immutable hook and policy configuration;
- environment and file-descriptor sanitization;
- normal exits, signal exits, Ctrl-C, and terminal behavior.

Release CI must include real Seatbelt end-to-end jobs on supported macOS 15 and
macOS 26 runners. Build and test both Apple Silicon and Intel release artifacts.

## Documentation and change discipline

Keep `README.md`, `THREAT_MODEL.md`, CLI help, and behavior consistent.
Describe guarantees narrowly and list residual risks. Never describe Sandy as
VM isolation or claim that hooks observe operations outside their documented
event surfaces.

Preserve unrelated user changes. Avoid broad rewrites when a focused patch is
enough. Security-sensitive behavior changes require tests in the same commit.
