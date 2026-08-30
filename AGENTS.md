# AGENTS.md

This file governs the entire repository.

## Product contract

Sandy is a macOS-native process sandbox for AI coding agents.

- Cargo workspace: `sandy-core`, `sandy-seatbelt`, `sandy-sandbox`, and
  `sandy-cli`
- Installed executable: `sandy`
- Default mode: standalone sandboxing
- Optional integrations: preserve verified existing Kontext hooks or
  ownership-marked Numbat hooks; their explicit flags require them
- Explicit host setup: `sandy integrations setup kontext|numbat --agent NAME`
  may install and configure the selected optional provider
- Runtime model: one foreground supervisor per invocation, never a Sandy daemon

Sandy is a process sandbox, not a container or VM. Describe its guarantees
narrowly.

Version `0.1.x` is limited to macOS, one foreground `run` mode, Claude Code,
Codex, OpenCode, and generic profiles, explicit filesystem and executable
grants, network allow/block with exact runtime Unix-socket and IPv4 local-host TCP exceptions,
dry-run output, and optional self-serve Kontext and host-installed Numbat hook
compatibility. It also includes an explicit foreground integration setup
command for Kontext and Numbat. Setup is not part of sandbox launch.

The `sandy-sandbox` package provides the supported `sandy` Rust library. It is
a caller-policy-only, current-process primitive with no executable dependency.
Its public model is platform-neutral; `0.1.x` has a macOS backend and returns
`Unsupported` elsewhere.

Agent presets are versioned, strictly typed profile documents embedded in the
CLI at compile time. Profiles resolve through deterministic inheritance in
`sandy-core` and may express only existing typed capabilities. Adding an agent
requires a profile document, an embedded registry entry, and tests; it must not
require renderer or bootstrap changes.

`sandy run --profile-file PATH` accepts one explicit, bounded, strict UTF-8 JSON
user profile. Its narrow schema extends exactly one selectable embedded profile
and may add only required filesystem grants, executable grants, and terminal
filesystem denials.
There is no implicit discovery, include, URL, fallback, or user-to-user
inheritance. File I/O and ambient resolution remain in `sandy-cli`; lexical
validation and deterministic additive composition remain in `sandy-core`.

Do not add Linux, detached sessions, a PTY proxy, domain filtering, credential
brokering, dynamic grants, rollback, resource limits, raw Seatbelt input, or
organization-managed Kontext support or outside-sandbox synchronous hook
decision services without an explicit scope decision.

Do not modify the separate Kontext or Numbat repositories as part of Sandy
changes.

## Architecture

Use a virtual workspace with four packages representing validation,
native-code, embedding, and product boundaries.

```text
crates/core/               package sandy-core; validated security contract
crates/seatbelt/           package sandy-seatbelt; macOS compiler and FFI
crates/sandy/              package sandy-sandbox; supported Rust facade
crates/cli/                package sandy-cli; sandy binary and product UX
```

Do not add more crates until another distinct owner, dependency direction, and
second consumer or security boundary exists. Runtime-control resolvers and test
support remain modules inside `sandy-cli` in `v0.1.x`.

Keep dependencies flowing in one direction:

```text
CLI
  -> sandy-core
  -> sandy-seatbelt -> sandy-core

sandy facade
  -> sandy-core
  -> sandy-seatbelt -> sandy-core

optional integrations
  -> typed capabilities
  -> never raw Seatbelt source
```

`sandy-core` performs deterministic validation but no ambient filesystem
discovery. `sandy-seatbelt` receives only validated policy and does not see
argv, environment, agent preset names, Clap, or service configuration. The CLI
does not render policy. `SandboxPolicy` is the shared, side-effect-free intent
builder; the owning product boundary resolves its paths before validation.

The enforcement backend adds no implicit filesystem or network capabilities.
The CLI owns an explicit typed macOS runtime baseline and composes it through
the same policy model as profiles and command-line grants. Profiles, CLI
options, runtime resources, and optional integrations must all contribute
typed capabilities before the trusted parent finishes `ValidatedPolicy`.
Product code must not mutate the resulting wire policy after validation.

## Execution model

`sandy run` resolves the complete launch in the trusted parent, creates a
private session directory, and spawns the same executable in a hidden bootstrap
mode through `std::process::Command`.

The fresh bootstrap validates and removes a bounded, versioned manifest,
applies Seatbelt, and replaces itself with the target only after the sandbox
succeeds. Failures are reported on standard error without executing the target.

Do not use Rust `pre_exec` callbacks or run general Rust code in a
fork-after-threads child. The hidden bootstrap must not appear in normal CLI
help.

The parent remains outside the sandbox, supervises only the launched session,
cleans up session resources, and returns the target's exact exit status.

The Rust facade has a different execution boundary: `sandy::apply(policy)`
irreversibly restricts the calling process. It has no bootstrap or process
supervisor. Callers must apply before creating threads or starting untrusted
work and must terminate after an enforcement failure.

The Rust facade disables subprocess creation unless the caller selects the
typed subprocess capability and separately grants executable mappings. On
macOS, subprocess compatibility includes broad Mach lookup and may reach
same-user local services even when IP networking is blocked.

## Security invariants

These rules are release-blocking:

- The target never runs when resolution, validation, probing, rendering, or
  Seatbelt application fails.
- Unsupported and incompatible nested-sandbox environments fail closed.
- Sandy never falls back to unrestricted execution.
- Restrictions are inherited by every target descendant.
- The CLI and profiles accept typed capabilities, never raw Seatbelt rules.
- User-authored profiles are additive and cannot remove an embedded base's
  grants, protections, or hook behavior. Missing required user paths fail the
  launch rather than being skipped.
- The renderer adds no implicit filesystem or network capabilities. Product
  compatibility baselines must be explicit typed policy input.
- File reads never imply executable mapping. Executable paths and subprocess
  compatibility are separate typed capabilities.
- One centralized renderer validates and escapes every value used in policy.
- Paths are absolute, canonicalized, bounded, and compared as `Path`
  components rather than string prefixes.
- Canonicalization does not remove time-of-check/time-of-use risk; symlink and
  replacement behavior requires negative tests.
- Security configuration load failures are fatal. Never use a permissive
  default for missing protection data.
- Sensitive terminal deny rules override broader grants.
- Sandy-owned bootstrap resources must not survive target execution. Document
  that caller-supplied, non-`CLOEXEC` descriptors remain inherited capabilities.
- Give each session a mode-`0700` private `TMPDIR`; do not grant broad
  temporary-directory access.
- Strip `DYLD_*`, `SSH_AUTH_SOCK`, and security-routing overrides unless a
  reviewed capability explicitly requires them.
- Do not silently grant the home directory, Keychains, SSH material, Docker
  sockets, agent sockets, or unrelated local services.
- Filesystem access to a Unix socket never implies connect authority. Exact
  socket connections require a separate typed capability.
- A local-host TCP exception names one nonzero port and connect operation on
  IPv4 addresses belonging to the Mac. Never translate it into blanket
  networking, bind, DNS, IPv6, another port, or external-address access.
- Network-enabled profiles may reach same-user local services as well as the
  Internet; treat that as an explicit compatibility tradeoff.

Treat the Seatbelt raw-profile interface as private, deprecated macOS SPI.
Probe it in a sacrificial process and test it live on each supported macOS
release.

Policy loosening requires a named capability, a positive compatibility test,
and a negative test proving adjacent sensitive access remains denied. Never
add a blanket permission solely to make a smoke test pass.

## Unsafe Rust boundary

`sandy-core`, `sandy-sandbox`, and `sandy-cli` use `#![forbid(unsafe_code)]`.
`sandy-seatbelt` uses:

```rust
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
```

Unsafe code and native declarations are permitted only in:

```text
crates/seatbelt/src/platform/macos/ffi.rs
```

The parent module may lower the unsafe lint for exactly that private module.
Repository checks must reject `unsafe`, `extern "C"`, and
`allow(unsafe_code)` anywhere else.

Every unsafe block needs an adjacent `SAFETY:` explanation covering pointer
validity, ownership, lifetime, nullability, thread/process assumptions, and
cleanup. The FFI boundary exposes only owned safe Rust types and functions.
Raw pointers, unsafe functions, native error buffers, and raw sandbox flags
must not escape it.

Adding a native symbol requires documenting its SDK declaration, availability,
deprecation status, cleanup contract, and live macOS coverage.

## Data and CLI contracts

Preserve target arguments and environment values as `OsString` bytes. Reject
embedded NUL only at the native execution boundary and reject values that
cannot be represented safely in policy.

Bound every bootstrap manifest and error frame. Reject unknown protocol
versions. Protocol changes require a version decision and malformed-input
tests.

Canonicalize existing grants, handle macOS aliases deliberately, and reject
nonexistent grants in `v0.1.x`.

The public interface is:

```bash
sandy run [SANDY OPTIONS] -- COMMAND [ARGUMENTS...]
sandy integrations setup kontext|numbat --agent claude|codex|opencode
```

`--profile-file PATH` is an explicit `run` option and conflicts with
`--profile`. Its source is a bounded existing regular strict-UTF-8 JSON file.
Both the absolute lexical source path and canonical target receive terminal
subtree denials; these pathname rules do not eliminate replacement races or
cover hard-link aliases.

`--read` and `--read-write` add only filesystem authority. `--execute` adds
only executable mapping and launch authority. A path requiring both must be
named through both capability types.

All Sandy options precede `--`. Everything after `--` is opaque target data
and must pass through unchanged. Do not add ambiguous shorthand.

Clap help is the source of truth for syntax. The typed manifest is the source
of truth for launch behavior. Renderer tests are the source of truth for
generated policy.

Error messages identify the failed phase and safe remediation without dumping
secrets, full environments, or sensitive policy contents.

## Process behavior

Inherit standard input, output, error, terminal, and foreground process group.
Do not add a PTY proxy in `v0.1.x`.

Keep the parent, bootstrap, and target in the user's foreground process group so
terminal signals retain native behavior. Preserve normal exit codes and return
`128 + signal` for signal termination. Any future independent process group or
PTY mode must add race-free signal forwarding before it ships.

Supervisor changes require exit, signal, Ctrl-C, and terminal regression tests.

## Kontext boundary

Kontext remains a runtime-only integration, never a linked dependency or Cargo
feature. For known agent presets, Sandy may inspect normal hook configuration
to preserve already-installed Kontext hooks; it must not infer integration from
a binary merely appearing on `PATH`.

`--kontext` means Kontext is required. Without the flag and without a verified
Kontext-owned hook, Sandy performs no Kontext preflight or resource grant.

The host-installed Kontext binary and LaunchAgent daemon remain outside the
sandbox. An automatically detected installation that cannot be established is
disabled atomically with a warning and contributes no Kontext capabilities.
Preflight fails before target execution when Kontext is explicitly required.
Sandy never installs, downloads, repairs, or uninstalls Kontext during `run` or
`doctor`. `sandy integrations setup kontext --agent NAME` may install Kontext
through its Homebrew tap and invoke the official interactive `kontext setup`
flow. It must reuse a healthy active registration without mutation and verify
any changed registration through the normal runtime resolver before reporting
success.

Grant only exact resources required by the selected hook. Agent-visible hook
registration and the active self-serve configuration are readable for
compatibility but protected from writes. A cached enforcement policy is also
readable and immutable only in remote mode. Keep databases, installation
identity, logs, credentials, Keychain material, and unrelated Kontext state
protected from writes or disclosure.

Tests use fake executables, fixture output, temporary configuration roots, and
mock sockets. They never inspect or modify a developer's real Kontext
installation.

Do not claim authenticated process-to-hook binding, complete tool coverage,
cryptographic provenance, or that Kontext supervises the Sandy process.

## Numbat boundary

Numbat remains a runtime-only integration, never a linked dependency or Cargo
feature. For known agent presets, Sandy may inspect normal hook or plugin
configuration to preserve an already-installed Numbat integration. A binary on
`PATH` is not installation evidence.

`--numbat` requires a supported installed hook. Sandy never installs,
downloads, updates, repairs, or uninstalls Numbat during `run` or `doctor`. Its
resolver accepts only bounded, ownership-marked Claude Code, Codex, or OpenCode
registrations whose event, lifecycle, agent, executable, and runtime arguments
match the supported protocol.

The explicit setup command may reuse a Numbat executable on `PATH` or download
the reviewed macOS asset for one pinned version into a versioned Sandy-owned
path. The URL, archive size, executable size, and SHA-256 digest are fixed in
the resolver. Extract only the named regular executable and publish it atomically
without overwriting an existing path. Configuration delegates to Numbat's
official idempotent hook installer in file-output mode and must pass normal
runtime rediscovery before success.

Agent user-hook locations honor the typed `CLAUDE_CONFIG_DIR`, `CODEX_HOME`,
`OPENCODE_CONFIG_DIR`, and OpenCode `XDG_CONFIG_HOME` roots. Do not generalize
these into arbitrary environment-variable path templates.

Grant the exact executable and configuration source, read-only recursive access
to declared rule directories, and only the configured output and sequence-state
files as writable. Require writable-file parent directories to exist, and
protect them from replacement without making Sandy create provider state.
Protect hook sources, executable aliases and canonical targets, and rule
directories from writes. Reject configured hooks that resolve to different
executables, place writable output or state inside rule directories, overlap
Sandy-protected data, reuse one path for output and state, or require direct
HTTP delivery.

The Numbat hook and agent share one sandbox identity. Do not describe writable
record output or sequence state as agent-proof, an audit boundary, or complete
enforcement evidence. An outside-sandbox synchronous evaluator is not part of
this compatibility layer.

`--numbat-collector[=PORT]` requires `--block-net` and authorizes connect to one
selected TCP port on IPv4 addresses belonging to the Mac for an
operator-started OTLP/HTTP collector. It neither requires installed hooks nor
starts, probes, configures, or authenticates the collector. Treat it as
telemetry transport with same-user endpoint replacement, forgery, and denial
of service risks, never as the deferred synchronous evaluator.

## Rust and dependencies

Use Rust edition 2024 and pin one toolchain version consistently in
`Cargo.toml`, `rust-toolchain.toml`, and CI. Commit `Cargo.lock`.

Centralize package metadata, dependency versions, release profiles, and lints
in the root manifest. Future workspace members must inherit workspace lints.

Prefer a small synchronous dependency set. New dependencies require a concrete
need, minimal features, a lockfile update, license/source/advisory checks, and
an explanation in the change.

Do not add an async runtime, HTTP client, keyring library, proxy stack, or
plugin framework in `v0.1.x`. The explicit setup path may execute the exact
system `curl` and `tar` tools for its pinned, digest-verified Numbat asset; this
authority must not be reachable from `run` or `doctor`.

Production paths do not use `unwrap`, `expect`, unchecked indexing, or panic
for expected errors. Use structured errors, checked arithmetic for
security-sensitive sizes, and `#[must_use]` for critical results.

Do not suppress lints without a nearby reason. Avoid `#[allow(dead_code)]`;
remove unused code or test the intended behavior.

## Tests

Keep pure unit tests beside resolution, manifest, escaping, and renderer code.
Use black-box integration tests for CLI, process, signal, and sandbox behavior.

Applying Seatbelt is irreversible. Every live sandbox test runs in a
sacrificial subprocess, never inside the unit-test process.

Tests modifying process-wide environment variables use a restoring guard and
serialization. Fixtures contain no developer paths, usernames, credentials,
installation identifiers, or real socket locations.

Every security fix and policy change includes a regression test. Release CI
runs live Seatbelt tests on supported macOS 15 and 26 runners and builds both
Apple Silicon and Intel artifacts.

## Development process

Before changing code:

1. read this file and the relevant architecture, threat-model, and security
   documentation;
2. identify the trust boundary and tests affected;
3. preserve unrelated work; and
4. choose the smallest patch that fully solves the request.

Behavior, tests, and documentation change together. Keep commits focused.
Never commit build output, local paths, credentials, or temporary fixtures.
Keep the lockfile synchronized with manifests.

The repository provides one authoritative `make check` command used locally
and in CI. It runs at minimum:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo deny check
```

Security-sensitive renderer, FFI, bootstrap, process, capability, or
runtime-integration changes also run the dedicated live macOS test target.

CI uses minimal permissions, disables persisted checkout credentials, pins
third-party actions to full commit SHAs, and uses locked Cargo commands.

Release tags must match the workspace version. The release workflow verifies
all publishable sources, builds native arm64 and x86_64 macOS archives,
publishes `sandy-core`, `sandy-seatbelt`, and then the supported
`sandy-sandbox` facade, publishes checksums, and updates only
`Formula/sandy.rb` in `kontext-security/homebrew-tap`. Crate publication uses
the pinned `cargo-release` configuration and Cargo's registry-index readiness
checks. Sandy has no package dependency on Kontext and must not modify the
tap's Kontext formulae.

Before submitting a change, confirm:

- [ ] requested behavior works;
- [ ] adjacent sensitive behavior remains denied;
- [ ] failure paths cannot execute the target;
- [ ] no capability was broadened unintentionally;
- [ ] user-controlled paths and values are validated and escaped;
- [ ] tests and documentation changed with behavior;
- [ ] `make check` passes.

Keep `README.md`, CLI help, architecture documentation, `THREAT_MODEL.md`,
`SECURITY.md`, and behavior consistent. Replace planning language in this
file with actual commands and paths as implementation lands.
