# Implementation plan

The original four-PR Rust facade plan below is complete. Linux support is the
current three-PR stack and preserves the same public policy surface.

## Linux stack

```text
                         sandy-core
                    validated semantics
                      /           \
             sandy-seatbelt     sandy-linux
                  macOS            Linux
                      \           /
                   sandy-sandbox facade

                       sandy-cli
                           |
                  selected native backend
```

### PR 1 — Linux enforcement substrate

Add `sandy-linux` as a separately reviewable security boundary:

```text
ValidatedPolicy
      |
      v
LinuxPolicyPlan       pure and deterministic
      |
      v
PreparedLinuxSandbox  pins paths and prepares rules
      |
      v
apply()               irreversible native transition
```

The backend uses private user, mount, and IPC namespaces, an optional network
namespace for `BlockAll`, a descriptor-built private root, complete capability
removal, and final seccomp filters. The fixed security baseline requires
Linux 6.12 or a vendor kernel carrying Landlock ABI 6 and always scopes signals
to the sandbox domain. The backend isolates System V IPC, replaces the inherited
session keyring, and denies key-management syscalls. Exact external Unix-socket
grants remain unsupported. Namespace support is exercised in a sacrificial
child before enforcement. Unsupported host facilities and policy shapes fail
without a weaker fallback.

### PR 2 — Current-process Linux facade

Dispatch `sandy::apply()` to the Linux backend without changing the public
surface or adding an executable dependency. The facade still adds no runtime
paths, profiles, environment changes, or helper process. Sacrificial tests
cover policy application, inheritance, network denial, and fail-closed cases.

### PR 3 — Linux CLI and distribution

Wire the existing same-executable bootstrap to `sandy-linux`. Add the explicit
Linux runtime baseline, backend-neutral dry-run and doctor output, full Linux
workspace and live CI, and native GNU/Linux archives for x86-64 and arm64.
Publish packages in dependency order:

```text
sandy-core -> sandy-seatbelt -> sandy-linux -> sandy-sandbox
```

Homebrew remains macOS-only. The Linux release contract and unsupported policy
shapes are documented in `LINUX_SECURITY_MODEL.md`.

## Completed Rust facade plan

## Product boundary

- The Rust crate is caller-policy-only: it adds no application compatibility
  baseline and does not launch another executable.
- `apply` irreversibly restricts the calling process. The consumer owns its
  process and worker architecture.
- The CLI remains the safe launcher for unmodified commands. It owns bootstrap,
  supervision, environment filtering, profiles, and its typed runtime
  baseline.
- Both entry points lower the same `SandboxPolicy` intent through validation and
  the native backend. The renderer never adds hidden filesystem or network
  capabilities.
- Facade callers may build `SandboxPolicy` in Rust or parse the same policy
  vocabulary from strict, bounded, versioned JSON. Parsing is side-effect-free
  and introduces no second policy model.
- The CLI may load that same complete caller-controlled document explicitly.
  It adds only documented fixed launcher capabilities and disables automatic
  integration discovery for that invocation.
- The CLI may load one explicit narrow user profile file. Deterministic schema
  validation and additive base composition of independent filesystem,
  executable, and terminal-deny capabilities live in `sandy-core`; bounded
  file loading, template expansion, canonicalization, diagnostics, and
  source-path protection remain in `sandy-cli`. No additional package boundary
  is needed.

## PR 1: make the CLI baseline explicit

Introduce the side-effect-free policy builder in `sandy-core`. Move every
macOS runtime filesystem and metadata capability out of the renderer and into a
typed CLI-owned baseline. Resolve that builder into the existing validated
policy without changing CLI behavior.

Review gates:

- deterministic normalization without broadening overlapping grants;
- no implicit filesystem or network allow rules in the renderer;
- dry-run output exposes the resolved metadata behavior;
- workspace tests and all sacrificial live macOS tests pass.

## PR 2: add the current-process Rust API

Add the supported `sandy-sandbox` package with a `sandy` library target. Its
public surface consists of typed filesystem, executable, network, and optional
subprocess policy construction, `apply`, a small stable error classification,
and no process-launch API. Resolve relative paths against one captured working
directory, reject nonexistent or unsafe paths, validate the complete policy,
compile it, and apply it to the current process.

The crate must not contain or invoke a helper executable. It must document that
application is irreversible, should happen before creating threads or opening
sensitive resources, and that any enforcement error requires immediate process
termination before untrusted work.

Review gates:

- no implicit filesystem, network, or foreground compatibility baseline in the
  library path;
- grants and terminal denies have positive and adjacent-negative tests;
- descendants inherit restrictions in a sacrificial process test;
- errors do not disclose caller paths or backend policy contents;
- unsupported targets compile and report unsupported enforcement.

## PR 3: package and release safely

Prepare implementation packages and the supported facade for coordinated
publication. Verify the normalized package sources, compile a separate consumer
through the documented dependency alias, and publish packages in dependency
order after both CLI archives have built and before the draft release becomes
public.

Review gates:

- packaged sources build without workspace-only files;
- the documented dependency alias imports as `sandy`;
- registry publication order follows backend dependencies and publishes the
  supported `sandy-sandbox` facade last;
- release tags and workspace versions remain coordinated;
- the existing CLI archive and package-manager update remain unchanged after
  crate publication succeeds.

## PR 4: accept facade JSON policies

Add `SandboxPolicy::from_json` as the single serialized construction path. Keep
the document wire types private, reject unknown fields and unsupported schema
versions, bound source bytes and capability counts, and return the same
`SandboxPolicy` produced by the Rust builder. File and executable authority
remain separate.

Review gates:

- parsing performs no filesystem access;
- no discovery, inheritance, includes, interpolation, or implicit grants;
- malformed diagnostics do not disclose policy values;
- the supported facade re-exports only the parser error, not document wire
  types; and
- builder and JSON policies use the same ambient resolution, validation,
  compilation, and enforcement path.

## Stable normalization rules

1. Bound caller entries before filesystem expansion.
2. Resolve grants to canonical existing targets.
3. Preserve lexical and canonical deny targets where they differ.
4. Bound the effective entries after expansion.
5. Deduplicate identical resolved rules.
6. For the same path and scope, read/write subsumes read.
7. Preserve exact and subtree rules as distinct capabilities.
8. Terminal denies override grants independently of builder order.
9. Do not otherwise merge overlapping paths or broaden authority.
