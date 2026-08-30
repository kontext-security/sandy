# Rust sandbox primitive implementation plan

This plan introduces an embeddable current-process sandbox while preserving the
existing `sandy` command. The work is intentionally split into three reviewable
pull requests.

## Product boundary

- The Rust crate is caller-policy-only: it adds no application compatibility
  baseline and does not launch another executable.
- `apply` irreversibly restricts the calling process. The consumer owns its
  process and worker architecture.
- The CLI remains the safe launcher for unmodified commands. It owns bootstrap,
  supervision, environment filtering, profiles, and its typed macOS runtime
  baseline.
- Both entry points lower the same `SandboxPolicy` intent through validation and
  the native backend. The renderer never adds hidden filesystem or network
  capabilities.

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
- non-macOS targets compile and report unsupported enforcement.

## PR 3: package and release safely

Prepare implementation packages and the supported facade for coordinated
publication. Add an external-consumer packaging test and publish packages in
dependency order before producing the existing CLI artifacts.

Review gates:

- packaged sources build without workspace-only files;
- the documented dependency alias imports as `sandy`;
- registry publication order is `sandy-core`, `sandy-seatbelt`, then
  `sandy-sandbox`;
- release tags and workspace versions remain coordinated;
- the existing CLI archive and package-manager update remain unchanged after
  crate publication succeeds.

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
