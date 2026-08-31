# Sandy Rust API

The `sandy-sandbox` package is a caller-policy-only current-process sandbox
primitive with no implicit application runtime baseline. Once published,
consumers alias the package to its `sandy` library name:

```toml
[dependencies]
sandy = { package = "sandy-sandbox", version = "0.2" }
```

It requires no Sandy executable, daemon, bootstrap hook, or special application
entry point.

## Primary use

```rust,no_run
use sandy::{AccessMode, NetworkPolicy, PathScope, SandboxPolicy};

let workspace = std::env::current_dir()?;
let cache = workspace.join(".cache");
let credentials = workspace.join("credentials");
let settings = workspace.join("settings.json");

// Every policy path must already exist when apply is called.

let policy = SandboxPolicy::new(NetworkPolicy::BlockAll)
    .allow_subprocesses()
    .grant(
        &workspace,
        AccessMode::ReadWrite,
        PathScope::Subtree,
    )
    .allow_execute(&workspace, PathScope::Subtree)
    .grant(&cache, AccessMode::Read, PathScope::Subtree)
    .deny_subtree(&credentials)
    .deny_write_exact(&settings);

sandy::apply(policy)?;
// Start the restricted application here.
# Ok::<(), Box<dyn std::error::Error>>(())
```

The caller owns process architecture and all policy. Sandy owns path resolution,
validation, native compilation, and the irreversible enforcement transition.

## JSON policy documents

Applications that keep policy outside their Rust source can construct the same
`SandboxPolicy` from JSON:

```rust,no_run
use sandy::SandboxPolicy;

let source = std::fs::read("sandbox.json")?;
let policy = SandboxPolicy::from_json(&source)?;
sandy::apply(policy)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The complete version 1 shape is:

```json
{
  "schema_version": 1,
  "network": "block_all",
  "allow_subprocesses": false,
  "grants": [
    {
      "path": "workspace",
      "access": "read_write",
      "scope": "subtree"
    }
  ],
  "executable_grants": [
    {
      "path": "workspace/tool",
      "scope": "exact"
    }
  ],
  "deny_subtrees": ["workspace/credentials"],
  "deny_write_exact": ["workspace/settings.json"]
}
```

`schema_version` and `network` are required. The remaining fields default to
empty capability sets or `false`. Documents are limited to 64 KiB, unknown
fields and unsupported versions are rejected, and parse errors do not contain
policy values. Parsing performs no filesystem access. Relative paths retain
their meaning until `apply` resolves them against one working-directory
snapshot and requires them to exist.

There is no interpolation, home-directory expansion, inheritance, include,
profile selection, or implicit executable authority. A caller that needs
runtime values may add them with the normal builder after parsing. Sandy does
not retain the source bytes or know which file they came from, so the embedding
application owns loading and protecting that source.

JSON path values are Unicode strings. Callers that need non-Unicode operating
system paths must use the Rust builder.

## Complete public surface

```rust,ignore
/// Irreversibly restricts the current process and future descendants.
///
/// All path resolution, normalization, validation, and native compilation
/// complete before enforcement is attempted. No weaker fallback is used.
pub fn apply(policy: SandboxPolicy) -> Result<(), SandboxError>;

/// Side-effect-free caller policy intent.
#[must_use]
pub struct SandboxPolicy {
    /* private */
}

impl SandboxPolicy {
    /// Parses a strict, bounded, versioned JSON policy document without
    /// consulting the filesystem.
    pub fn from_json(source: &[u8]) -> Result<Self, PolicyDocumentError>;

    /// Creates an empty filesystem policy with explicit network behavior.
    pub fn new(network: NetworkPolicy) -> Self;

    /// Grants read or read/write access to one exact path or complete subtree.
    /// This records intent and performs no filesystem access.
    pub fn grant(
        self,
        path: impl Into<PathBuf>,
        access: AccessMode,
        scope: PathScope,
    ) -> Self;

    /// Allows native executable mapping from one exact path or subtree.
    /// With subprocess support, this also permits launching a matching path.
    /// This does not grant ordinary file reads or writes.
    pub fn allow_execute(
        self,
        path: impl Into<PathBuf>,
        scope: PathScope,
    ) -> Self;

    /// Allows ordinary descendant process creation. Executable paths remain
    /// scoped by `allow_execute`.
    pub fn allow_subprocesses(self) -> Self;

    /// Denies reads, writes, executable mapping, and launch to a subtree.
    /// The deny overrides overlapping grants regardless of builder order.
    pub fn deny_subtree(self, path: impl Into<PathBuf>) -> Self;

    /// Denies writes to exactly one path without implicitly granting reads.
    /// Preparation also pins writable ancestors against relocation; adjacent
    /// entries remain writable.
    pub fn deny_write_exact(self, path: impl Into<PathBuf>) -> Self;
}

#[non_exhaustive]
pub enum PolicyDocumentError {
    /// The source exceeds 64 KiB.
    TooLarge,
    /// The JSON syntax or document shape is invalid.
    Parse { line: usize, column: usize },
    /// The schema version is not supported by this release.
    UnsupportedVersion(u32),
    /// At least one capability section exceeds its entry limit.
    TooManyCapabilities,
}

#[non_exhaustive]
pub enum AccessMode {
    /// Permit reads but no mutation.
    Read,
    /// Permit reads and mutation.
    ReadWrite,
}

#[non_exhaustive]
pub enum PathScope {
    /// Match only the named filesystem node.
    Exact,
    /// Match the named directory and everything beneath it.
    Subtree,
}

#[non_exhaustive]
pub enum NetworkPolicy {
    /// Permit network operations.
    AllowAll,
    /// Add no network allow rule.
    BlockAll,
}

pub struct SandboxError {
    /* private */
}

impl SandboxError {
    /// Returns the stable phase classification without exposing sensitive data.
    pub fn kind(&self) -> ErrorKind;
}

#[non_exhaustive]
pub enum ErrorKind {
    /// No backend can establish the contract on this platform.
    Unsupported,
    /// Caller policy cannot be resolved or enforced safely.
    InvalidPolicy,
    /// Trusted preparation failed before native enforcement began.
    PreparationFailed,
    /// Native enforcement failed and the requested boundary is unproven.
    EnforcementFailed,
}
```

Unimplemented operations are absent rather than published as placeholders.

## Policy semantics

- Sandy adds no filesystem grants, network grants, runtime baseline, profiles,
  protected product paths, or environment changes.
- Relative paths are resolved against one working-directory snapshot captured
  by `apply`.
- Every requested path must exist. Grants use the canonical target. Denies
  preserve both safe lexical and canonical spellings when they differ. Parent
  components are resolved with filesystem semantics after following symlinks.
- File reads never imply executable mapping or launch authority. Call
  `allow_execute` explicitly for programs, libraries, or generated code that
  may be executed.
- Subprocess creation is disabled unless `allow_subprocesses` is selected, and
  launching a particular path also requires a matching `allow_execute` grant.
  On macOS, the subprocess compatibility class includes broad Mach lookup and
  can reach same-user local services even when IP networking is blocked.
- Exact and subtree rules remain distinct. For one identical path and scope,
  read/write subsumes read.
- Denies override grants independently of builder call order.
- Root may only be granted exact read access. Root cannot be denied.
- Inputs and effective rules are bounded before native enforcement.
- Unsupported capability semantics are rejected; they are never ignored.
- With subprocess support enabled, ordinary descendant creation and
  same-sandbox signals are permitted. Executable mapping and launch paths
  remain explicit. Process inspection and foreground terminal compatibility
  are not part of this capability.

## Process semantics

- Successful application is irreversible.
- The current process and future descendants inherit the restriction.
- Call `apply` before creating threads. Existing threads are outside the
  portable API contract.
- Already-open descriptors, sockets, memory, environment values, and native
  handles are not revoked or sanitized.
- Preparation completes before enforcement is attempted.
- After an enforcement failure, terminate before running untrusted work.
- A second application is unsupported and must not be used to widen or replace
  an existing policy.

## Platform contract

The API and policy vocabulary are platform-neutral. Starting with version 0.2,
Sandy has native macOS and Linux backends. Other platforms return
`ErrorKind::Unsupported`. Linux additionally requires Linux 6.12 or a vendor
kernel carrying Landlock ABI 6, user, mount, and IPC namespaces, `openat2`, the
modern mount API, and seccomp. A host or policy combination that cannot preserve
the contract returns `Unsupported`; it is never weakened.
Host security policy must permit the calling executable to configure those
namespaces. Sandy tests that transition in a sacrificial child before altering
the caller.

On Linux, preparation verifies that the caller is single-threaded. Application
enters private namespaces and a descriptor-built filesystem view before adding
Landlock and seccomp restrictions. Preparation errors leave the process
unchanged. An enforcement error can leave it partially restricted, so the
caller must terminate immediately. The current working directory must be
covered by an explicit filesystem grant because the private view contains only
granted paths. The Linux backend replaces the inherited session keyring with an
anonymous ring and denies key-management syscalls as fixed native semantics.

## Intentionally private or absent

- CLI profiles, explicit user profile-file loading, and runtime baselines
- command launch, supervision, output capture, and terminal handling
- helper and bootstrap protocols
- environment mutation
- raw native policy source
- exact socket and endpoint exceptions
- current-process support probing
- C ABI and other language bindings

The CLI's `--profile-file` document is separate from the facade JSON shape. It
composes with CLI-owned profiles and compatibility behavior, while
`SandboxPolicy::from_json` describes only caller-owned current-process policy.
