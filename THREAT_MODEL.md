# Threat model

Sandy reduces the filesystem, network, credential, and local-service access of
a process tree. The CLI and current-process Rust facade have native macOS and
Linux backends. The protected subject is the host user's data outside explicit
grants. The target command, its dependencies, generated code, and all
descendants are untrusted.

## Trusted computing base

The trusted base is `sandy-core` validation, the selected native backend, and
the host kernel. CLI launches additionally trust the Sandy parent and bootstrap.
macOS trusts the Seatbelt compiler and native wrapper. Linux application trusts
namespace and mount preparation, Landlock, capability removal, and seccomp.
The selected executable and agent hooks are inside the sandbox and untrusted.
An optional Kontext daemon remains a separate host service.

The explicit `sandy integrations setup` command is a trusted host
administration operation, not part of sandbox launch. It executes Homebrew and
provider-owned setup binaries outside Seatbelt and permits them to persistently
change the user's installation and agent hook configuration. Ordinary `run`
and `doctor` paths do not have this authority.

## Security boundaries

Sandy validates and canonicalizes an entire launch before applying policy. A
fresh bootstrap removes its manifest, applies the selected native backend, and
only then executes the target. Any failure terminates without running the
target. Descendants inherit the resulting restrictions.

The Rust facade instead applies policy directly to its calling process. The
embedding application is responsible for invoking `apply` before it creates
threads or begins untrusted work. There is no helper executable in this path.
Successful restrictions are inherited by future descendants.

Facade JSON is untrusted input for strict, bounded parsing and trusted security
configuration after the embedding application selects it. Parsing performs no
filesystem access and produces the same typed `SandboxPolicy` as the Rust
builder. The format has no discovery, inheritance, includes, interpolation, or
implicit authority. The embedding application owns loading and protecting the
source bytes; Sandy retains neither their contents nor their source path.

The CLI may load the same document explicitly through `--policy-file`. This
replaces agent-policy contributions and disables automatic runtime-control
discovery. The CLI remains responsible for fixed typed launcher capabilities,
including the target, working directory, private session, and platform runtime;
these appear in dry-run output and cannot silently override an authored deny.
The CLI protects the policy source's absolute lexical and canonical pathnames.

The facade's optional subprocess capability permits process creation,
same-sandbox inspection and signals, and the platform runtime services needed
to start ordinary descendants. On macOS this includes broad Mach lookup, which
may reach same-user local services even when IP networking is blocked.

Typed capabilities are the only input to policy compilation. Raw native policy
source is not accepted. Unsafe Rust is confined to each backend's private native
wrapper. Native backends add no implicit filesystem or network authority. The
CLI explicitly composes its typed platform runtime baseline before validation.

On Linux, preparation must run while the process is single-threaded. It pins
paths, verifies exact policy representability, exercises namespace setup in a
sacrificial child, and compiles native rules before enforcement. Application
enters private user, mount, and IPC namespaces and a private filesystem view,
then applies Landlock, removes capabilities, and installs seccomp. A preparation
failure leaves the process unchanged. An enforcement failure may leave it
partially restricted, so continuing is unsupported. The private view omits the
host process tree, `/sys`, broad `/run` and `/dev` contents, and the former host
root. The CLI grants only named runtime devices and public proc files. Existing
descriptors remain capabilities. Unsupported hosts and policy combinations fail
rather than receiving approximate enforcement. Landlock signal scoping prevents
the restricted process from signaling processes outside its sandbox domain
while preserving signals among its descendants.

An explicitly selected user profile file is parsed through a narrower schema
than embedded profiles. It can only add required filesystem grants, executable
grants, and terminal denials to one selectable embedded base; it cannot remove
inherited policy or declare integration behavior. Filesystem grants never add
executable authority. The CLI reads from the canonical path selected before
opening and denies both that target and the supplied absolute lexical path
inside the launched sandbox.

The user profile is operator-selected security configuration, not agent input:
it can add host filesystem or executable authority. The operator must trust and
control it. Current-session source denial does not authenticate the document or
prevent a target from altering a writable source before a later launch.

## In scope

- reads and writes outside explicit filesystem grants;
- common sensitive home paths, including SSH, cloud credentials, and Keychains;
- IP networking and connections to ungranted Unix sockets when `--block-net`
  is selected;
- environment-based dynamic-loader and security-routing injection;
- symlink and policy-string injection at launch;
- mutation, removal, or replacement of configured agent control hooks while a
  sandboxed session is running;
- execution before successful validation and native application; and
- restriction inheritance by child processes.

## Out of scope and residual risks

For the Rust facade, resources acquired before `apply` are already inside the
calling process and cannot be revoked by filesystem pathname policy. This
includes environment values, memory, file descriptors, sockets, and other
native handles. Existing threads are outside the portable contract, so callers
must apply before creating them.

- kernel, native sandbox mechanism, or hardware vulnerabilities;
- VM-grade memory or kernel isolation;
- side channels and denial of service;
- data already present in inherited standard streams or explicitly opened file
  descriptors;
- terminal-control ioctls on inherited TTY and PTY descriptors;
- native operations, including applicable ioctls, on explicitly granted device
  files;
- all confused-deputy behavior through allowed Mach/XPC services;
- outbound data disclosure while network is enabled;
- mutation between path canonicalization and later use;
- replacement of a user-profile pathname after trusted preparation, and access
  through a hard-link alias not named by the lexical or canonical source path;
- replacement of a CLI policy-file pathname after trusted preparation, and
  access through an unnamed hard-link alias;
- replacement of an explicitly granted Unix socket after the trusted parent
  verifies its path, type, and owner;
- access to Kontext's exact Unix socket when the integration is active, even
  under `--block-net`;
- access to an explicitly granted IPv4 local-host TCP port on loopback or
  another interface belonging to the Mac, and any same-user process that
  occupies that port, under `--block-net`;
- authenticated provenance for optional Kontext hook events; and
- complete agent behavior visibility through cooperative hook surfaces.

Provider installation has the supply-chain risk of the selected distribution
channel. Kontext installation trusts Homebrew, its configured tap, and the
official Kontext setup flow. Sandy's Numbat installer accepts only the embedded
macOS asset URL for one version, bounds the archive, verifies its embedded
SHA-256 digest, extracts only the named executable as a regular bounded file,
and publishes it without overwriting an existing path. The digest provides
artifact integrity, not publisher identity or revocation. Existing executables
found on `PATH` are operator-selected inputs and are not authenticated by
Sandy.

Agent-visible hook registration and the active self-serve configuration are
intentionally readable and are therefore not confidential from the sandboxed
process tree. In remote mode this surface also includes the cached enforcement
policy required for outage behavior. Their integrity is protected: Sandy
resolves both lexical entries and canonical targets and denies writes. Kontext
credentials, installation identity, databases, logs, and unrelated state remain
outside that readable surface. Kontext setup, repair, and uninstall are trusted
host operations and are not expected to work from inside Sandy. Sandy may invoke
the official setup flow only through the explicit `integrations setup` command.

Compatibility preflight executes the hook-configured Kontext binary in the
trusted parent before Seatbelt is applied. Its deadline and output are bounded,
but Sandy does not authenticate that binary or contain descendants it creates.
Only enable hooks installed through a trusted host workflow.

Kontext compatibility grants read-only filesystem access and a separate
connect-only Unix-socket capability for the verified daemon endpoint. The
lexical `/tmp` path and its canonical `/private/tmp` alias identify the same
endpoint on macOS and are both emitted as exact rules. This does not authorize
socket bind, sibling sockets, IP networking, or a cryptographically bound
session identity.

Numbat compatibility preserves only an already-installed hook or plugin whose
ownership marker and complete generated command or plugin shape Sandy
recognizes. This is format recognition, not binary authentication or a runtime
health check. The configured executable, hook source, and operator rule
directories are readable but protected from writes. Every intermediate
directory below an overlapping writable grant is also pinned, preventing an
agent from relocating a protected registration or rule subtree through an
ancestor rename. Record
output and the sequence-state database must remain writable by the hook; because
the hook and agent share one Seatbelt identity, the agent can also alter,
truncate, fabricate, or remove that data. Sandy therefore does not treat those
files as an audit boundary or claim that Numbat decisions have authenticated
provenance.

The explicit Numbat setup path creates `~/.numbat` and a versioned executable
below `~/Library/Application Support/Sandy/integrations`, then runs Numbat's
idempotent hook installer with an exact file output. Launch-time discovery
never creates those paths or repairs the registration.

Setup rejects symlinks and publishes without overwriting an existing
executable, but its directory checks are pathname-based. Concurrent mutation
by another process running as the same user is outside the `0.1.x` threat
model; setup must not be described as race-free against a hostile same-user
process.

Configured Numbat hooks that deliver directly over HTTP are not supported.
Granting that mode would expose ordinary external networking and potentially
environment-provided delivery credentials to the complete agent process tree.
Sandy neither launches a collector nor moves synchronous hook decisions into an
outside-sandbox service.

`--numbat-collector[=PORT]` is a separate, telemetry-only capability that
requires `--block-net`. It allows TCP connect to one selected port on IPv4
addresses belonging to this Mac, including loopback and non-loopback
interfaces, without authorizing bind, an adjacent port, a Unix socket, IPv6,
or an external IPv4 address. Sandy does not start, probe, authenticate, or
reserve the listener. The agent can forge telemetry, overload the collector,
and connect to another same-user process that races to occupy the selected
port. This endpoint is not a synchronous reference monitor.

Hook-source discovery honors the supported agent configuration-root overrides.
Those values affect both the agent and Sandy and are intentionally preserved in
the child environment. Sandy accepts only absolute, UTF-8, non-root values for
the closed set modeled by typed profiles. The resolved root must already exist,
is granted as agent state, and must not be home-wide or overlap protected data.
Known writable user hook leaves are protected even when absent so one sandboxed
run cannot plant a registration that expands the next run's capabilities.

Agent state directories may contain credentials and are granted for compatible
known-agent profiles. This is a deliberate usability tradeoff and must not be
described as credential isolation.

For network-enabled launches, Sandy supplies a platform public PEM root bundle
through `SSL_CERT_FILE` when the caller did not select another certificate
source. This avoids broader credential-store access. A caller-set bundle
remains subject to the normal filesystem policy; Sandy does not infer a read
grant from an environment variable.

## Fail-closed requirements

An unsupported platform, nested sandbox, malformed or oversized manifest,
invalid path, profile compilation error, native enforcement error, or explicitly
required runtime-control integration failure must prevent target execution. A failure
while preserving an automatically detected optional integration contributes no
runtime-control capabilities, emits a warning, and does not prevent standalone
execution. Sandy never silently retries without enforcement or broadens policy
to recover from a compatibility error.
