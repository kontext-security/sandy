# Threat model

Sandy reduces the filesystem, network, credential, and local-service access of
a macOS process tree. The protected subject is the host user's data outside the
explicit grants. The target command, its dependencies, generated code, and all
descendants are untrusted.

## Trusted computing base

The trusted base is the Sandy parent and bootstrap, `sandy-core` validation,
the Seatbelt compiler and native wrapper, macOS Seatbelt, and the host kernel.
The selected executable and agent hooks are inside the sandbox and untrusted.
An optional Kontext daemon remains a separate host service.

## Security boundaries

Sandy validates and canonicalizes an entire launch before applying policy. A
fresh bootstrap removes its manifest, applies Seatbelt, and only then executes
the target. Any failure terminates without running the target. Descendants
inherit the resulting restrictions.

Typed capabilities are the only input to policy compilation. Raw Seatbelt
source is not accepted. Unsafe Rust is confined to the private native wrapper
in `sandy-seatbelt`.

## In scope

- reads and writes outside explicit filesystem grants;
- common sensitive home paths, including SSH, cloud credentials, and Keychains;
- network access when `--block-net` is selected;
- environment-based dynamic-loader and security-routing injection;
- symlink and policy-string injection at launch;
- mutation, removal, or replacement of configured agent control hooks while a
  sandboxed session is running;
- execution before successful validation and Seatbelt application; and
- restriction inheritance by child processes.

## Out of scope and residual risks

- kernel, Seatbelt, or hardware vulnerabilities;
- VM-grade memory or kernel isolation;
- side channels and denial of service;
- data already present in inherited standard streams or explicitly opened file
  descriptors;
- terminal-control ioctls on inherited macOS TTY and PTY descriptors;
- all confused-deputy behavior through allowed Mach/XPC services;
- outbound data disclosure while network is enabled;
- mutation between path canonicalization and later use;
- authenticated provenance for optional Kontext hook events; and
- complete agent behavior visibility through cooperative hook surfaces.

Agent-visible hook registration and the active self-serve configuration are
intentionally readable and are therefore not confidential from the sandboxed
process tree. In remote mode this surface also includes the cached enforcement
policy required for outage behavior. Their integrity is protected: Sandy
resolves both lexical entries and canonical targets and denies writes. Kontext
credentials, installation identity, databases, logs, and unrelated state remain
outside that readable surface. Kontext setup, repair, and uninstall are trusted
host operations and are not expected to work from inside Sandy.

Compatibility preflight executes the hook-configured Kontext binary in the
trusted parent before Seatbelt is applied. Its deadline and output are bounded,
but Sandy does not authenticate that binary or contain descendants it creates.
Only enable hooks installed through a trusted host workflow.

Agent state directories may contain credentials and are granted for compatible
known-agent profiles. This is a deliberate usability tradeoff and must not be
described as credential isolation.

## Fail-closed requirements

An unsupported platform, nested sandbox, malformed or oversized manifest,
invalid path, profile compilation error, Seatbelt error, or required Kontext
preflight failure must prevent target execution. A failure while preserving an
automatically detected optional integration contributes no runtime-control
capabilities, emits a warning, and does not prevent standalone execution. Sandy
never silently retries without enforcement or broadens policy to recover from a
compatibility error.
