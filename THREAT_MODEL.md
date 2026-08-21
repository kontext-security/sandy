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
- execution before successful validation and Seatbelt application; and
- restriction inheritance by child processes.

## Out of scope and residual risks

- kernel, Seatbelt, or hardware vulnerabilities;
- VM-grade memory or kernel isolation;
- side channels and denial of service;
- data already present in inherited standard streams or explicitly opened file
  descriptors;
- all confused-deputy behavior through allowed Mach/XPC services;
- outbound data disclosure while network is enabled;
- mutation between path canonicalization and later use;
- authenticated provenance for optional Kontext hook events; and
- complete agent behavior visibility through cooperative hook surfaces.

Agent state directories may contain credentials and are granted for compatible
known-agent profiles. This is a deliberate usability tradeoff and must not be
described as credential isolation.

## Fail-closed requirements

An unsupported platform, nested sandbox, malformed or oversized manifest,
invalid path, profile compilation error, Seatbelt error, or required Kontext
preflight failure must prevent target execution. Sandy never silently retries
without enforcement or broadens policy to recover from a compatibility error.
