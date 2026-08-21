# Sandy

Native macOS sandboxing for AI coding agents. The command is `sandy`.

> [!IMPORTANT]
> This repository currently contains the design for `v0.1.0`. The interface
> below is planned, not yet released.

## Quick start

Run an agent with read/write access to the current project and restricted
access to the rest of the machine:

```bash
sandy run -- claude
sandy run -- codex
```

That is the default product. It does not require Kontext, a daemon, an account,
or a second installation of the agent.

Additional access is explicit:

```bash
# Read another project
sandy run --read ../shared-library -- claude

# Read and write an output directory
sandy run --read-write ~/Downloads/output -- codex

# Disable network access
sandy run --block-net -- cargo test

# Inspect the resolved sandbox without running anything
sandy run --dry-run -- claude
```

The explicit `run -- <command>` boundary is intentional in `v0.1.0`: agent
arguments are passed through unchanged and cannot be confused with sandbox
options.

## Optional Kontext integration

If [Kontext](https://github.com/kontext-security/kontext) is already installed,
one flag enables its existing hooks and runtime governance inside the sandbox:

```bash
sandy run --kontext -- claude
sandy run --kontext -- codex
```

Kontext is entirely opt-in. Without `--kontext`, `sandy` does not locate the
Kontext CLI, contact its daemon, read its configuration, or change the sandbox
policy to accommodate it.

With `--kontext`:

1. the trusted launcher checks the host installation with
   `kontext doctor --json`;
2. it starts the existing user LaunchAgent when it is configured but not yet
   running;
3. it validates the selected agent's hook configuration; and
4. it adds narrow, read-only grants for the installed hook executable and
   policy cache, plus an exact grant for the daemon's Unix socket.

The `kontext` binary remains installed once on the host, normally through
Homebrew. The Kontext daemon remains outside the sandbox. Nothing is copied or
installed into the child process, because Seatbelt restricts ordinary host
processes rather than creating a container filesystem.

```text
standalone

user -> sandy -> sandboxed agent and descendants
           |
           +-> applies Seatbelt before the agent executes

with --kontext

user -> sandy -> sandboxed agent -> existing Kontext hooks
           |                          |
           |                    exact Unix socket
           |                          v
           |                   Kontext daemon
           +-> applies Seatbelt policy and ledger
```

The integration does not grant the child access to Kontext's ledger database,
installation token, Keychain items, or logs. Hook coverage remains distinct
from the kernel boundary: Kontext evaluates supported hook events, while
Seatbelt constrains the process even when an operation has no agent hook.

## Why a separate repository?

The two products have separate responsibilities:

- `sandy` owns process launch and operating-system isolation;
- Kontext owns identity, contextual tool policy, hook decisions, and the
  authorization ledger.

Keeping them separate makes the sandbox useful on its own and lets the current
Kontext repository and installation model remain unchanged.

## Architecture

`v0.1.0` will be a small Rust workspace with one public CLI and a private
Seatbelt wrapper:

```text
sandy (trusted parent, not sandboxed)
  |
  | spawns the same binary in a hidden bootstrap mode
  v
bootstrap (fresh process)
  | validate launch manifest
  | apply Seatbelt
  | report success or a bounded structured error
  v
exec target agent (sandbox inherited by every descendant)
```

The parent resolves commands, paths, profiles, and optional Kontext resources
before launch. A fresh bootstrap process applies Seatbelt and immediately
executes the target. This avoids running general Rust code after `fork()` in a
multithreaded process. The target can never execute if policy generation or
sandbox initialization fails.

The session parent inherits the user's terminal, forwards termination signals,
waits for the agent, and returns its exact exit status. `v0.1.0` does not add a
PTY proxy, detached sessions, or an always-on sandbox daemon.

## `v0.1.0` scope

Included:

- Apple Silicon and Intel macOS;
- built-in Claude Code, Codex, and generic command profiles;
- current-project read/write access for coding-agent profiles;
- canonicalized, explicit additional filesystem grants;
- sandbox inheritance across child processes;
- normal network access by default and an explicit full-network block;
- environment filtering;
- local TOML profiles and resolved-manifest output;
- optional self-serve Kontext integration; and
- fail-closed startup when requested enforcement cannot be applied.

Deferred:

- Linux and Windows;
- organization-managed Kontext installations;
- domain-filtered networking and network proxies;
- credential injection or broad Keychain access;
- dynamic permission expansion;
- filesystem rollback and resource limits;
- detached sessions and PTY attachment; and
- VM-style memory or kernel isolation.

## Security model

The standalone default is deny-first for filesystem access. Coding-agent
profiles allow the current project, required macOS runtime resources, the
agent's narrowly identified runtime state, subprocess execution, terminal use,
and outbound network access. Sensitive locations such as SSH material,
Keychains, and Kontext state remain denied even if a broader parent directory
is granted.

Every path grant is resolved and validated before it enters the Seatbelt
profile. Symlinks, profile-string escaping, inherited file descriptors, Unix
sockets, signal behavior, and sandbox inheritance are security test targets,
not implementation details to assume.

The default network-enabled coding profiles may reach other same-user local
services as well as the Internet. `sandy` strips sensitive inherited endpoints
such as `SSH_AUTH_SOCK` and Kontext routing overrides, but isolation from all
local sockets requires `--block-net`. Shell redirection can also deliberately
hand the child an already-open file descriptor; `sandy` closes inherited file
descriptors other than standard input, output, and error.

Kontext compatibility does not provide cryptographic binding between a process
and hook events. The current local daemon socket trusts same-user clients, and
agent hook coverage is cooperative. `v0.1.0` therefore describes `--kontext`
as compatibility with Kontext governance, not authenticated supervision.

## macOS compatibility

The practical per-process mechanism is Apple's Seatbelt raw-profile interface.
That interface is private and deprecated, so `sandy` must probe it in a
sacrificial process and fail closed on unsupported or already-sandboxed
runtimes. Releases will run live end-to-end tests on supported macOS versions,
including macOS 15 and 26, rather than relying on compilation alone.

## Prior art

[nono](https://github.com/nolabs-ai/nono) demonstrates that native,
capability-based agent sandboxing can have container-free command-line UX.
This project is an original macOS-focused implementation with optional Kontext
interoperability. No nono source code is included.

## Initial milestone

The first milestone is successful end-to-end execution of:

```bash
sandy run -- claude
sandy run --kontext -- claude
```

with verified project access, denied sensitive access, inherited restrictions,
normal terminal behavior, exact exit-status propagation, and no target
execution when sandbox initialization fails.
