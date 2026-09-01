# Linux security model

The Linux backend is one native security boundary shared by the supported Rust
facade and the CLI bootstrap. It adds no product policy, profiles, arguments,
environment values, or implicit filesystem grants.

```text
ValidatedPolicy
      |
      v
LinuxPolicyPlan          deterministic and ambient-free
      |
      v
PreparedLinuxSandbox    pins paths and compiles native rules
      |
      v
apply()                 irreversible current-process transition
```

## Enforcement transaction

Preparation verifies the single-threaded precondition, rejects unsupported
policy combinations, opens policy paths with `openat2`, verifies that
executable grants do not require clearing an inherited host `noexec`, exercises
the namespace and modern mount transaction in a sacrificial child, creates a
hard-required Landlock ruleset, and compiles the seccomp filters. A preparation
failure leaves the process unrestricted.

Application then:

1. enters private user, mount, and IPC namespaces, plus a network namespace
   for `BlockAll`;
2. installs same-ID, one-entry UID and GID maps and makes mount propagation
   private, then replaces the inherited session keyring with a fresh anonymous
   keyring;
3. reopens every grant in the new mount namespace and verifies its device,
   inode, and type against the original pinned object;
4. constructs a private tmpfs root from the verified grants;
5. overlays typed write protections and enters the private root;
6. applies the complete Landlock ruleset and `no_new_privs`;
7. removes ambient, bounding, effective, permitted, and inheritable capabilities;
8. installs seccomp filters that freeze namespace and mount topology and enforce
   subprocess and network-socket creation policy.

An application failure can leave the current process partially restricted. The
caller must terminate immediately. The CLI bootstrap exits without executing
its target.

## Fixed native semantics

Sandy's fixed filesystem and signal-isolation baseline requires Linux 6.12 or
a vendor kernel carrying Landlock ABI 6.
Every accepted policy scopes signal delivery: a sandboxed process may signal
same-domain descendants but cannot signal an unsandboxed parent, sibling, or
other host process. The requirement is hard: a host never receives a weakened
version of a requested policy. A newer host ABI does not silently add
restrictions. Device ioctls on already-open descriptors remain inherited
capabilities.

The host must permit the calling executable to create and configure user,
mount, and IPC namespaces and—when blocking network access—a network namespace.
Some distributions restrict those operations through a system security profile.
Sandy exercises the namespace and modern mount setup in a sacrificial child
during preparation and reports the backend as unsupported when the host denies
it; it never falls back to weaker enforcement. Host administrators must make
the namespace capability available through their normal system security policy.
On Ubuntu, an administrator should authorize user namespaces for the installed
Sandy executable through AppArmor. Disabling
`kernel.apparmor_restrict_unprivileged_userns` is appropriate only for isolated
CI runners because it weakens the restriction system-wide.

System V shared memory, message queues, and semaphores are confined to the
private IPC namespace. Descendants remain able to create and share new IPC
objects inside the sandbox domain; host IPC objects are not visible. Live tests
create a host message queue before application and prove that its identifier is
unusable afterward.

Kernel keyrings are not isolated by an IPC namespace. Sandy therefore replaces
the inherited session keyring with a fresh anonymous ring before hiding the host
filesystem, then permanently denies `add_key`, `request_key`, and `keyctl` with
seccomp. A live test proves a key inherited before application is unreadable
afterward. Key payloads already copied into process memory remain part of the
public current-process residual-risk contract.

Read authority never includes execute authority. The private filesystem marks
non-executable mounts `noexec`; an executable nested below a readable subtree
receives its own executable overmount only when the host mount is executable.
Sandy never clears an inherited `noexec` attribute and rejects an executable
grant that would require doing so. Landlock separately mediates `execve`.
Read/write authority uses a fixed ABI 8 filesystem-mutation set so later kernel
rights do not silently alter the accepted policy.

`BlockAll` uses a private network namespace and denies creation of new
addressable socket descriptors. Exact pathname Unix-socket authority is not in
the initial Linux contract and is rejected during deterministic planning.
Unnamed Unix `socketpair` IPC remains available because it cannot connect to a
host endpoint. Ring setup, entry, and registration are disabled under
`BlockAll` so asynchronous socket operations cannot bypass these controls.
Already-open ordinary descriptors remain caller-held capabilities, matching the
public current-process contract.

`clone3` is rejected with `ENOSYS` so standard libraries can use their legacy
`clone` fallback. Legacy `clone` always rejects namespace flags. When subprocess
creation is disabled it additionally permits only thread-forming clones and
rejects `fork`, `vfork`, `execve`, and `execveat`.

## Filesystem view

The backend pins each source path before enforcement. After namespace entry it
reopens the canonical path and rejects replacement unless device, inode, and
object type still match the original pin. It clones mounts only from those
new-namespace descriptors and attaches them to descriptor-pinned targets in a
private tmpfs root. Non-granted siblings, the host process tree, `/sys`, broad
`/run` contents, and the former host root are absent. Exact selected files may
create otherwise-empty parent directories in the private view. Open descriptors
and memory acquired before `apply()` are not revoked.

An exact protected file is overmounted read-only. Filesystem enforcement is
pathname-based. A protected regular file with a pre-existing hard-link alias is
rejected, and Sandy verifies that its link count does not change between
preparation and namespace entry. Recursive write protections are rejected: a
hard link outside a recursively read-only mount could otherwise mutate the same
inode through a writable pathname.

The following combinations are rejected before enforcement rather than being
weakened:

- a confidential deny nested below a visible subtree, because a mount mask
  would still expose placeholder metadata;
- recursive write protections, because a hard-link alias outside the protected
  subtree could retain write authority;
- exact grants on directories, because native directory rules are hierarchical;
- subtree grants on non-directories;
- exact read/write regular-file grants, because content mutation and
  parent-directory replacement cannot both be represented without broadening
  authority; explicitly named device files are supported;
- exact directory write protections, because pinning a mount point prevents
  replacement but not every metadata mutation;
- pathname Unix-socket exceptions;
- global metadata compatibility;
- local-host-only TCP exceptions.

The private root never mounts procfs. The CLI may bind only explicitly selected
public proc files such as CPU and kernel-version data. A foreground CLI launch
recreates `/proc/self/exe` as a static symlink to the already-visible,
executable primary target. This lets that target identify or re-execute its own
image without adding underlying file authority. Descendants see the primary
target rather than a dynamic per-process link. Process entries,
`/proc/self/fd`, `/dev/fd`, `/dev/shm`, magic links, and the host process tree
remain absent. Programs requiring procfs-backed descriptor paths, dynamic
per-process executable identity, or filesystem-backed shared memory are outside
the initial Linux compatibility contract. Ordinary child processes remain
supported when the typed policy enables them.

When the internal foreground-CLI compatibility capability is present, the
backend recreates a bounded set of host runtime symlinks (`/bin`, `/sbin`,
loader directories, resolver and timezone data, and public CA paths) only when
their canonical targets are already visible through explicit grants. This adds
no underlying file authority; it preserves the runtime spelling selected by
the host distribution.

The requested working directory must be visible through an explicit grant.
Sandy rejects the policy before enforcement rather than silently changing the
working directory to the private root.

CLI dry-run stops after deterministic policy lowering and therefore works on a
host that cannot enter the required namespaces. `sandy doctor` and launch-time
preparation remain the authoritative checks for kernel and host-policy support.

## CLI compatibility boundary

The Linux CLI baseline explicitly grants the system program and library trees,
public certificate and timezone data, selected resolver and account files, and
the small public proc-file set documented in the dry-run policy. Read access and
executable mapping remain separate. It also names `/dev/null`, `/dev/zero`,
`/dev/random`, `/dev/urandom`, and `/dev/tty`; adjacent devices and process
entries are not exposed. A bounded set of host runtime symlinks is
recreated only when its resolved target already has matching authority.

An exact device grant is device authority, not ordinary file authority. In
particular, the CLI's writable `/dev/tty` grant lets interactive programs reopen
their controlling terminal and use the terminal operations permitted by that
device. The live suite proves the named devices work while adjacent devices
such as `/dev/full` and `/dev/ptmx` remain absent.

Host `/sys`, the procfs process tree, and broad `/run` and `/dev` contents are
absent. Standard input, output, error, and an existing controlling terminal
remain native. Linux does not support the CLI's local-host-only TCP exception
or exact external Unix-socket grants in the initial CLI.

Write-protected entries must exist so the backend can pin and overmount them.
The CLI resolves embedded profiles through the shared typed policy model, but
does not perform macOS runtime-control discovery on Linux. Built-in and user
profiles are accepted only when the complete resolved policy is representable;
absent write-protected files beneath a writable grant or a confidential deny
nested inside a writable tree fail before the bootstrap executes the target.
The CLI reports the former as an explicit profile-initialization precondition;
it never creates or silently skips a protected control file.

The Linux CLI accepts `--read-write` only for existing directories. Exact
read-only and executable regular-file grants remain supported; a writable
regular file is rejected before bootstrap with guidance to grant its containing
directory.

The release workflow verifies the packaged x86-64 and arm64 binaries with
`doctor` and a real sandboxed launch on Ubuntu 24.04. The x86-64 artifact is
built on Ubuntu 22.04; that build choice lowers its glibc floor but does not
claim compatibility with every Linux distribution. CI also runs real Node,
Python, and subprocess fixtures. On x86-64 and arm64, CI additionally runs a
pinned native Codex release through its built-in profile. A deterministic local
Responses API drives an agent turn that invokes Codex's command tool. The
fixture proves that the command may write inside the granted project and cannot
write to an adjacent host path; it does not use external credentials or qualify
every interactive terminal path. Native Claude Code and OpenCode releases,
along with common Rust toolchains, can depend on dynamic `/proc/self` paths
omitted by the private root and are outside the initial Linux compatibility
contract.

## Unsafe boundary

All Linux unsafe code and raw native calls are confined to
`crates/linux/src/ffi.rs`. It exposes owned descriptors, lifetime-bound
`BorrowedFd` inputs, and safe functions. Raw pointers, native structures,
unvalidated descriptor integers, and unsafe functions do not escape that
module.
