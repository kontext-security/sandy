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
policy combinations, opens policy paths with `openat2`, exercises the namespace
and modern mount transaction in a sacrificial child, creates a hard-required
Landlock ruleset, and compiles the seccomp filters. A preparation failure leaves
the process unrestricted.

Application then:

1. enters a user and mount namespace, plus a network namespace for `BlockAll`;
2. installs same-ID, one-entry UID and GID maps and makes mount propagation
   private;
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

Sandy's fixed filesystem-rights baseline requires Landlock ABI 5. An exact
external pathname Unix-socket grant under `BlockAll` requires ABI 9 so socket
connection authority remains separate from filesystem visibility. The
requirement is policy-specific and hard: a host never receives a weakened
version of a requested policy. A newer host ABI does not silently add
restrictions. The backend does not implicitly restrict signal delivery. Device
ioctls on already-open descriptors remain inherited capabilities.

The host must permit the calling executable to create and configure user,
mount, and—when blocking network access—network namespaces. Some distributions
restrict those operations through a system security profile. Sandy exercises
the namespace and modern mount setup in a sacrificial child during preparation and
reports the backend as unsupported when the host denies it; it never falls back
to weaker enforcement. Host administrators must make the namespace capability
available through their normal system security policy.

Read authority never includes execute authority. Read/write authority uses the
fixed mutation rights through ABI 8 because ABI 9's aggregate write set also
contains pathname-socket resolution. `ResolveUnix` is added only for an exact
typed socket grant.

`BlockAll` uses a private network namespace and denies new externally
addressable non-Unix socket descriptors. When the policy has no pathname
Unix-socket grants, creating addressable sockets is denied without requiring
pathname-socket mediation. A typed external pathname-socket grant enables only
Unix socket creation and requires ABI 9 to limit connections to that exact
path. Unnamed Unix `socketpair` IPC remains available because it cannot connect
to a host endpoint. Ring setup, entry, and registration are disabled under
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
private tmpfs root. Non-granted siblings, host `/proc`, `/sys`, `/run`, and the
former host root are absent. Open descriptors and memory acquired before
`apply()` are not revoked.

An exact protected file is overmounted read-only. A protected subtree is
recursively read-only.

The following combinations are rejected before enforcement rather than being
weakened:

- a confidential deny nested below a visible subtree, because a mount mask
  would still expose placeholder metadata;
- exact grants on directories, because native directory rules are hierarchical;
- subtree grants on non-directories;
- exact read/write file grants, because content mutation and parent-directory
  replacement cannot both be represented without broadening authority;
- exact directory write protections, because pinning a mount point prevents
  replacement but not every metadata mutation;
- global metadata compatibility;
- local-host-only TCP exceptions.

The private root deliberately omits procfs. Product compatibility grants and
any future selective procfs design belong to the CLI boundary and require live
positive and negative tests before shipping.

When the internal foreground-CLI compatibility capability is present, the
backend recreates a bounded set of host runtime symlinks (`/bin`, `/sbin`,
loader directories, timezone data, and the public CA-bundle path) only when
their canonical targets are already visible through explicit grants. This adds
no underlying file authority; it preserves the runtime spelling selected by
the host distribution.

The requested working directory must be visible through an explicit grant.
Sandy rejects the policy before enforcement rather than silently changing the
working directory to the private root.

## Unsafe boundary

All Linux unsafe code and raw native calls are confined to
`crates/linux/src/ffi.rs`. It exposes owned descriptors and safe functions. Raw
pointers, native structures, and unsafe functions do not escape that module.
