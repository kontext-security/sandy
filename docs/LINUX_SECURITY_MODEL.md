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
policy combinations, opens policy paths with `openat2`, creates a hard-required
Landlock ruleset, and compiles the seccomp filters. A preparation failure leaves
the process unrestricted.

Application then:

1. enters a user and mount namespace, plus a network namespace for `BlockAll`;
2. installs same-ID, one-entry UID and GID maps and makes mount propagation
   private;
3. constructs a private tmpfs root from descriptor-pinned grants;
4. overlays typed write protections and enters the private root;
5. applies the complete Landlock ruleset and `no_new_privs`;
6. removes ambient, bounding, effective, permitted, and inheritable capabilities;
7. installs seccomp filters that freeze namespace and mount topology and enforce
   subprocess and network-socket creation policy.

An application failure can leave the current process partially restricted. The
caller must terminate immediately. The CLI bootstrap exits without executing
its target.

## Fixed native semantics

Sandy requires Landlock ABI 9. The implementation handles the fixed ABI 8
filesystem rights plus ABI 9 pathname Unix-socket resolution and reviewed scope
flags; a newer host ABI does not silently add restrictions. Device ioctls on
already-open descriptors remain inherited capabilities. ABI 9 is required so
pathname Unix-socket connect authority remains separate from filesystem
visibility.

The host must permit the calling executable to create and configure user,
mount, and—when blocking network access—network namespaces. Some distributions
restrict those operations through a system security profile. Sandy exercises
the complete namespace setup in a sacrificial child during preparation and
reports the backend as unsupported when the host denies it; it never falls back
to weaker enforcement. Host administrators must make the namespace capability
available through their normal system security policy.

Read authority never includes execute authority. Read/write authority uses the
fixed mutation rights through ABI 8 because ABI 9's aggregate write set also
contains pathname-socket resolution. `ResolveUnix` is added only for an exact
typed socket grant.

`BlockAll` uses a private network namespace and denies new non-Unix socket file
descriptors. When the policy has no pathname Unix-socket grants, all new socket
file descriptors are denied. Already-open descriptors remain caller-held
capabilities, matching the public current-process contract.

`clone3` is rejected with `ENOSYS` so standard libraries can use their legacy
`clone` fallback. Legacy `clone` always rejects namespace flags. When subprocess
creation is disabled it additionally permits only thread-forming clones and
rejects `fork`, `vfork`, `execve`, and `execveat`.

## Filesystem view

The backend pins each source path before enforcement, clones mounts from those
descriptors, and attaches them to descriptor-pinned targets in a private tmpfs
root. Non-granted siblings, host `/proc`, `/sys`, `/run`, and the former host
root are absent. Open descriptors and memory acquired before `apply()` are not
revoked.

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

The requested working directory must be visible through an explicit grant.
Sandy rejects the policy before enforcement rather than silently changing the
working directory to the private root.

## Unsafe boundary

All Linux unsafe code and raw native calls are confined to
`crates/linux/src/ffi.rs`. It exposes owned descriptors and safe functions. Raw
pointers, native structures, and unsafe functions do not escape that module.
