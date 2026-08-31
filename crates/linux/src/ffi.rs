//! Sole Linux unsafe/native boundary.

use std::{
    ffi::{CStr, CString},
    fs::File,
    io,
    mem::size_of,
    os::fd::{FromRawFd, OwnedFd, RawFd},
};

const EMPTY: &CStr = c"";

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub(crate) fn effective_ids() -> (u32, u32) {
    // SAFETY: `geteuid` and `getegid` take no pointers, own no resources, and
    // return process credentials directly.
    unsafe { (libc::geteuid(), libc::getegid()) }
}

pub(crate) fn unshare_namespaces(block_network: bool) -> io::Result<()> {
    let mut flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS;
    if block_network {
        flags |= libc::CLONE_NEWNET;
    }
    // SAFETY: `unshare` receives only a validated fixed flag set. It borrows no
    // pointers and transfers no ownership. Callers enforce the single-threaded
    // process precondition before invoking this irreversible operation.
    cvt(unsafe { libc::unshare(flags) }).map(|_| ())
}

pub(crate) fn make_mounts_private() -> io::Result<()> {
    // SAFETY: all pointers are either null as required by mount(2), or the
    // process-lifetime static C string `/`. No pointer is retained. The flags
    // change propagation only in the already-private mount namespace.
    cvt(unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        )
    })
    .map(|_| ())
}

pub(crate) fn mount_tmpfs(target: &CStr) -> io::Result<()> {
    // SAFETY: `target` and the static source/type/data strings are valid,
    // NUL-terminated for the duration of the call. mount(2) copies them and
    // retains no Rust pointer. The mount is confined to the private namespace.
    cvt(unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            target.as_ptr(),
            c"tmpfs".as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
            c"mode=0700,size=64m".as_ptr().cast(),
        )
    })
    .map(|_| ())
}

pub(crate) fn open_path_at(root: RawFd, relative: &CStr) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: `root` is a borrowed open directory descriptor, `relative` and
    // `how` remain valid for the syscall, and the exact structure size is
    // supplied. On success the returned descriptor is uniquely owned here.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root,
            relative.as_ptr(),
            &how,
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        let raw = i32::try_from(fd).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        // SAFETY: the successful openat2 call returned a fresh descriptor and
        // ownership is transferred exactly once into `OwnedFd`.
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}

pub(crate) fn clone_mount(
    source: RawFd,
    recursive: bool,
    read_only: bool,
    allow_device: bool,
) -> io::Result<OwnedFd> {
    let mut flags = libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC | libc::AT_EMPTY_PATH as u32;
    if recursive {
        flags |= libc::AT_RECURSIVE as u32;
    }
    // SAFETY: `source` is a borrowed O_PATH descriptor. With AT_EMPTY_PATH the
    // empty pathname selects that descriptor; no pointer is retained. A
    // successful open_tree returns a new mount descriptor owned by this call.
    let fd = unsafe { libc::syscall(libc::SYS_open_tree, source, EMPTY.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let raw = i32::try_from(fd).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
    // SAFETY: the successful syscall returned a fresh descriptor and ownership
    // is transferred exactly once.
    let mount_fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let attributes = libc::mount_attr {
        attr_set: libc::MOUNT_ATTR_NOSUID
            | if allow_device {
                0
            } else {
                libc::MOUNT_ATTR_NODEV
            }
            | if read_only {
                libc::MOUNT_ATTR_RDONLY
            } else {
                0
            },
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let attribute_flags = libc::AT_EMPTY_PATH | if recursive { libc::AT_RECURSIVE } else { 0 };
    // SAFETY: the mount descriptor, empty path, and mount_attr pointer remain
    // valid for the syscall; the kernel copies the fixed-size structure and
    // retains no pointer. The detached mount is not externally visible yet.
    let result = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            mount_fd.as_raw_fd(),
            EMPTY.as_ptr(),
            attribute_flags,
            &attributes,
            size_of::<libc::mount_attr>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(mount_fd)
    }
}

pub(crate) fn attach_mount(mount_fd: RawFd, target_fd: RawFd) -> io::Result<()> {
    let flags = libc::MOVE_MOUNT_F_EMPTY_PATH | libc::MOVE_MOUNT_T_EMPTY_PATH;
    // SAFETY: both descriptors are borrowed and valid for the call. Empty
    // pathnames select the descriptors under the matching flags. move_mount
    // consumes the detached mount in the kernel but not the descriptor itself.
    let result = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mount_fd,
            EMPTY.as_ptr(),
            target_fd,
            EMPTY.as_ptr(),
            flags,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn pivot_root(new_root: &CStr, old_root: &CStr) -> io::Result<()> {
    // SAFETY: both paths are valid NUL-terminated strings for the syscall and
    // are copied immediately. The caller has made `new_root` a mount point and
    // created `old_root` beneath it.
    cvt_long(unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), old_root.as_ptr()) })
        .map(|_| ())
}

pub(crate) fn detach_mount(path: &CStr) -> io::Result<()> {
    // SAFETY: `path` is a valid NUL-terminated string for the duration of the
    // call and umount2 retains no pointer.
    cvt(unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) }).map(|_| ())
}

pub(crate) fn drop_all_capabilities(last_capability: u32) -> io::Result<()> {
    const SECURE_BITS: libc::c_ulong = 0x01 | 0x02 | 0x04 | 0x08 | 0x40 | 0x80;

    // SAFETY: prctl receives only integer operations and values, borrows no
    // pointers, and transfers no ownership. CAP_SETPCAP is still effective
    // while the bounding set is reduced.
    cvt(unsafe { libc::prctl(libc::PR_SET_SECUREBITS, SECURE_BITS, 0, 0, 0) })?;
    // SAFETY: this prctl variant has no pointer arguments. It clears the
    // calling thread's ambient set synchronously.
    cvt(unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    })?;
    for capability in 0..=last_capability {
        // SAFETY: this prctl variant has no pointer arguments. Each numeric
        // capability is bounded by the kernel-reported cap_last_cap value.
        cvt(unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) })?;
    }

    let header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [CapData::default(), CapData::default()];
    // SAFETY: the header and two-element data array match Linux's
    // _LINUX_CAPABILITY_VERSION_3 ABI, remain valid for the call, contain no
    // outgoing pointers, and are not retained by the kernel.
    cvt_long(unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) }).map(|_| ())
}

pub(crate) fn verify_no_capabilities() -> io::Result<()> {
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [CapData::default(), CapData::default()];
    // SAFETY: the writable header and data array match Linux's capability ABI,
    // remain uniquely borrowed for the syscall, and are fully initialized.
    cvt_long(unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) })?;
    if data
        .iter()
        .any(|entry| entry.effective != 0 || entry.permitted != 0 || entry.inheritable != 0)
    {
        Err(io::Error::from_raw_os_error(libc::EPERM))
    } else {
        Ok(())
    }
}

pub(crate) fn c_string(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

pub(crate) fn file_from_owned(fd: OwnedFd) -> File {
    File::from(fd)
}

fn cvt(value: libc::c_int) -> io::Result<libc::c_int> {
    if value == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

fn cvt_long(value: libc::c_long) -> io::Result<libc::c_long> {
    if value == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

use std::os::fd::AsRawFd;
