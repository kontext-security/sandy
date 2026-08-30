//! Fixed macOS compatibility rules shared by every Sandy policy.
//!
//! These rules are part of the Seatbelt backend rather than user- or agent-selectable
//! capabilities. They contain no caller-provided values; dynamic policy values continue to pass
//! through the compiler's single escaping path.

/// Static SBPL operations required for ordinary foreground command execution.
///
/// The profile starts deny-first and permits process control only within the inherited sandbox.
/// Broad Mach lookup is a documented compatibility tradeoff; the explicit security-service
/// denials prevent common Keychain APIs from becoming credential deputies.
pub(crate) const STATIC_RULES: &str = "\
(version 1)\n\
(deny default)\n\
(allow process-exec*)\n\
(allow process-fork)\n\
(allow process-info* (target self))\n\
(allow process-info* (target same-sandbox))\n\
(allow signal (target self))\n\
(allow signal (target same-sandbox))\n\
(allow sysctl-read)\n\
(allow mach-lookup)\n\
(deny mach-lookup (global-name \"com.apple.SecurityServer\"))\n\
(deny mach-lookup (global-name \"com.apple.securityd\"))\n\
(deny mach-lookup (global-name \"com.apple.securityd.xpc\"))\n\
(deny mach-lookup (global-name \"com.apple.securityd.general\"))\n\
(deny mach-lookup (global-name \"com.apple.securityd.systemkeychain\"))\n\
(deny mach-lookup (global-name \"com.apple.security.keychaind\"))\n\
(deny mach-lookup (global-name \"com.apple.secd\"))\n\
(deny mach-lookup (global-name \"com.apple.security.agent\"))\n\
(allow mach-per-user-lookup)\n\
(allow mach-task-name)\n\
(deny mach-priv*)\n\
(allow ipc-posix-shm-read-data)\n\
(allow ipc-posix-shm-write-data)\n\
(allow ipc-posix-shm-write-create)\n\
(allow system-fsctl)\n\
(allow system-info)\n";

/// Terminal operations required to preserve native foreground terminal behavior.
///
/// The device pattern remains narrow, and its adjacent-negative live test proves unrelated device
/// ioctls stay denied. Issue #4 tracks replacing the pattern with an exact typed device.
pub(crate) const FOREGROUND_TERMINAL_RULES: &str = "\
(allow pseudo-tty)\n\
(allow file-ioctl\n\
    (literal \"/dev/tty\")\n\
    (literal \"/dev/ptmx\")\n\
    (regex #\"^/dev/ttys[0-9]+$\"))\n";
