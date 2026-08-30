//! Fixed macOS backend rules and explicitly selected compatibility rules.

/// Deny-first profile header shared by every Sandy policy.
pub(crate) const DENY_FIRST_RULES: &str = "\
(version 1)\n\
(deny default)\n";

/// Runtime operations explicitly selected for ordinary subprocess support.
///
/// These rules permit creation and control only within the inherited sandbox;
/// executable mapping remains a separate typed path capability. Broad Mach
/// lookup is a documented compatibility tradeoff; the security-service denies
/// prevent common Keychain APIs from becoming credential deputies.
pub(crate) const SUBPROCESS_RULES: &str = "\
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

/// Compatibility operations explicitly selected by the foreground CLI.
///
pub(crate) const FOREGROUND_CLI_RULES: &str = "\
(allow pseudo-tty)\n\
(allow file-ioctl\n\
    (literal \"/dev/tty\")\n\
    (literal \"/dev/ptmx\")\n\
    (regex #\"^/dev/ttys[0-9]+$\"))\n";
