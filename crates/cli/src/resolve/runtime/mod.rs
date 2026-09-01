//! Product-owned runtime compatibility policy.

use sandy_core::SandboxPolicy;

use crate::resolve::CliPolicyIntent;

#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;

#[cfg(target_os = "linux")]
pub(crate) fn intent(policy: SandboxPolicy) -> CliPolicyIntent {
    linux::intent(policy)
}

#[cfg(target_os = "macos")]
pub(crate) fn intent(policy: SandboxPolicy) -> CliPolicyIntent {
    macos::intent(policy)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn intent(policy: SandboxPolicy) -> CliPolicyIntent {
    CliPolicyIntent::new(policy)
}
