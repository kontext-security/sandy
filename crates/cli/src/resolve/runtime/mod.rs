//! Product-owned runtime compatibility policy.

use sandy_core::NetworkPolicy;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use sandy_core::SandboxPolicy;

use crate::resolve::CliPolicyIntent;

#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;

#[cfg(target_os = "linux")]
pub(crate) fn intent(network: NetworkPolicy) -> CliPolicyIntent {
    linux::intent(network)
}

#[cfg(target_os = "macos")]
pub(crate) fn intent(network: NetworkPolicy) -> CliPolicyIntent {
    macos::intent(network)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn intent(network: NetworkPolicy) -> CliPolicyIntent {
    CliPolicyIntent::new(SandboxPolicy::new(network))
}
