use sandy_core::ValidatedPolicy;

use crate::{LinuxError, LinuxErrorKind};

/// Minimum Landlock ABI for Sandy's filesystem and signal-isolation baseline.
pub const BASELINE_LANDLOCK_ABI: u32 = 6;

/// Policy-specific host support established without applying restrictions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupportInfo {
    landlock_abi: u32,
}

impl SupportInfo {
    /// Returns the minimum Landlock ABI required by the supplied policy.
    #[must_use]
    pub const fn landlock_abi(self) -> u32 {
        self.landlock_abi
    }
}

/// Verifies that the running host can represent the supplied policy exactly.
///
/// This is diagnostic only. [`crate::prepare`] repeats every authoritative
/// check and remains the gate before native application.
pub fn probe(policy: &ValidatedPolicy) -> Result<SupportInfo, LinuxError> {
    let plan = crate::plan(policy)?;
    let required_abi = BASELINE_LANDLOCK_ABI;
    #[cfg(target_os = "linux")]
    {
        crate::namespace::prepare(plan.blocks_network())?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = plan;
    probe_platform(required_abi)
}

#[cfg(target_os = "linux")]
fn probe_platform(required_abi: u32) -> Result<SupportInfo, LinuxError> {
    use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, Scope};

    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V8))
        .and_then(|builder| builder.scope(Scope::Signal))
        .map_err(|_| LinuxError::new(LinuxErrorKind::Unsupported, "support probe"))?
        .create()
        .map_err(|_| LinuxError::new(LinuxErrorKind::Unsupported, "support probe"))?;

    Ok(SupportInfo {
        landlock_abi: required_abi,
    })
}

#[cfg(not(target_os = "linux"))]
fn probe_platform(_required_abi: u32) -> Result<SupportInfo, LinuxError> {
    Err(LinuxError::new(
        LinuxErrorKind::Unsupported,
        "support probe",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_baseline_includes_signal_scoping() {
        assert_eq!(BASELINE_LANDLOCK_ABI, 6);
    }
}
