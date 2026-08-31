use sandy_core::ValidatedPolicy;

use crate::{LinuxError, LinuxErrorKind};

/// Landlock ABI whose rights Sandy has fixed and tested.
///
/// ABI 9 is required because pathname Unix-socket connection authority must
/// remain independent from filesystem visibility.
pub const REQUIRED_LANDLOCK_ABI: u32 = 9;

/// Policy-specific host support established without applying restrictions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupportInfo {
    landlock_abi: u32,
}

impl SupportInfo {
    /// Returns the fixed Landlock ABI used by this Sandy build.
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
    let _ = crate::plan(policy)?;
    probe_platform()
}

#[cfg(target_os = "linux")]
fn probe_platform() -> Result<SupportInfo, LinuxError> {
    use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, Scope};

    Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V9))
        .and_then(|ruleset| ruleset.scope(Scope::Signal | Scope::AbstractUnixSocket))
        .and_then(|ruleset| {
            ruleset
                .set_compatibility(CompatLevel::HardRequirement)
                .create()
                .map(|_| ())
        })
        .map_err(|_| LinuxError::new(LinuxErrorKind::Unsupported, "support probe"))?;

    Ok(SupportInfo {
        landlock_abi: REQUIRED_LANDLOCK_ABI,
    })
}

#[cfg(not(target_os = "linux"))]
fn probe_platform() -> Result<SupportInfo, LinuxError> {
    Err(LinuxError::new(
        LinuxErrorKind::Unsupported,
        "support probe",
    ))
}
