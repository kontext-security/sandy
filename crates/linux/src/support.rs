use sandy_core::{NetworkPolicy, PolicySpec, ValidatedPolicy};

use crate::{LinuxError, LinuxErrorKind};

/// Minimum Landlock ABI for Sandy's fixed filesystem-rights baseline.
pub const BASELINE_LANDLOCK_ABI: u32 = 5;

/// Landlock ABI required by exact external pathname Unix-socket grants.
pub const PATHNAME_SOCKET_LANDLOCK_ABI: u32 = 9;

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
    let required_abi = required_abi(plan.policy.spec());
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

    let mut handled = AccessFs::from_all(ABI::V8);
    if required_abi == PATHNAME_SOCKET_LANDLOCK_ABI {
        handled |= AccessFs::ResolveUnix;
    }
    let builder = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled)
        .map_err(|_| LinuxError::new(LinuxErrorKind::Unsupported, "support probe"))?;
    let builder = if required_abi == PATHNAME_SOCKET_LANDLOCK_ABI {
        builder
            .scope(Scope::AbstractUnixSocket)
            .map_err(|_| LinuxError::new(LinuxErrorKind::Unsupported, "support probe"))?
    } else {
        builder
    };
    builder
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

fn required_abi(policy: &PolicySpec) -> u32 {
    if policy.network == NetworkPolicy::BlockAll && !policy.unix_sockets.is_empty() {
        PATHNAME_SOCKET_LANDLOCK_ABI
    } else {
        BASELINE_LANDLOCK_ABI
    }
}

#[cfg(test)]
mod tests {
    use sandy_core::{AbsolutePath, UnixSocketGrant, UnixSocketOperation};

    use super::*;

    #[test]
    fn exact_external_socket_authority_raises_only_its_policy_requirement()
    -> Result<(), Box<dyn std::error::Error>> {
        let ordinary = PolicySpec {
            network: NetworkPolicy::BlockAll,
            ..PolicySpec::default()
        };
        assert_eq!(required_abi(&ordinary), BASELINE_LANDLOCK_ABI);

        let with_socket = PolicySpec {
            unix_sockets: vec![UnixSocketGrant {
                path: AbsolutePath::new("/service.sock".to_owned())?,
                operation: UnixSocketOperation::Connect,
            }],
            ..ordinary
        };
        assert_eq!(required_abi(&with_socket), PATHNAME_SOCKET_LANDLOCK_ABI);
        Ok(())
    }
}
