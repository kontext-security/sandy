//! Explicit host-side lifecycle for optional runtime-control integrations.
//!
//! Launch-time discovery is intentionally read-only. This module is the sole
//! CLI path allowed to install a provider or change its hook registration.

use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{
    cli::{IntegrationCommand, IntegrationProvider, IntegrationsArgs, SupportedAgent},
    error::AppError,
    profile::{self, ResolvedHookSource},
    resolve::{ResolvedUserPaths, resolve_command, resolve_user_paths},
};

use super::{IntegrationMode, ResolvedRuntimeControl};

mod kontext;
mod numbat;

/// Provider-neutral inputs shared by setup and runtime verification.
pub(super) struct SetupContext {
    pub(super) agent: SupportedAgent,
    pub(super) paths: ResolvedUserPaths,
    pub(super) hook_sources: Vec<ResolvedHookSource>,
}

impl SetupContext {
    fn resolve(agent: SupportedAgent) -> Result<Self, AppError> {
        let profile_name = agent.profile_name().to_owned();
        let selected = profile::select(Some(&profile_name), OsStr::new(&profile_name))?;
        let paths = resolve_user_paths(selected.protected_templates())?;
        let hook_sources = selected.hook_sources(&paths)?;
        Ok(Self {
            agent,
            paths,
            hook_sources,
        })
    }
}

/// Provider operations used by the closed host setup lifecycle.
///
/// Provider-specific code owns only location, installation, and configuration.
/// The existing runtime resolver remains the authority for deciding whether the
/// resulting registration is safe to preserve inside Sandy.
trait SetupProvider {
    fn service(&self) -> &'static str;

    fn validate_agent(&self, agent: SupportedAgent) -> Result<(), AppError>;

    fn resolve(
        &self,
        context: &SetupContext,
        mode: IntegrationMode,
    ) -> Result<ResolvedRuntimeControl, AppError>;

    fn locate(&self, context: &SetupContext) -> Result<Option<PathBuf>, AppError>;

    fn install(&self, context: &SetupContext) -> Result<PathBuf, AppError>;

    fn configure(
        &self,
        executable: &std::path::Path,
        context: &SetupContext,
    ) -> Result<(), AppError>;
}

fn find_executable(name: &str) -> Result<Option<PathBuf>, AppError> {
    match resolve_command(&[OsString::from(name)]) {
        Ok(command) => Ok(Some(command.program)),
        Err(AppError::CommandNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn resolve_executable(path: &Path) -> Result<Option<PathBuf>, AppError> {
    match resolve_command(&[OsString::from(path)]) {
        Ok(command) => Ok(Some(command.program)),
        Err(AppError::CommandNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn run_provider_command(
    provider: &'static str,
    executable: &Path,
    arguments: &[&str],
    phase: &'static str,
) -> Result<(), AppError> {
    let status = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|source| AppError::io(format!("{phase} for {provider}"), source))?;
    if !status.success() {
        return Err(AppError::integration_setup(
            provider,
            format!("{phase} exited with {status}"),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SetupOutcome {
    AlreadyConfigured,
    ConfiguredExisting,
    InstalledAndConfigured,
}

pub(crate) fn run(arguments: IntegrationsArgs) -> Result<i32, AppError> {
    if !cfg!(target_os = "macos") {
        return Err(AppError::UnsupportedPlatform);
    }

    let IntegrationCommand::Setup(arguments) = arguments.command;
    let context = SetupContext::resolve(arguments.agent)?;
    let outcome = match arguments.provider {
        IntegrationProvider::Kontext => ensure(&kontext::KontextSetup, &context)?,
        IntegrationProvider::Numbat => ensure(&numbat::NumbatSetup, &context)?,
    };
    let provider = match arguments.provider {
        IntegrationProvider::Kontext => "Kontext",
        IntegrationProvider::Numbat => "Numbat",
    };
    let status = match outcome {
        SetupOutcome::AlreadyConfigured => "was already installed and configured",
        SetupOutcome::ConfiguredExisting => "was already installed and is now configured",
        SetupOutcome::InstalledAndConfigured => "was installed and configured",
    };
    println!(
        "{provider} {status}. Sandy verified the {} registration's runtime capabilities.",
        context.agent.profile_name()
    );
    Ok(0)
}

fn ensure<A: SetupProvider>(
    provider: &A,
    context: &SetupContext,
) -> Result<SetupOutcome, AppError> {
    provider.validate_agent(context.agent)?;

    // A healthy active registration is authoritative evidence. Do not rerun
    // setup or mutate provider-owned configuration merely because the user
    // asked Sandy to ensure it.
    if provider
        .resolve(context, IntegrationMode::Detect)?
        .is_active()
    {
        return Ok(SetupOutcome::AlreadyConfigured);
    }

    if context.paths.home.is_none() {
        return Err(AppError::integration_setup(
            provider.service(),
            "HOME could not be resolved; set HOME to an existing directory before running setup",
        ));
    }

    let (executable, installed) = match provider.locate(context)? {
        Some(executable) => (executable, false),
        None => (provider.install(context)?, true),
    };
    provider.configure(&executable, context)?;

    let verified = provider.resolve(context, IntegrationMode::Required)?;
    if !verified.is_active() {
        return Err(AppError::integration_setup(
            provider.service(),
            "provider setup completed but runtime verification remained inactive",
        ));
    }

    Ok(if installed {
        SetupOutcome::InstalledAndConfigured
    } else {
        SetupOutcome::ConfiguredExisting
    })
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, path::Path};

    use super::*;

    struct FakeProvider {
        active: Cell<bool>,
        located: bool,
        activates_when_configured: bool,
        locate_calls: Cell<usize>,
        install_calls: Cell<usize>,
        configure_calls: Cell<usize>,
    }

    impl FakeProvider {
        fn new(active: bool, located: bool) -> Self {
            Self {
                active: Cell::new(active),
                located,
                activates_when_configured: true,
                locate_calls: Cell::new(0),
                install_calls: Cell::new(0),
                configure_calls: Cell::new(0),
            }
        }
    }

    impl SetupProvider for FakeProvider {
        fn service(&self) -> &'static str {
            "fake"
        }

        fn validate_agent(&self, _agent: SupportedAgent) -> Result<(), AppError> {
            Ok(())
        }

        fn resolve(
            &self,
            _context: &SetupContext,
            mode: IntegrationMode,
        ) -> Result<ResolvedRuntimeControl, AppError> {
            if self.active.get() {
                ResolvedRuntimeControl::active("fake", None, Default::default())
            } else if mode.is_required() {
                Err(AppError::integration_setup("fake", "verification failed"))
            } else {
                Ok(ResolvedRuntimeControl::inactive("fake"))
            }
        }

        fn locate(&self, _context: &SetupContext) -> Result<Option<PathBuf>, AppError> {
            self.locate_calls.set(self.locate_calls.get() + 1);
            Ok(self.located.then(|| PathBuf::from("/existing/fake")))
        }

        fn install(&self, _context: &SetupContext) -> Result<PathBuf, AppError> {
            self.install_calls.set(self.install_calls.get() + 1);
            Ok(PathBuf::from("/installed/fake"))
        }

        fn configure(&self, _executable: &Path, _context: &SetupContext) -> Result<(), AppError> {
            self.configure_calls.set(self.configure_calls.get() + 1);
            self.active.set(self.activates_when_configured);
            Ok(())
        }
    }

    fn context() -> SetupContext {
        SetupContext {
            agent: SupportedAgent::Codex,
            paths: ResolvedUserPaths {
                home: Some(PathBuf::from("/Users/example")),
                protected: Vec::new(),
            },
            hook_sources: Vec::new(),
        }
    }

    fn context_without_home() -> SetupContext {
        SetupContext {
            agent: SupportedAgent::Codex,
            paths: ResolvedUserPaths {
                home: None,
                protected: Vec::new(),
            },
            hook_sources: Vec::new(),
        }
    }

    #[test]
    fn active_provider_is_not_located_or_mutated() -> Result<(), AppError> {
        let provider = FakeProvider::new(true, true);
        assert_eq!(
            ensure(&provider, &context())?,
            SetupOutcome::AlreadyConfigured
        );
        assert_eq!(provider.locate_calls.get(), 0);
        assert_eq!(provider.install_calls.get(), 0);
        assert_eq!(provider.configure_calls.get(), 0);
        Ok(())
    }

    #[test]
    fn existing_provider_is_configured_then_verified() -> Result<(), AppError> {
        let provider = FakeProvider::new(false, true);
        assert_eq!(
            ensure(&provider, &context())?,
            SetupOutcome::ConfiguredExisting
        );
        assert_eq!(provider.locate_calls.get(), 1);
        assert_eq!(provider.install_calls.get(), 0);
        assert_eq!(provider.configure_calls.get(), 1);
        Ok(())
    }

    #[test]
    fn unresolved_home_fails_before_host_mutation() {
        let provider = FakeProvider::new(false, true);
        assert!(ensure(&provider, &context_without_home()).is_err());
        assert_eq!(provider.locate_calls.get(), 0);
        assert_eq!(provider.install_calls.get(), 0);
        assert_eq!(provider.configure_calls.get(), 0);
    }

    #[test]
    fn missing_provider_is_installed_configured_and_verified() -> Result<(), AppError> {
        let provider = FakeProvider::new(false, false);
        assert_eq!(
            ensure(&provider, &context())?,
            SetupOutcome::InstalledAndConfigured
        );
        assert_eq!(provider.locate_calls.get(), 1);
        assert_eq!(provider.install_calls.get(), 1);
        assert_eq!(provider.configure_calls.get(), 1);
        Ok(())
    }

    #[test]
    fn setup_fails_when_the_runtime_resolver_cannot_verify_the_result() {
        let mut provider = FakeProvider::new(false, true);
        provider.activates_when_configured = false;
        assert!(ensure(&provider, &context()).is_err());
        assert_eq!(provider.locate_calls.get(), 1);
        assert_eq!(provider.install_calls.get(), 0);
        assert_eq!(provider.configure_calls.get(), 1);
    }
}
