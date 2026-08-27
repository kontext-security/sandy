use std::path::{Path, PathBuf};

use crate::{
    cli::SupportedAgent,
    error::AppError,
    integration::{IntegrationMode, ResolvedRuntimeControl, kontext},
};

use super::{SetupContext, SetupProvider, find_executable, run_provider_command};

const SERVICE: &str = "Kontext";

pub(super) struct KontextSetup;

impl SetupProvider for KontextSetup {
    fn service(&self) -> &'static str {
        SERVICE
    }

    fn validate_agent(&self, agent: SupportedAgent) -> Result<(), AppError> {
        if agent == SupportedAgent::Opencode {
            return Err(AppError::integration_setup(
                SERVICE,
                "Kontext setup is supported for claude and codex",
            ));
        }
        Ok(())
    }

    fn resolve(
        &self,
        context: &SetupContext,
        mode: IntegrationMode,
    ) -> Result<ResolvedRuntimeControl, AppError> {
        kontext::resolve(&context.hook_sources, mode, &context.paths)
    }

    fn locate(&self, _context: &SetupContext) -> Result<Option<PathBuf>, AppError> {
        find_executable("kontext")
    }

    fn install(&self, _context: &SetupContext) -> Result<PathBuf, AppError> {
        let brew = find_executable("brew")?.ok_or_else(|| {
            AppError::integration_setup(
                SERVICE,
                "Kontext is not installed and Homebrew was not found; install Homebrew or install Kontext, then rerun this command",
            )
        })?;
        run_provider_command(
            SERVICE,
            &brew,
            &["install", "kontext-security/tap/kontext"],
            "Homebrew installation",
        )?;

        find_executable("kontext")?.ok_or_else(|| {
            AppError::integration_setup(
                SERVICE,
                "Homebrew completed but kontext is not available on PATH; add Homebrew's bin directory to PATH and rerun setup",
            )
        })
    }

    fn configure(&self, executable: &Path, _context: &SetupContext) -> Result<(), AppError> {
        // The official setup flow owns authentication, daemon installation,
        // and hook registration. Sandy inherits the terminal so a first-time
        // setup can request its install token without Sandy handling it.
        run_provider_command(SERVICE, executable, &["setup"], "Kontext setup")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opencode_is_rejected_before_host_mutation() {
        assert!(
            KontextSetup
                .validate_agent(SupportedAgent::Opencode)
                .is_err()
        );
        assert!(KontextSetup.validate_agent(SupportedAgent::Claude).is_ok());
        assert!(KontextSetup.validate_agent(SupportedAgent::Codex).is_ok());
    }
}
