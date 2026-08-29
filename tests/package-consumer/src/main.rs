use std::path::Path;

use sandy::{AccessMode, ErrorKind, NetworkPolicy, PathScope, SandboxPolicy};

fn policy_for(workspace: &Path) -> SandboxPolicy {
    SandboxPolicy::new(NetworkPolicy::BlockAll)
        .allow_subprocesses()
        .grant(workspace, AccessMode::ReadWrite, PathScope::Subtree)
        .allow_execute(workspace, PathScope::Subtree)
        .deny_subtree(workspace.join("credentials"))
        .deny_write_exact(workspace.join("settings.json"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = std::env::current_dir()?;
    let policy = policy_for(&workspace);

    #[cfg(not(target_os = "macos"))]
    {
        let error = sandy::apply(policy)
            .err()
            .ok_or("unsupported platform unexpectedly applied the sandbox")?;
        if error.kind() != ErrorKind::Unsupported {
            return Err("unsupported platform returned the wrong Sandy error kind".into());
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _policy = policy;
        let _apply: fn(SandboxPolicy) -> Result<(), sandy::SandboxError> = sandy::apply;
        let _error_kind = ErrorKind::Unsupported;
    }
    Ok(())
}
