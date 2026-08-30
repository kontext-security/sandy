use std::{ffi::OsString, path::PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "sandy",
    version,
    about = "Native macOS sandboxing for AI coding agents"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Run a command inside a macOS sandbox.
    Run(RunArgs),
    /// Check whether Sandy can enforce a sandbox on this machine.
    Doctor(DoctorArgs),
    /// Install and configure an optional runtime-control integration.
    Integrations(IntegrationsArgs),
    #[command(name = "__bootstrap", hide = true)]
    Bootstrap(BootstrapArgs),
    #[command(name = "__probe", hide = true)]
    Probe,
}

#[derive(Debug, Args)]
pub(crate) struct IntegrationsArgs {
    #[command(subcommand)]
    pub(crate) command: IntegrationCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum IntegrationCommand {
    /// Reuse or install a provider, configure its hooks, and verify the result.
    Setup(IntegrationSetupArgs),
}

#[derive(Debug, Args)]
pub(crate) struct IntegrationSetupArgs {
    /// Runtime-control provider to configure.
    #[arg(value_enum)]
    pub(crate) provider: IntegrationProvider,

    /// Agent registration Sandy must ensure and verify after provider setup.
    #[arg(long, value_enum)]
    pub(crate) agent: SupportedAgent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum IntegrationProvider {
    Kontext,
    Numbat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum SupportedAgent {
    Claude,
    Codex,
    Opencode,
}

impl SupportedAgent {
    #[must_use]
    pub(crate) fn profile_name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Opencode => "opencode",
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    /// Force an agent profile (claude, codex, opencode, generic). Without it,
    /// the profile is detected from the command name.
    #[arg(long, value_name = "NAME")]
    pub(crate) profile: Option<String>,

    /// Load one user-authored session profile. The document must extend one
    /// built-in profile and may add typed filesystem and executable policy.
    #[arg(long, value_name = "PATH", conflicts_with = "profile")]
    pub(crate) profile_file: Option<PathBuf>,

    /// Grant read-only access to an existing path.
    #[arg(long, value_name = "PATH")]
    pub(crate) read: Vec<PathBuf>,

    /// Grant read/write access to an existing path.
    #[arg(long = "read-write", value_name = "PATH")]
    pub(crate) read_write: Vec<PathBuf>,

    /// Allow executable mapping and launch from an existing path.
    ///
    /// This does not grant ordinary file reads or writes.
    #[arg(long, value_name = "PATH")]
    pub(crate) execute: Vec<PathBuf>,

    /// Block IP networking and ungranted Unix-socket connections. An active
    /// Kontext integration retains its exact verified socket connection.
    #[arg(long)]
    pub(crate) block_net: bool,

    /// Print the resolved launch and generated policy without executing.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Require an existing healthy Kontext installation.
    #[arg(long)]
    pub(crate) kontext: bool,

    /// Require an existing supported Numbat hook installation.
    #[arg(long)]
    pub(crate) numbat: bool,

    /// With --block-net, allow one IPv4 TCP port on this Mac for an
    /// operator-started Numbat OTLP/HTTP collector. PORT defaults to 4318.
    #[arg(
        long,
        value_name = "PORT",
        num_args = 0..=1,
        default_missing_value = "4318",
        requires = "block_net"
    )]
    pub(crate) numbat_collector: Option<u16>,

    /// Command and arguments. Sandy options must appear before --.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub(crate) target: Vec<OsString>,
}

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {
    /// Also require and validate an existing Kontext installation.
    #[arg(long)]
    pub(crate) kontext: bool,

    /// Also require and validate an existing Numbat hook installation.
    #[arg(long)]
    pub(crate) numbat: bool,
}

#[derive(Debug, Args)]
pub(crate) struct BootstrapArgs {
    #[arg(long, value_name = "PATH")]
    pub(crate) manifest: PathBuf,
}
