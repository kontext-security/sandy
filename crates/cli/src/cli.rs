use std::{ffi::OsString, path::PathBuf};

use clap::{Args, Parser, Subcommand};

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
    #[command(name = "__bootstrap", hide = true)]
    Bootstrap(BootstrapArgs),
    #[command(name = "__probe", hide = true)]
    Probe,
}

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    /// Force an agent profile (claude, codex, opencode, generic). Without it,
    /// the profile is detected from the command name.
    #[arg(long, value_name = "NAME")]
    pub(crate) profile: Option<String>,

    /// Grant read-only access to an existing path.
    #[arg(long, value_name = "PATH")]
    pub(crate) read: Vec<PathBuf>,

    /// Grant read/write access to an existing path.
    #[arg(long = "read-write", value_name = "PATH")]
    pub(crate) read_write: Vec<PathBuf>,

    /// Block network access for the sandboxed process tree.
    #[arg(long)]
    pub(crate) block_net: bool,

    /// Print the resolved launch and generated policy without executing.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Require an existing healthy Kontext installation.
    #[arg(long)]
    pub(crate) kontext: bool,

    /// Command and arguments. Sandy options must appear before --.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub(crate) target: Vec<OsString>,
}

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {
    /// Also require and validate an existing Kontext installation.
    #[arg(long)]
    pub(crate) kontext: bool,
}

#[derive(Debug, Args)]
pub(crate) struct BootstrapArgs {
    #[arg(long, value_name = "PATH")]
    pub(crate) manifest: PathBuf,
}
