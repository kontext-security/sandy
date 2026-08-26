use crate::error::AppError;
use crate::{
    cli::{Cli, Command},
    doctor, execution, integration,
};

pub(crate) fn dispatch(cli: Cli) -> Result<i32, AppError> {
    match cli.command {
        Command::Run(arguments) => execution::run(arguments),
        Command::Doctor(arguments) => doctor::run(arguments),
        Command::Integrations(arguments) => integration::setup::run(arguments),
        Command::Bootstrap(arguments) => execution::bootstrap(arguments),
        Command::Probe => doctor::probe_child(),
    }
}
