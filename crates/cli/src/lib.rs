#![forbid(unsafe_code)]

mod agent;
mod app;
mod cli;
mod doctor;
mod error;
mod execution;
mod integration;
mod policy_file;
mod resolve;

use std::process::ExitCode;

use clap::Parser;

use crate::{app::dispatch, cli::Cli};

#[must_use]
pub fn main_entry() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            return exit_code(code);
        }
    };

    match dispatch(cli) {
        Ok(code) => exit_code(code),
        Err(error) => {
            eprintln!("sandy: {error}");
            exit_code(error.exit_code())
        }
    }
}

fn exit_code(code: i32) -> ExitCode {
    let bounded = u8::try_from(code.clamp(0, 255)).unwrap_or(1);
    ExitCode::from(bounded)
}
