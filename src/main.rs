//! A simple utility for launching build automation tools inside a Firejail sandbox without having
//! to manually create a new profile for each project you work on.
//!
//! This is accomplished by matching the command and subcommand (if applicable) against
//! a list of profiles to identify how the process should be sandboxed and then walking up the
//! filesystem from the current directory, looking for a file or directory specified as defining
//! the root directory for the current project. (eg. "The outermost `Makefile`")

// Copyright (c) 2021,2022 Stephan Sokolow

#![warn(clippy::all, clippy::pedantic, clippy::restriction, clippy::cargo)]
#![allow(
    clippy::implicit_return,
    clippy::needless_return,
    clippy::missing_inline_in_public_items,
    clippy::blanket_clippy_restriction_lints
)]
#![forbid(unsafe_code)] // Delegate anything `unsafe` to Firejail

use std::error::Error;

mod cli;
mod config;
mod types;

fn main() -> Result<(), Box<dyn Error>> {
    let action = cli::parse_args(std::env::args_os());
    if let cli::Action::Exit = action {
        return Ok(());
    }

    let config: config::Config = toml::from_str(config::DEFAULT_CONFIG)?;
    match action {
        cli::Action::PathToConf => {
            if let Some(path) = config::find_path() {
                println!("{}", path.to_string_lossy());
                return Ok(());
            } else {
                eprintln!(
                    "CRITICAL FAILURE: Neither $XDG_CONFIG_HOME nor $HOME/.config are \
                    absolute directory paths."
                );
                std::process::exit(1);
                // TODO: Use a more consistent, less slipshod way to handle non-zero process exit
            };
        },
        cli::Action::WriteConf => todo!(),
        cli::Action::Sandbox(args) => {
            // TODO: Integration test this and use prettier human-readable output
            config.validate().unwrap();

            // TODO: Actually use the config
            println!("{:#?}", config);
            println!("args: {:#?}", args);

            todo!("Split last component off argv[0] and look up profile");
            // TODO: If no profile exists, point the user at the configuration file so they can
            // create one.

            // TODO: Support some kind of --debug flag as the first argument (and only as
            // the first argument) which will display the constructed Firejail command and any
            // other useful information.
        },
        cli::Action::Exit => unreachable!(),
    }
}
