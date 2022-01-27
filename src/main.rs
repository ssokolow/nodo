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

mod config;
mod types;

fn main() -> Result<(), Box<dyn Error>> {
    let config: config::Config = toml::from_str(config::DEFAULT_CONFIG)?;

    // TODO: Integration test this and use prettier human-readable output
    config.validate().unwrap();

    // TODO: Actually use the config
    println!("{:#?}", config);
    Ok(())
}
