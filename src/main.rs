//! A simple utility for launching build automation tools inside a Firejail sandbox without having
//! to manually create a new profile for each project you work on.
//!
//! Copyright (c) 2021,2022 Stephan Sokolow

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

fn main() -> Result<(), Box<dyn Error>> {
    let config: config::Config = toml::from_str(config::DEFAULT_CONFIG)?;

    // TODO: Integration test this
    config.validate();

    // TODO: Actually use the config
    println!("{:#?}", config);
    Ok(())
}
