#![warn(clippy::all, clippy::pedantic, clippy::restriction, clippy::cargo)]
#![allow(
    clippy::implicit_return,
    clippy::needless_return,
    clippy::missing_inline_in_public_items,
    clippy::blanket_clippy_restriction_lints
)]
#![forbid(unsafe_code)] // Delegate anything `unsafe` to Firejail

use std::collections::BTreeMap; // Used to preserve key ordering in Debug output
use std::error::Error;
use std::ops::Not;

use serde_derive::{Deserialize, Serialize};

// TODO: Validate that all Vec<String> fields contain no empty strings
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Deserialize, Serialize)]
/// The schema for a single command's sandboxing profile, with "single command" defined as the
/// value of `argv[0]` when it is being spawned as a subprocess.
struct CommandProfile {
    /// If `true`, allow the sandboxed program unrestricted network communication.
    ///
    /// If `false`, launch the program in its own network namespace so it can only communicate with
    /// subprocesses it launches.
    ///
    /// **NOTE:** It is recommended to leave this set to `false` and selectively override it using
    /// `allow_network_subcommands`.
    ///
    /// **TODO:** Unit test to ensure the default remains `false` when refactoring things
    #[serde(default, skip_serializing_if = "Not::not")]
    allow_network: bool,

    /// A list of subcommands (currently defined as the first argument passed to the command) which
    /// should be allowed unrestricted network access.
    ///
    /// This is useful for commands which must query package repositories or fetch dependencies.
    ///
    /// **TODO:** Decide whether retrofitting smarter subcommand handling later would be
    /// a potential security risk.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allow_network_subcommands: Vec<String>,

    /// If `true`, launch the sandboxed command with the working directory set to the sandbox root.
    ///
    /// This is useful for allowing commands like `make` to be invoked from anywhere within the
    /// project hierarchy.
    #[serde(default, skip_serializing_if = "Not::not")]
    cwd_to_root: bool,

    /// A list of subcommands (currently defined as the first argument passed to the command) which
    /// should be rejected because, not only must they be run un-sandboxed, their effects are
    /// significant enough that the user should explicitly bypass the sandboxing wrapper to
    /// indicate their intent.
    ///
    /// **TODO:** Decide whether retrofitting smarter subcommand handling later would be
    /// a potential security risk.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deny_subcommands: Vec<String>,

    /// A list of subcommands (currently defined as the first argument passed to the command) which
    /// should treat the current working directory as the sandbox root.
    ///
    /// For example, because they are used to create new projects, rather than operate on existing
    /// ones.
    ///
    /// **TODO:** Decide whether retrofitting smarter subcommand handling later would be
    /// a potential security risk.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    projectless_subcommands: Vec<String>,

    /// If any of the file/directory names in this list are present, choose the directory they
    /// appear in to be the root of the sandbox.
    root_marked_by: Vec<String>,

    /// If `false`, treat the nearest ancestor containing one of the `root_marked_by` files or
    /// directories as the sandbox root.
    ///
    /// If `true`, walk all the way up to the filesystem root and then take the last match
    /// encountered to be the sandbox root. (This is useful for systems like Cargo Workspaces which
    /// appear as child projects within a parent project.)
    #[serde(default, skip_serializing_if = "Not::not")]
    root_find_outermost: bool,

    /// A list of subcommand names which should be treated as aliases for other subcommand names
    /// when looking up what sandboxing profile to apply.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    subcommand_aliases: BTreeMap<String, String>,
}

/// The schema for the configuration file which controls sandboxing behaviour
#[derive(Debug, Deserialize, Serialize)]
struct Config {
    /// A default list of root-relative paths to be denied access to
    /// (The idea being to provide an analogue to `chattr +a foo.log`
    /// so `git diff` can be used to reveal shenanigans)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    root_blacklist: Vec<String>,

    /// A list of mappings from command names (`argv[0]`) to the sandboxing profiles to use on them
    #[serde(rename = "profile")]
    profiles: BTreeMap<String, CommandProfile>,
}

fn main() -> Result<(), Box<dyn Error>> {
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    /// Assert that a failure to specify `root_marked_by` will be caught at TOML parsing time
    fn root_marked_by_required() {
        let config: Result<CommandProfile, _> = toml::from_str("");
        assert!(config.is_err());

        let config: CommandProfile = toml::from_str("root_marked_by = [\"Makefile\"]").unwrap();
    }

    /// Assert that the top-level config defaults are as un-surprising as possible
    /// (Important in a security tool)
    #[test]
    fn unsurprising_toplevel_defaults() {
        // TODO: Disallow this in the validation stage
        let config: Config = toml::from_str("profile = {}").unwrap();

        assert!(config.profiles.is_empty());
        assert!(config.root_blacklist.is_empty());
    }

    /// Assert that profile fields not directly related to security have unsurprising
    /// default behaviour
    #[test]
    fn unsurprising_profile_defaults() {
        let profile: CommandProfile = toml::from_str("root_marked_by=[\"foo\"]").unwrap();

        assert_eq!(profile.cwd_to_root, false);
        assert_eq!(profile.root_marked_by, ["foo"]);
    }

    /// Assert that the field defaults for a profile are the most secure options
    #[test]
    fn safe_profile_defaults() {
        let profile: CommandProfile = toml::from_str("root_marked_by=[\"foo\"]").unwrap();

        assert_eq!(profile.allow_network, false);
        assert!(profile.allow_network_subcommands.is_empty());
        assert!(profile.projectless_subcommands.is_empty());
        assert!(profile.subcommand_aliases.is_empty());
        assert_eq!(profile.root_find_outermost, false);
    }
}
