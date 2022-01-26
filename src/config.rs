//! Configuration file schema and validation routines
//!
//! **TODO:** beta-read and improve `cargo doc` output.

use std::collections::BTreeMap; // Used to preserve key ordering in Debug output
use std::ops::Not;
use std::path;

use serde_derive::{Deserialize, Serialize};

/// The contents of the default configuration file that is used if nothing else is found
///
/// **TODO:** Actually implement support for loading a non-default config file
pub const DEFAULT_CONFIG: &str = include_str!("defaults.toml");

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Deserialize, Serialize)]
/// The schema for a single command's sandboxing profile, with "single command" defined as the
/// value of `argv[0]` when it is being spawned as a subprocess.
pub struct CommandProfile {
    /// If `true`, allow the sandboxed program unrestricted network communication.
    ///
    /// If `false`, launch the program in its own network namespace so it can only communicate with
    /// subprocesses it launches.
    ///
    /// **NOTE:** It is recommended to leave this set to `false` and selectively override it using
    /// `allow_network_subcommands`.
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
    /// should be rejected because, not only must they be run unsandboxed, their effects are
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

/// Check for likely misunderstandings in a field expecting a file/command/subcommand name.
///
/// 1. Must not contain a path separator (Don't let users specify a path when a names are expected)
/// 2. Must not contain whitespace (These fields don't take shell-quoted argument lists)
/// 3. Must not be an empty string
///
/// **TODO:** Unit test this (Including a note that the test doesn't currently cover the
/// non-`path::MAIN_SEPARATOR` case that can only be tested on Windows, and a test using the Ogham
/// whitespace character that doesn't look like whitespace since that could cause a desync between
/// how different tools do their whitespace splitting.)
fn is_bad_filename(value: &str) -> Result<(), &str> {
    if value.is_empty() {
        return Err("empty string");
    }

    for codepoint in value.chars() {
        if path::is_separator(codepoint) {
            return Err("path separator");
        } else if codepoint.is_whitespace() {
            // Better to reject pathological file/command/subcommand names than accept bad data
            // which could be potentially be exploited
            //
            // (How likely are you, really, to intend something like `cargo "make thing" ...`?)
            return Err("shell argument list");
        } else if codepoint == '\0' {
            return Err("null byte");
        }
    }

    Ok(())
}

/// Helper for running `is_bad_filename` on all members of an iterable
macro_rules! check_name_list {
    ($list:expr, $msg:literal) => {
        for name in $list {
            is_bad_filename(name)
                .map_err(|err_msg| format!("Expected {}. Found {}: {:?}", $msg, err_msg, name))?
        }
    };
}

impl CommandProfile {
    /// Perform validation beyond what Serde is capable of
    ///
    /// (Implemented manually rather than adding [validator](https://github.com/Keats/validator)
    /// as another point of trust in a tool meant to enforce security.)
    ///
    /// **TODO:** Switch to a better error type and don't stop at the first error.
    fn validate(&self) -> Result<(), String> {
        check_name_list!(&self.root_marked_by, "filename in 'root_marked_by'");
        check_name_list!(self.subcommand_aliases.keys(),
            "subcommand in 'subcommand_aliases' key");
        check_name_list!(self.subcommand_aliases.values(),
            "subcommand in 'subcommand_aliases' value");
        check_name_list!(&self.allow_network_subcommands,
            "subcommand in 'allow_network_subcommands' value");
        check_name_list!(&self.deny_subcommands,
            "subcommand in 'deny_subcommands' value");
        check_name_list!(&self.projectless_subcommands,
            "subcommand in 'projectless_subcommands' value");

        Ok(())
    }
}

/// The schema for the configuration file which controls sandboxing behaviour
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    /// A default list of root-relative paths to be denied access to
    /// (The idea being to provide an analogue to `chattr +a foo.log`
    /// so `git diff` can be used to reveal shenanigans)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    root_blacklist: Vec<String>,

    /// A list of mappings from command names (`argv[0]`) to the sandboxing profiles to use on them
    #[serde(rename = "profile")]
    profiles: BTreeMap<String, CommandProfile>,
}


impl Config {
    /// Perform validation beyond what Serde is capable of
    ///
    /// (Implemented manually rather than adding [validator](https://github.com/Keats/validator)
    /// as another point of trust in a tool meant to enforce security.)
    ///
    /// **TODO:** Switch to a better error type and don't stop at the first error.
    pub fn validate(&self) -> Result<(), String> {
        check_name_list!(&self.root_blacklist, "Expected filename in 'root_blacklist'");
        check_name_list!(self.profiles.keys(), "Expected command name as profile name");

        if self.profiles.is_empty() {
            return Err("Configuration file must contain at least one profile".into());
        }
        for profile in self.profiles.values() {
            profile.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Assert that a failure to specify `root_marked_by` will be caught at TOML parsing time
    #[test]
    fn root_marked_by_required() {
        toml::from_str::<CommandProfile>("").unwrap_err();
        toml::from_str::<CommandProfile>("root_marked_by = [\"Makefile\"]").unwrap();
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

    /// Assert that profile fields not directly related to security have unsurprising
    /// default behaviour
    #[test]
    fn unsurprising_profile_defaults() {
        let profile: CommandProfile = toml::from_str("root_marked_by=[\"foo\"]").unwrap();
        // Just to be thorough
        assert_eq!(profile.root_marked_by, ["foo"]);

        // What we actually care about
        assert_eq!(profile.cwd_to_root, false);
    }

    /// Assert that the Serde-level defaults for the top-level config are as unsurprising
    /// as possible. (Important in a security tool)
    #[test]
    fn unsurprising_toplevel_defaults() {
        let config: Config = toml::from_str("profile = {}").unwrap();
        assert!(config.profiles.is_empty());
        assert!(config.root_blacklist.is_empty());
    }

    // TODO: test the validate() methods and ensure they cannot be refactored to `&mut self`
    // (Which would make it easier for the other tests to fall out of sync with what they're
    // supposed to be asserting)
}
