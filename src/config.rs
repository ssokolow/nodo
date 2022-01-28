//! Configuration file schema and supplementary validation routines

use std::collections::BTreeMap; // Used to ensure deterministic key ordering in Debug output

use serde_derive::Deserialize;

use crate::types::{caps, CommandName, FileName, SubcommandName};

/// The contents of the default configuration file that is used if nothing else is found
///
/// **TODO:** Actually implement support for loading a non-default config file
pub const DEFAULT_CONFIG: &str = include_str!("defaults.toml");

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Deserialize)]
/// The schema for a single command's sandboxing profile, with "single command" defined as the
/// value of `argv[0]` as seen by the subprocess run inside the sandbox.
///
/// For the purposes of these rules, "subcommand" is defined as the value of `argv[1]` as seen by
/// the subprocess run inside the sandbox.
///
/// **TODO:** Decide whether retrofitting smarter subcommand handling **later** would be
/// a potential security risk.
pub struct CommandProfile {
    /// If `true`, allow the sandboxed program unrestricted network communication.
    ///
    /// If `false`, launch the program in its own network namespace so it can only communicate with
    /// subprocesses it launches.
    ///
    /// **NOTE:** It is recommended to leave this set to `false` and selectively override it using
    /// `allow_network_subcommands` if the command has subcommands.
    #[serde(default)]
    allow_network: caps::Network,

    /// A list of subcommands which should be allowed unrestricted network access.
    ///
    /// This is useful for commands which must query package repositories or fetch dependencies.
    #[serde(default)]
    allow_network_subcommands: Vec<SubcommandName>,

    /// A list of subcommands which should be rejected because, not only must they be run
    /// unsandboxed, their effects are significant enough that the user should explicitly bypass
    /// the sandboxing wrapper to indicate their intent.
    #[serde(default)]
    deny_subcommands: Vec<SubcommandName>,

    /// A list of subcommands which should be invoked with the current working directory as the
    /// sandbox root.
    ///
    /// For example, because they are used to create new projects, rather than operate on existing
    /// ones, and will be run in locations where any `root_marked_by` matches will be spurious.
    #[serde(default)]
    projectless_subcommands: Vec<SubcommandName>,

    /// If any of the file/directory names in this list are present, choose the directory they
    /// appear in to be the root of the sandbox.
    root_marked_by: Vec<FileName>,

    /// If `false`, treat the nearest ancestor containing one of the `root_marked_by` files or
    /// directories as the sandbox root.
    ///
    /// If `true`, walk all the way up to the filesystem root and then take the last match
    /// encountered to be the sandbox root. (This is useful for systems like Cargo Workspaces which
    /// appear as child projects within a parent project.)
    #[serde(default)]
    root_find_outermost: caps::ProjectRoot,

    /// A list of subcommand names which should be treated as aliases for other subcommand names
    /// when looking up what sandboxing profile to apply.
    #[serde(default)]
    subcommand_aliases: BTreeMap<SubcommandName, SubcommandName>,
}

/// The schema for the configuration file as a whole
#[derive(Debug, Deserialize)]
pub struct Config {
    /// A list of flags to pass to Firejail before the flags determined by the profile but after
    /// the hard-coded flags generated to do things like blacklisting the sandboxing
    /// configuration file.
    ///
    /// This field must be specified. If you *really* mean to specify a sandbox that's as full of
    /// holes as Swiss cheese, explicitly use an empty list.
    firejail_base_flags: Vec<String>,

    /// A default list of root-relative paths to be denied access to.
    ///
    /// (The idea being to provide an analogue to `chattr +a foo.log` so `git diff` can be used to
    /// reveal attempts by malware inside the sandbox to sneak malicious code into a commit.)
    #[serde(default)]
    root_blacklist: Vec<FileName>,

    /// A list of mappings from command names (`argv[0]`) to the sandboxing profiles to be applied
    #[serde(rename = "profile")]
    profiles: BTreeMap<CommandName, CommandProfile>,
}

impl Config {
    /// Perform validation beyond what Serde is maintainably capable of
    ///
    /// (Implemented manually rather than accepting [validator](https://github.com/Keats/validator)
    /// as another point of trust in a tool meant to enforce security.)
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.profiles.is_empty() {
            return Err("Configuration file must contain at least one profile");
        }
        for profile in self.profiles.values() {
            if profile.root_marked_by.is_empty() {
                return Err("'root_marked_by' must contain at least one file/folder name");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::convert::TryFrom;

    /// Assert that a failure to specify at least one profile or a failure to include
    /// a `root_marked_by` field in the profile will be caught at TOML parsing time
    /// and that `.validate()` will reject empty `Vec`s.
    #[test]
    fn profiles_required() {
        toml::from_str::<Config>("").unwrap_err();
        toml::from_str::<Config>("firejail_base_flags=[]\nprofile = {}")
            .unwrap()
            .validate()
            .unwrap_err();
        toml::from_str::<Config>("firejail_base_flags=[]\n[profile.make]").unwrap_err();
        toml::from_str::<Config>("firejail_base_flags=[]\n[profile.make]\nroot_marked_by = []")
            .unwrap()
            .validate()
            .unwrap_err();
        toml::from_str::<Config>("firejail_base_flags=[]\n[profile.make]\nroot_marked_by = [\"\"]")
            .unwrap_err();
        toml::from_str::<Config>(
            "firejail_base_flags=[]\n[profile.make]\nroot_marked_by=[\"Makefile\"]",
        )
        .unwrap()
        .validate()
        .unwrap();
    }

    /// Assert that the field defaults for a profile are the most secure options
    #[test]
    fn safe_profile_defaults() {
        let profile: CommandProfile = toml::from_str("root_marked_by=[\"foo\"]").unwrap();

        assert_eq!(profile.allow_network, caps::Network::ChildProcsOnly);
        assert!(profile.allow_network_subcommands.is_empty());
        assert!(profile.projectless_subcommands.is_empty());
        assert!(profile.subcommand_aliases.is_empty());
        assert_eq!(profile.root_find_outermost, caps::ProjectRoot::Innermost);
    }

    /// Assert that profile fields not directly related to security have unsurprising
    /// default behaviour
    #[test]
    fn unsurprising_profile_defaults() {
        // Verify that the default for `root_marked_by` isn't going to undermine .validate()
        let profile: CommandProfile = toml::from_str("root_marked_by=[]").unwrap();
        assert_eq!(profile.root_marked_by, []);

        // Verify that `deny_subcommands` isn't going to do something surprising
        let profile: CommandProfile = toml::from_str("root_marked_by=[\"foo\"]").unwrap();
        assert!(profile.deny_subcommands.is_empty());

        // Just to be thorough
        assert_eq!(profile.root_marked_by, [FileName::try_from("foo".to_owned()).unwrap()]);
    }

    /// Assert that the Serde-level defaults for the top-level config, before `.validate()` is run,
    /// aren't going to undermine `.validate()`.
    #[test]
    fn unsurprising_toplevel_defaults() {
        let config: Config = toml::from_str("firejail_base_flags = []\nprofile = {}").unwrap();
        assert!(config.profiles.is_empty());
        assert!(config.root_blacklist.is_empty());
    }

    // TODO: test the validate() methods and ensure they cannot be refactored to `&mut self`
    // (Which would make it easier for the other tests to fall out of sync with what they're
    // supposed to be asserting)
}
