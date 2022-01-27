//! Capabilities (in the "POSIX capabilities" sense) that a configuration file may grant

use serde_derive::Deserialize;

/// Helper for creating newtypes for boolean sandbox permissions that should not be conflated
///
/// The term "capability" is used in the "POSIX Capabilities" sense.
///
/// # Note to Future Maintainers
///
/// 1. Following the convention set by `serde(default)`, the false variant will be the default,
///    so make sure the false variant is the one which grants fewer permissions when adding new
///    calls to this macro.
///
/// 2. Don't implement support for getting the value back out. Instead, convert the value to be
///    compared into the newtype.
///
///    This makes it more difficult to circumvent the protections afforded by using newtypes
///    and makes potential footguns more apparent.
macro_rules! make_capability {
    ($cap_name:ident, $false_variant:ident, $true_variant:ident,
     $cap_desc: expr, $false_desc:expr, $true_desc:expr) => {
        #[doc=$cap_desc]
        #[derive(Copy, Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
        #[serde(from = "bool")]
        pub enum $cap_name {
            #[doc=$false_desc]
            $false_variant,
            #[doc=$true_desc]
            $true_variant,
        }

        impl Default for $cap_name {
            fn default() -> Self {
                Self::$false_variant
            }
        }

        impl From<bool> for $cap_name {
            fn from(value: bool) -> Self {
                if value {
                    Self::$true_variant
                } else {
                    Self::$false_variant
                }
            }
        }
    };
}

make_capability!(Network, ChildProcsOnly, AllNetworks,
    "Scope of network access",
    "Launch the program in its own network namespace so it can only communicate with subprocesses it launches.",
    "Allow unrestricted network communication.");
make_capability!(
    ProjectRoot,
    Innermost,
    Outermost,
    "Policy for identifying the project root directory",
    "Stop looking for the project root at the first match.",
    "Ascend to the filesystem root and then use the most permissive match found."
);

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Deserialize)]
    struct TestFields {
        #[serde(default)]
        network: Network,
        #[serde(default)]
        project_root: ProjectRoot,
    }

    /// Assert that the capability enums err on the side of security when under the influence of
    /// `serde(default)`
    #[test]
    fn caps_have_safe_defaults() {
        let test_values: TestFields = toml::from_str("").unwrap();
        assert_eq!(test_values.network, Network::ChildProcsOnly);
        assert_eq!(test_values.project_root, ProjectRoot::Innermost);
    }

    /// Assert that refactoring hasn't reversed the meanings of the capability enums
    ///
    /// This is mainly to re-state the `make_capability!` definitions in a different form so that,
    /// if a mistake is made, it has to be made twice in two different ways to slip past.)
    #[test]
    fn caps_are_properly_mapped_to_bools() {
        assert_eq!(Network::from(false), Network::ChildProcsOnly);
        assert_eq!(Network::from(true), Network::AllNetworks);
        assert_eq!(ProjectRoot::from(false), ProjectRoot::Innermost);
        assert_eq!(ProjectRoot::from(true), ProjectRoot::Outermost);
    }
}
