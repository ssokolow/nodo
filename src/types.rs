//! Data types shared between the configuration schema and the actual internal APIs

use std::path;

use serde_derive::Deserialize;

pub mod caps;

/// Helper for creating newtypes for string config fields that should not be conflated
///
/// (eg. So it's a compile time error to conflate an `argv[0]` and an `argv[1]` value)
///
/// # Note to Future Maintainers
///
/// Don't implement support for getting the strings back out. Instead, convert the value to be
/// compared into the newtype.
///
/// This makes it more difficult to circumvent the protections afforded by using newtypes and makes
/// apparent the need to do things like normalizing `argv[0]` before checking it.
macro_rules! newtype {
    ($newtype:ident, $docstring:expr) => {
        #[doc = "Newtype for "]
        #[doc=$docstring]
        #[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
        #[serde(try_from = "String")]
        pub struct $newtype(String);

        impl TryFrom<String> for $newtype {
            type Error = &'static str;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                is_bad_name(&value)?;
                Ok($newtype(value))
            }
        }
    };
}

newtype!(FileName, "values like `root_marked_by` (too restrictive for `argv[2]` and beyond)");
newtype!(CommandName, "`argv[0]` as seen by wrapped commands for use as profile names");
newtype!(SubcommandName, "`argv[1]` as seen by wrapped commands for use as subcommand names");

/// Check for end-user misunderstandings in a field expecting a file/command/subcommand name.
///
/// 1. Must not contain a path separator (Don't let users specify a path when a name is expected)
/// 2. Must not contain whitespace (These fields don't take shell-quoted argument lists)
/// 3. Must not contain a null byte (OS APIs can't accept null bytes within strings)
/// 4. Must not be an empty string (Filenames can't be empty and it's better to reject mistakes in
///    subcommand names than to be compatible with such a pathological case)
///
/// # Note to Future Maintainers
///
/// 1. This is private because, if you need to use it without using/creating a newtype in
///    this module, you should probably re-think your design.
///
/// 2. This rejects whitespace because it's better to reject pathological file/command/subcommand
///    names than to accept the *much* more likely case that the user has entered bad data that
///    might present a security vulnerability.
///
///    (How likely are you, really, to intend to support a command like `cargo "make thing" ...`
///    which isn't `["cargo", "make", "thing", ...]` but `["cargo", "make thing", ...]`?)
///
fn is_bad_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("empty string");
    }

    for codepoint in name.chars() {
        #[allow(clippy::else_if_without_else)]
        if path::is_separator(codepoint) {
            return Err("path separator");
        } else if codepoint.is_whitespace() {
            return Err("shell argument list");
        } else if codepoint == '\0' {
            return Err("null byte");
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    /// Assert that creation of of newtypes uses is_bad_name to validate
    ///
    /// (eg. Make sure refactoring doesn't misplace the `?` operator)
    #[test]
    fn newtypes_perform_validation() {
        // Use .to_owned() since I'd need to test the ToOwned<String> implementation either way
        // and YAGNI on a ToOwned<&str> at this time.
        assert!(FileName::try_from("foo-bar".to_owned()).is_ok());
        assert!(FileName::try_from("foo bar".to_owned()).is_err());
        assert!(CommandName::try_from("foo-bar".to_owned()).is_ok());
        assert!(CommandName::try_from("foo bar".to_owned()).is_err());
        assert!(SubcommandName::try_from("foo-bar".to_owned()).is_ok());
        assert!(SubcommandName::try_from("foo bar".to_owned()).is_err());
    }

    /// Assert that is_bad_name rejects supposed filenames/commands/subcommands that are
    /// impossible because they're empty strings or contain binary nulls or path separators
    #[test]
    fn is_bad_name_rejects_impossible_values() {
        assert_eq!(is_bad_name("control"), Ok(()));
        assert_eq!(is_bad_name("control-2"), Ok(()));

        assert_eq!(is_bad_name(""), Err("empty string"));
        assert_eq!(is_bad_name("contains\0null"), Err("null byte"));

        // On Windows, this should test / and \ while, on POSIX platforms, it should do / twice
        assert_eq!(is_bad_name("contrib/do_it"), Err("path separator"));
        assert_eq!(
            is_bad_name(&format!("contrib{}do_it", path::MAIN_SEPARATOR)),
            Err("path separator")
        );
    }

    /// Assert that is_bad_name rejects whitespace to protect against footguns
    #[test]
    fn is_bad_name_whitespace_check_is_thorough() {
        assert_eq!(is_bad_name("control"), Ok(()));
        assert_eq!(is_bad_name("contains space"), Err("shell argument list"));
        assert_eq!(is_bad_name("contains\ttab"), Err("shell argument list"));
        assert_eq!(is_bad_name("contains\nnewline"), Err("shell argument list"));

        // The most misleading case that relying on .is_whitespace() should catch
        assert_eq!(is_bad_name("control-with-dash"), Ok(()));
        assert_eq!(is_bad_name("contains ogham space"), Err("shell argument list"));

        // TODO: Decide how things like U+2800 BRAILLE PATTERN BLANK should be handled,
        // which *appear* to be whitespace but aren't. (Research what others are doing)
    }
}
