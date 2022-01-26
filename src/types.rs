use std::path;

use serde_derive::Deserialize;

/// Helper for creating newtypes for string config fields that should not be conflated
///
/// (eg. So it's a compile time error to conflate an `argv[0]` and an `argv[1]` value)
///
/// **NOTE:** Don't implement support for getting the strings back out. Instead, convert the value
/// to be compared into the newtype. This makes it more difficult to circumvent the protections and
/// makes apparent the need to do things like normalizing argv[0] before checking it.
macro_rules! try_from_filename {
    ($type:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
        #[serde(try_from = "String")]
        pub struct $type(String);

        impl TryFrom<String> for $type {
            type Error = &'static str;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                is_bad_filename(&value)?;
                Ok($type(value))
            }
        }
    };
}

try_from_filename!(FileName); // Values like `root_marked_by` (too restrictive for argv[2]+)
try_from_filename!(CommandName); // argv[0] for wrapped command
try_from_filename!(SubcommandName); // argv[1] for wrapped command

/// Check for likely misunderstandings in a field expecting a file/command/subcommand name.
///
/// 1. Must not contain a path separator (Don't let users specify a path when a name is expected)
/// 2. Must not contain whitespace (These fields don't take shell-quoted argument lists)
/// 3. Must not be an empty string
fn is_bad_filename(value: &str) -> Result<(), &'static str> {
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

#[cfg(test)]
mod test {
    use super::*;

    /// Assert that creation of of newtypes uses is_bad_filename to validate
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

    /// Assert that is_bad_filename rejects supposed filenames/commands/subcommands that are
    /// impossible because they're empty strings or contain binary nulls or path separators
    #[test]
    fn is_bad_filename_rejects_impossible_values() {
        assert_eq!(is_bad_filename("control"), Ok(()));
        assert_eq!(is_bad_filename("control-2"), Ok(()));

        assert_eq!(is_bad_filename(""), Err("empty string"));
        assert_eq!(is_bad_filename("contains\0null"), Err("null byte"));

        // On Windows, this should test / and \ while, on POSIX platforms, it should do / twice
        assert_eq!(is_bad_filename("contrib/do_it"), Err("path separator"));
        assert_eq!(
            is_bad_filename(&format!("contrib{}do_it", path::MAIN_SEPARATOR)),
            Err("path separator")
        );
    }

    /// Assert that is_bad_filename rejects whitespace to protect against footguns
    #[test]
    fn is_bad_filename_whitespace_check_is_thorough() {
        assert_eq!(is_bad_filename("control"), Ok(()));
        assert_eq!(is_bad_filename("contains space"), Err("shell argument list"));
        assert_eq!(is_bad_filename("contains\ttab"), Err("shell argument list"));
        assert_eq!(is_bad_filename("contains\nnewline"), Err("shell argument list"));

        // The most misleading case that relying on .is_whitespace() should catch
        assert_eq!(is_bad_filename("control-with-dash"), Ok(()));
        assert_eq!(is_bad_filename("contains ogham space"), Err("shell argument list"));

        // TODO: Decide how things like U+2800 BRAILLE PATTERN BLANK should be handled,
        // which *appear* to be whitespace but aren't. (Research what others are doing)
    }
}
