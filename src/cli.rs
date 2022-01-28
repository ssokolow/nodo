//! Minimal argument parsing, `--help`, and other CLI routines

use std::ffi::OsString;

/// The action determined to have been requested by [`parse_args`]
#[derive(Debug, Eq, PartialEq)]
pub enum Action {
    /// Just quit. We've already done what needs to be done.
    Exit,
    /// Run the provided command in a sandbox.
    Sandbox(ChildArgs),
    /// Write the active configuration file to disk and output the path written to.
    WriteConf,
    // TODO: Decide on the best way to present a listing of available profiles
}

/// Parsed information that is relevant to launching a sandboxed subprocess
#[derive(Debug, Default, Eq, PartialEq)]
pub struct ChildArgs {
    /// If `true`, print diagnostic output for troubleshooting or refining sandbox profiles
    pub debug: bool,
    /// The command-line to be passed to Firejail after the generated sandboxing directives
    pub child_argv: Vec<OsString>,
}

/// Print the `--help` output to stdout
///
/// # Note to Future Maintainers
///
/// When making any changes to this, check how `help2man --no-info target/debug/nodo | man -l -`
/// interprets it.
///
/// Pay particular attention to how its hard word-wrapping detection can remove line-breaks. (This
/// is why there are two newline characters between each `USAGE` line.)
fn print_help() {
    println!(
        concat!(
            "{wrapper_bin} {wrapper_version}\n",
            "\n",
            "{wrapper_desc}.\n",
            "\n",
            "USAGE:\n",
            "    {wrapper_bin} [--debug|--] <command> [subcommand] [arguments]\n",
            "\n",
            "    {wrapper_bin} [--help|--version|--write-conf]\n",
            "\n",
            "OPTIONS:\n",
            "    --              Don't interpret <command> as an option even if it's --debug\n",
            "    --debug         Print information on the Firejail command being executed and\n",
            "                    omit --quiet so that problems with sandboxing policies can\n",
            "                    be diagnosed.\n",
            "    --help          Print this help message to standard output\n",
            "    --version       Print the version number to standard output\n",
            "    --write-conf    Save the active configuration to a file and report where it \n",
            "                    was saved via stdout.\n",
            "\n",
            "<command> and [subcommand] will be used to look up a sandboxing profile in the\n",
            "configuration file and then <command> [subcommand] [arguments] will be executed as\n",
            "a subprocess inside a Firejail sandbox.\n",
            "\n",
            "Please report any issues at {repo_url}"
        ),
        wrapper_bin = env!("CARGO_BIN_NAME"),
        wrapper_version = env!("CARGO_PKG_VERSION"),
        wrapper_desc = env!("CARGO_PKG_DESCRIPTION"),
        repo_url = env!("CARGO_PKG_REPOSITORY"),
    );
}

/// Helper to abstract away the handful of flags we don't just pass through
///
/// We don't use a command-line argument parsing library because:
///
/// 1. They tend to just be footguns for this kind of wrapper
/// 2. It represents another external dependency that may be vulnerable to a supply-chain attack.
pub fn parse_args(args: impl Iterator<Item = OsString>) -> Action {
    let mut debug = false;
    let mut child_argv: Vec<_> = args.skip(1).collect();

    match child_argv.get(0).map(|x| x.to_string_lossy()).as_deref() {
        Some("--") => {
            // Since we only inspect the first argument for this, removing it is enough
            child_argv.remove(0);
        },
        Some("--debug") => {
            debug = true;
            child_argv.remove(0);
        },
        None | Some("--help" | "-h") => {
            // No arguments, --help, or -h
            print_help();
            return Action::Exit;
        },
        Some("--version") => {
            // Needed by help2man
            println!("{}", env!("CARGO_PKG_VERSION"));
            return Action::Exit;
        },
        Some("--write-conf") => {
            return Action::WriteConf;
        },
        _ => (),
    }

    // Don't let `--` suppress the "help on 'no command provided'" behaviour
    if child_argv.get(0).is_none() {
        print_help();
        return Action::Exit;
    }

    Action::Sandbox(ChildArgs { debug, child_argv })
}

#[cfg(test)]
mod test {
    use super::*;

    /// Helper for applying parse_args to test input more concisely
    macro_rules! test_args {
        ($( $arg:expr ),*) => {
            parse_args([
                OsString::from(env!("CARGO_BIN_NAME")),
                $( OsString::from($arg) ),*
            ].into_iter())
        }
    }

    /// Helper for generating comparison fixtures concisely
    macro_rules! make_expected {
        ($debug:expr, $( $arg:expr ),*) => {
            Action::Sandbox(ChildArgs {
                    debug: $debug,
                    child_argv: vec![$( OsString::from($arg) ),*]
            })
        }
    }

    /// Assert that [`parse_args`] strips the parent command's argv[0]
    #[test]
    fn parse_args_omits_argv0() {
        assert_eq!(
            test_args!("cargo", "run", "--", "--help"),
            make_expected!(false, "cargo", "run", "--", "--help")
        );
    }

    /// Assert that the `--debug` flag behaves as expected
    #[test]
    fn parse_args_debug_field() {
        // --debug sets ChildArgs.debug in position argv[1]
        assert_eq!(
            test_args!("--debug", "cargo", "run", "--", "--help"),
            make_expected!(true, "cargo", "run", "--", "--help")
        );

        // --debug is ignored in other positions
        assert_eq!(
            test_args!("cargo", "--debug", "run", "--", "--help"),
            make_expected!(false, "cargo", "--debug", "run", "--", "--help")
        );
        assert_eq!(
            test_args!("cargo", "run", "--", "--debug"),
            make_expected!(false, "cargo", "run", "--", "--debug")
        );
    }

    /// Assert that [`parse_args`] recognizes the "print and exit" conditions and `--write-conf`
    #[test]
    fn parse_args_recognizes_special_flags() {
        assert_eq!(test_args!(), Action::Exit);
        assert_eq!(test_args!("-h"), Action::Exit);
        assert_eq!(test_args!("--help"), Action::Exit);
        assert_eq!(test_args!("--version"), Action::Exit);
        assert_eq!(test_args!("--write-conf"), Action::WriteConf);
    }

    /// Assert that [`parse_args`] will react to flags if and only if they're the first argument
    #[test]
    fn special_flags_are_positional() {
        // Special flags are ignored outside argv[1]
        assert_eq!(test_args!("foo", "-h"), make_expected!(false, "foo", "-h"));
        assert_eq!(test_args!("foo", "--help"), make_expected!(false, "foo", "--help"));
        assert_eq!(test_args!("foo", "--help"), make_expected!(false, "foo", "--help"));
        assert_eq!(test_args!("foo", "--version"), make_expected!(false, "foo", "--version"));
        assert_eq!(test_args!("foo", "--write-conf"), make_expected!(false, "foo", "--write-conf"));

        // Special flags apply in argv[1] regardless of what follows
        assert_eq!(test_args!("-h", "foo"), Action::Exit);
        assert_eq!(test_args!("-h", "--bar"), Action::Exit);
        assert_eq!(test_args!("-h", "--write-conf"), Action::Exit);
        assert_eq!(test_args!("--help", "foo"), Action::Exit);
        assert_eq!(test_args!("--help", "--bar"), Action::Exit);
        assert_eq!(test_args!("--help", "--write-conf"), Action::Exit);
        assert_eq!(test_args!("--version", "foo"), Action::Exit);
        assert_eq!(test_args!("--version", "--bar"), Action::Exit);
        assert_eq!(test_args!("--version", "--write-conf"), Action::Exit);
        assert_eq!(test_args!("--write-conf", "foo"), Action::WriteConf);
        assert_eq!(test_args!("--write-conf", "--bar"), Action::WriteConf);
        assert_eq!(test_args!("--write-conf", "--help"), Action::WriteConf);
    }

    /// Assert that `--` in the first position allows commands named after flags
    #[test]
    fn doubledash_escapes_flags() {
        assert_eq!(test_args!("--", "-h"), make_expected!(false, "-h"));
        assert_eq!(test_args!("--", "--help"), make_expected!(false, "--help"));
        assert_eq!(test_args!("--", "--version"), make_expected!(false, "--version"));
        assert_eq!(test_args!("--", "--write-conf"), make_expected!(false, "--write-conf"));
    }

    /// Assert that `--` in the first position has no effect on the parsed output when unnecessary
    #[test]
    fn doubledash_is_invisible_in_parsed_output() {
        assert_eq!(test_args!("--"), Action::Exit);
        assert_eq!(test_args!("--", "foo"), test_args!("foo"));

        // ...but not after the first argument, where it's part of the child's arguments
        assert_eq!(test_args!("foo", "--"), test_args!("foo", "--"));
        assert_eq!(test_args!("--", "foo", "--"), test_args!("foo", "--"));
        assert_eq!(test_args!("--", "--"), make_expected!(false, "--"));
    }
}
