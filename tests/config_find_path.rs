//! Tests for `config::find_path` which use `--conf-path` invoked as a subprocess to work around
//! the shortcomings of POSIX environment variables discussed in
//! [rust-lang/rust#90308](https://github.com/rust-lang/rust/issues/90308).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs, io};

/// Helper to set up and tear down test directories
///
/// Feed `line!()` to the first argument to ensure tests don't race with each other
/// without needing to pull in the `rand` crate or read from `/dev/urandom`.
fn with_test_dir(test_id: u32, test_cb: fn(&Path)) {
    let mut test_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    test_dir.push(format!("test_config_find_path_{}", test_id));

    test_dir = ensure_dir(test_dir);
    test_cb(&test_dir);
    fs::remove_dir_all(test_dir).unwrap();
}

/// Helper to `fs::create_dir_all(...).unwrap()` but ignore "already exists" in case a previous
/// test run failed an assertion and left itself un-cleaned-up to help with diagnosis
///
/// Return the path to make the tests using this more concise
fn ensure_dir(path: PathBuf) -> PathBuf {
    fs::create_dir_all(&path)
        .or_else(|e| if e.kind() == io::ErrorKind::AlreadyExists { Ok(()) } else { Err(e) })
        .unwrap();
    path
}

/// Helper to deduplicate the boilerplate of invoking `--conf-path` with a custom environment
/// and working directory
macro_rules! output_for {
    ($cwd:expr, $( $key:ident => $value:expr ),*) => {{
        Command::new(env!("CARGO_BIN_EXE_nodo"))
            .arg("--conf-path")
            .current_dir($cwd)
            .env_clear()
            $(.env(stringify!($key), $value))*
            .output()
            .unwrap()
    }}
}

/// Helper to assert both the status code and the stderr message for failure
///
/// Use a macro so `assert_eq!` and `assert!` report the most useful failure location
macro_rules! assert_failure {
    ($output:expr) => {
        assert_eq!($output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&$output.stderr).starts_with("CRITICAL FAILURE:"));
    };
}

/// Helper to assert both the status code and the expected output for success
///
/// Use a macro so `assert_eq!` reports the most useful failure location
macro_rules! assert_success {
    ($output:expr, $test_dir:expr) => {
        assert_eq!($output.status.code(), Some(0));
        assert_eq!(
            String::from_utf8_lossy(&$output.stdout),
            $test_dir.join(format!("{}.toml\n", env!("CARGO_PKG_NAME"))).to_string_lossy()
        );
    };
}

#[test]
/// Assert that the `.is_absolute()` calls are rejecting empty strings
fn rejects_empty_paths() {
    with_test_dir(line!(), |test_dir: &Path| {
        // Control
        let config = ensure_dir(test_dir.join(".config"));
        assert_success!(output_for!(test_dir, HOME => test_dir), config);
        assert_success!(output_for!(test_dir, XDG_CONFIG_HOME => test_dir), test_dir);

        // Test
        assert_failure!(output_for!(test_dir, HOME => ""));
        assert_failure!(output_for!(test_dir, XDG_CONFIG_HOME => "", HOME => ""));
        // NOTE: Can't expect failure with HOME unset without LD_PRELOAD mocking `getpwuid_r`.
    });
}

#[test]
/// Assert that `config::find_path` rejects relative paths in accordance with the XDG Base
/// Directory specification (and simply as proper practice for a security tool).
fn rejects_relative_paths() {
    with_test_dir(line!(), |test_dir: &Path| {
        // Control
        let config = ensure_dir(test_dir.join(".config"));
        assert_success!(output_for!(test_dir, HOME => test_dir), config);
        assert_success!(output_for!(test_dir, XDG_CONFIG_HOME => test_dir), test_dir);

        // With `./`
        assert_failure!(output_for!(test_dir, HOME => "."));
        assert_failure!(output_for!(test_dir, XDG_CONFIG_HOME => "./config", HOME => "."));

        // Without `./`
        let foo = test_dir.join("foo");
        ensure_dir(foo.join(".config"));
        assert_failure!(output_for!(test_dir, HOME => "foo"));
        assert_failure!(output_for!(test_dir, XDG_CONFIG_HOME => "foo/.config", HOME => "foo"));
        // NOTE: Can't expect failure with HOME unset without LD_PRELOAD mocking `getpwuid_r`.
    });
}

#[test]
/// Assert that `config::find_path` rejects nonexistent paths since, as a security tool, we don't
/// want to "make it fit" by creating them
fn rejects_nonexistent_paths() {
    with_test_dir(line!(), |test_dir: &Path| {
        // Control
        let config = ensure_dir(test_dir.join(".config"));
        let foo = ensure_dir(test_dir.join("foo"));
        assert_success!(output_for!(test_dir, HOME => test_dir), config);
        assert_success!(output_for!(test_dir, XDG_CONFIG_HOME => &foo, HOME => &test_dir), foo);

        fs::remove_dir(&config).unwrap();
        fs::remove_dir(&foo).unwrap();
        assert_failure!(output_for!(test_dir, HOME => &test_dir));
        assert_failure!(output_for!(test_dir, XDG_CONFIG_HOME => &foo, HOME => &test_dir));
        // NOTE: Can't expect failure with HOME unset without LD_PRELOAD mocking `getpwuid_r`.
    });
}

#[test]
/// Assert that `config::find_path` rejects paths leading to files rather than directories
fn rejects_file_paths() {
    with_test_dir(line!(), |test_dir: &Path| {
        let config = test_dir.join(".config");
        let foo = test_dir.join("foo");
        fs::write(&config, "Test File 1").unwrap();
        fs::write(&foo, "Test File 2").unwrap();

        assert_failure!(output_for!(test_dir, HOME => &test_dir));
        assert_failure!(output_for!(test_dir, XDG_CONFIG_HOME => &foo, HOME => &test_dir));
        // NOTE: Can't expect failure with HOME unset without LD_PRELOAD mocking `getpwuid_r`.
    });
}

#[test]
/// Assert that `config::find_path` returns the intended output for valid paths
fn accepts_valid_paths() {
    with_test_dir(line!(), |test_dir: &Path| {
        let foo = ensure_dir(test_dir.join("foo"));
        let foo_config = ensure_dir(foo.join(".config"));
        let config = ensure_dir(test_dir.join(".config"));
        assert_success!(output_for!(test_dir, HOME => test_dir), config);
        assert_success!(output_for!(test_dir, XDG_CONFIG_HOME => &foo, HOME => &test_dir), foo);

        assert_success!(output_for!(test_dir, HOME => &foo), &foo_config);
        assert_success!(
            output_for!(test_dir, XDG_CONFIG_HOME => &test_dir, HOME => &test_dir),
            &test_dir
        );

        // NOTE: *CAN* test unset HOME if expecting success with a set XDG_CONFIG_HOME
        assert_success!(output_for!(test_dir, XDG_CONFIG_HOME => &foo), foo);
        assert_success!(output_for!(test_dir, XDG_CONFIG_HOME => &test_dir), &test_dir);
    });
}

#[test]
/// Assert that an invalid `$XDG_CONFIG_HOME` will fall back to a valid `$HOME` properly
fn fallback_on_invalid() {
    with_test_dir(line!(), |test_dir: &Path| {
        let foo = ensure_dir(test_dir.join("foo"));
        let foo_config = ensure_dir(foo.join(".config"));
        let bar = test_dir.join("bar");
        let baz = test_dir.join("baz");
        fs::write(&baz, "Test File").unwrap();

        assert_success!(
            // Empty
            output_for!(test_dir, XDG_CONFIG_HOME => "", HOME => &foo),
            &foo_config
        );
        assert_success!(
            // Relative dotdir
            output_for!(test_dir, XDG_CONFIG_HOME => ".", HOME => &foo),
            &foo_config
        );
        assert_success!(
            // Relative non-dotdir
            output_for!(test_dir, XDG_CONFIG_HOME => ".config", HOME => &foo),
            &foo_config
        );
        assert_success!(
            // Nonexistent
            output_for!(test_dir, XDG_CONFIG_HOME => &bar, HOME => &foo),
            &foo_config
        );
        assert_success!(
            // File, not directory
            output_for!(test_dir, XDG_CONFIG_HOME => &baz, HOME => &foo),
            &foo_config
        );
    });
}

// TODO: Decide where std::fs::canonicalize fits into the intended semantics
// (We want to canonicalize it before handing off to Firejail, but it might be surprising and/or
// confusing if the text displayed to the user doesn't match what's in XDG_CONFIG_HOME or HOME)
