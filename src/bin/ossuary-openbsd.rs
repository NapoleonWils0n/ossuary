//==============================================================================
// ossuary-openbsd
// Description: Mount and unmount encrypted containers on Freebsd
// References: [LIB-01], [LIB-02]
//==============================================================================


// Import command-line argument parsing traits and macros from the clap crate
use clap::{Parser, CommandFactory};
// Import filesystem metadata and path handling tools from the standard library
use std::fs;
// Import string handling utilities
use std::str;
// Import standard I/O library types and error handling definitions
use std::io;
// Import threading utilities for timing/sleep operations
use std::thread;
// Import Duration for managing sleep delays between teardown steps
use std::time::Duration;
// Import shared helper functions from library crate
use ossuary::{run_command, run_and_capture};


/// CLI arguments structure parsed via `clap` to handle user input flags.
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Manage Opensbsd encrypted containers",
    after_help = "Examples:\n  mount:\n    ossuary -m mount -f /path/to/container -p /path/to/mountpoint\n\n  umount:\n    ossuary -m umount -f /path/to/container -p /path/to/mountpoint",
    override_usage = "ossuary -m <action> -f <container> -p <mountpoint>"
)]
#[clap(disable_version_flag = true, disable_help_flag = true)]
struct Args {
    /// Action to perform: 'mount' or 'umount'
    #[arg(short = 'm', help = "Action to perform")]
    action: String,

    /// Path to the container disk image file
    #[arg(short = 'f', help = "Path to the container")]
    container: String,

    /// Path to the mountpoint
    #[arg(short = 'p', help = "Path to the mountpoint")]
    mountpoint: String,

    /// Print help
    #[arg(short = 'h', long = "help", action = clap::ArgAction::Help)]
    help: Option<bool>,

    /// Print version
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    version: Option<bool>,
}

/// Verifies that the program is being executed with root (UID 0) privileges.
/// Prints help text and exits with an error if run as a standard user.
fn check_root() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Error: must be run as root.\n");
        let _ = Args::command().print_help();
        println!();
        std::process::exit(1);
    }
}
