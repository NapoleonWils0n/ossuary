//==============================================================================
// ossuary-linux
// Description: Mount and unmount encrypted containers on Linux
// References: [LIB-01], [LIB-02]
//==============================================================================

// Import command-line argument parsing traits and macros from the clap crate
use clap::{Parser, CommandFactory};
// Import string handling utilities
use std::str;
// Import standard I/O library types and error handling definitions
use std::io;
// Import shared helper functions from library crate
use ossuary::{run_command, run_and_capture};

/// CLI arguments structure parsed via `clap` to handle user input flags.
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Manage Linux encrypted containers",
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

/// Finds a free loopback device using losetup -f
fn find_free_loopback_device() -> Result<String, io::Error> {
    let output = run_and_capture(&["losetup", "-f"])?;
    Ok(output.trim().to_string())
}

/// Finds the active loop device associated with the container image (`losetup -j`)[cite: 14].
fn find_loop_device_for_container(container: &str) -> Result<String, io::Error> {
    let output = run_and_capture(&["losetup", "-j", container])?;
    if let Some(line) = output.lines().next() {
        if let Some(dev) = line.split(':').next() {
            return Ok(dev.trim().to_string());
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Loop device not found for container."))
}

/// Mounts a LUKS container
fn mount_container(container: &str, mountpoint: &str) -> Result<(), io::Error> {
    let loop_device = find_free_loopback_device()?;
    run_command(&["losetup", &loop_device, container])?;
    run_command(&["cryptsetup", "luksOpen", &loop_device, "luks"])?;
    run_command(&["mount", "/dev/mapper/luks", mountpoint])?;
    Ok(())
}

/// Unmounts a LUKS container
fn umount_container(container: &str, mountpoint: &str) -> Result<(), io::Error> {
    run_command(&["umount", mountpoint])?;
    run_command(&["cryptsetup", "luksClose", "luks"])?;
    let loop_device = find_loop_device_for_container(container)?;
    run_command(&["losetup", "-d", &loop_device])?;
    Ok(())
}

/// Main entry point: checks root permissions, parses command line options, 
/// and routes execution to either `mount_container` or `umount_container`.
fn main() {
    check_root();

    let args = Args::parse();

    match args.action.as_str() {
        "mount" => {
            if let Err(e) = mount_container(&args.container, &args.mountpoint) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        "umount" => {
            if let Err(e) = umount_container(&args.container, &args.mountpoint) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("Invalid action: {}", args.action);
            std::process::exit(1);
        }
    }
}
