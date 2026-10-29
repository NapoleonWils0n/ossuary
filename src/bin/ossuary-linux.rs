//==============================================================================
// ossuary-linux
// Description: Mount and unmount encrypted containers on Linux using RAII
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

/// RAII Guard responsible for automatic teardown of Linux loop devices and LUKS 
/// mappings if mounting fails mid-way.
struct LinuxGuard {
    loop_device: Option<String>,
    luks_open: bool,
    luks_name: Option<String>,
}

impl LinuxGuard {
    fn new() -> Self {
        Self {
            loop_device: None,
            luks_open: false,
            luks_name: None,
        }
    }

    /// Disarms the guard when mounting succeeds so automatic cleanup is disabled.
    fn disarm(mut self) {
        self.loop_device = None;
        self.luks_open = false;
        self.luks_name = None;
    }
}

impl Drop for LinuxGuard {
    fn drop(&mut self) {
        // If the LUKS mapping was opened before failure, close it using its dynamic name.
        if self.luks_open {
            if let Some(ref name) = self.luks_name {
                let _ = run_command(&["cryptsetup", "luksClose", name]);
            }
        }
        // If a loop device was attached before failure, detach it.
        if let Some(ref dev) = self.loop_device {
            let _ = run_command(&["losetup", "-d", dev]);
        }
    }
}

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

/// Finds the active loop device associated with the container image (`losetup -j`).
fn find_loop_device_for_container(container: &str) -> Result<String, io::Error> {
    let output = run_and_capture(&["losetup", "-j", container])?;
    if let Some(line) = output.lines().next() {
        if let Some(dev) = line.split(':').next() {
            return Ok(dev.trim().to_string());
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Loop device not found for container."))
}

/// Helper to extract the LUKS UUID from an attached loop device.
fn get_luks_uuid(loop_device: &str) -> Result<String, io::Error> {
    let output = run_and_capture(&["cryptsetup", "luksUUID", loop_device])?;
    let uuid = output.trim().to_string();
    if uuid.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "Failed to retrieve LUKS UUID."));
    }
    Ok(uuid)
}

/// Mounts a LUKS container using its unique LUKS UUID as the device-mapper name.
fn mount_container(container: &str, mountpoint: &str) -> Result<(), io::Error> {
    let mut guard = LinuxGuard::new();

    let loop_device = find_free_loopback_device()?;
    run_command(&["losetup", &loop_device, container])?;
    guard.loop_device = Some(loop_device.clone());

    // Dynamically query the unique LUKS UUID from the container header
    let uuid = get_luks_uuid(&loop_device)?;
    let luks_name = format!("ossuary-{}", uuid);
    guard.luks_name = Some(luks_name.clone());

    // Prompts for passphrase using the unique mapping name
    run_command(&["cryptsetup", "luksOpen", &loop_device, &luks_name])?;
    guard.luks_open = true;

    let mapper_path = format!("/dev/mapper/{}", luks_name);
    run_command(&["mount", &mapper_path, mountpoint])?;

    guard.disarm();
    Ok(())
}

/// Unmounts a LUKS container by dynamically looking up its UUID via its loop device.
fn umount_container(container: &str, mountpoint: &str) -> Result<(), io::Error> {
    // Find the loop device currently bound to this container
    let loop_device = find_loop_device_for_container(container)?;
    
    // Query its UUID so we know the exact device-mapper name to close
    let uuid = get_luks_uuid(&loop_device)?;
    let luks_name = format!("ossuary-{}", uuid);
    let mapper_path = format!("/dev/mapper/{}", luks_name);

    // Reference mapper_path to avoid unused variable warning
    let _ = mapper_path;

    run_command(&["umount", mountpoint])?;
    run_command(&["cryptsetup", "luksClose", &luks_name])?;
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