//==============================================================================
// ossuary-openbsd
// Description: Mount and unmount encrypted containers on OpenBSD
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
// Import shared helper functions from library crate
use ossuary::{run_command, run_and_capture};

/// CLI arguments structure parsed via `clap` to handle user input flags.
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Manage OpenBSD encrypted containers",
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
fn check_root() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Error: must be run as root.\n");
        let _ = Args::command().print_help();
        println!();
        std::process::exit(1);
    }
}

/// Finds a free vnode loopback device using `vnconfig -l`.
fn find_free_vnode_device() -> Result<String, io::Error> {
    let output = run_and_capture(&["vnconfig", "-l"])?;
    for line in output.lines() {
        if line.contains("not in use") || line.contains("unconfigured") {
            let parts: Vec<&str> = line.split(':').collect();
            if let Some(device) = parts.first() {
                return Ok(device.trim().to_string());
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Free vnode device not found."))
}

/// Finds the vnode device currently covering the specified container file.
fn find_vnode_for_container(container: &str) -> Result<String, io::Error> {
    let output = run_and_capture(&["vnconfig", "-l"])?;
    for line in output.lines() {
        if line.contains(container) {
            let parts: Vec<&str> = line.split(':').collect();
            if let Some(device) = parts.first() {
                return Ok(device.trim().to_string());
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Vnode device for container not found."))
}

/// Helper to find the softraid sd device associated with a given vnode partition (e.g., vnd0a).
fn find_softraid_device_for_vnode(vnode_part: &str) -> Result<String, io::Error> {
    let output = run_and_capture(&["bioctl", "softraid0"])?;
    for line in output.lines() {
        if line.contains(vnode_part) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(dev) = parts.last() {
                if dev.starts_with("sd") {
                    return Ok((*dev).to_string());
                }
            }
        }
    }
    // Fallback: scan active softraid devices
    let output_all = run_and_capture(&["bioctl", "softraid0"])?;
    for line in output_all.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(dev) = parts.last() {
            if dev.starts_with("sd") && dev[2:].chars().all(|c| c.is_ascii_digit()) {
                return Ok((*dev).to_string());
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Softraid device not found for vnode."))
}

/// Mounts the OpenBSD encrypted container:
/// 1. Attaches container to a free vnode (e.g., vnd0).
/// 2. Unlocks/attaches softraid crypto volume (`bioctl -c C`).
/// 3. Mounts the decrypted softraid partition (`/dev/sdXa`) to the mountpoint.
fn mount_container(container: &str, mountpoint: &str) -> Result<(), io::Error> {
    if !fs::metadata(container).is_ok() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Container file not found: {}", container)));
    }

    if !fs::metadata(mountpoint).is_ok() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Mount point directory does not exist: {}", mountpoint)));
    }

    let vnode = find_free_vnode_device()?;
    let vnode_partition = format!("{}a", vnode);

    // Attach container to vnode
    run_command(&["vnconfig", &vnode, container])?;

    // Attach crypto volume via bioctl (will prompt for passphrase)
    if let Err(e) = run_command(&["bioctl", "-c", "C", "-l", &vnode_partition, "softraid0"]) {
        let _ = run_command(&["vnconfig", "-u", &vnode]);
        return Err(e);
    }

    // Find the created softraid device (e.g., sd2)
    let sd_device = find_softraid_device_for_vnode(&vnode_partition)?;
    let device_partition = format!("/dev/{}a", sd_device);

    // Mount the decrypted partition
    if let Err(e) = run_command(&["mount", &device_partition, mountpoint]) {
        let _ = run_command(&["bioctl", "-d", &sd_device]);
        let _ = run_command(&["vnconfig", "-u", &vnode]);
        return Err(e);
    }

    Ok(())
}

/// Unmounts the OpenBSD encrypted container:
/// 1. Unmounts the filesystem at the mountpoint.
/// 2. Detaches the softraid crypto volume (`bioctl -d`).
/// 3. Unconfigures the vnd loopback device (`vnconfig -u`).
fn umount_container(container: &str, mountpoint: &str) -> Result<(), io::Error> {
    if !fs::metadata(mountpoint).is_ok() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Mount point directory does not exist: {}", mountpoint)));
    }

    let vnode = find_vnode_for_container(container)?;
    let vnode_partition = format!("{}a", vnode);
    let sd_device = find_softraid_device_for_vnode(&vnode_partition)?;

    // Unmount filesystem
    run_command(&["umount", mountpoint])?;

    // Detach softraid crypto volume
    run_command(&["bioctl", "-d", &sd_device])?;

    // Unconfigure vnode device
    run_command(&["vnconfig", "-u", &vnode])?;

    Ok(())
}

/// Main entry point: checks root permissions, parses arguments, and dispatches action.
fn main() {
    check_root();

    let args = Args::parse();

    match args.action.as_str() {
        "mount" => {
            if let Err(e) = mount_container(&args.container, &args.mountpoint) {
                eprintln!("Error mounting container: {}", e);
                std::process::exit(1);
            }
        }
        "umount" => {
            if let Err(e) = umount_container(&args.container, &args.mountpoint) {
                eprintln!("Error unmounting container: {}", e);
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("Invalid action: Use 'mount' or 'umount'.");
            std::process::exit(1);
        }
    }
}
