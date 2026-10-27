//==============================================================================
// ossuary-openbsd
// Description: Mount and unmount encrypted containers on OpenBSD using RAII
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

/// RAII Guard responsible for automatic teardown of OpenBSD devices if mounting fails mid-way.
struct ContainerGuard {
    vnode: Option<String>,
    sd_device: Option<String>,
}

impl ContainerGuard {
    fn new() -> Self {
        Self {
            vnode: None,
            sd_device: None,
        }
    }

    /// Disarms the guard when mounting succeeds so automatic cleanup is disabled.
    fn disarm(mut self) {
        self.vnode = None;
        self.sd_device = None;
    }
}

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        // If a softraid device was attached before failure, detach it first.
        if let Some(ref sd) = self.sd_device {
            let _ = run_command(&["bioctl", "-d", sd]);
        }
        // If a vnode loopback device was configured before failure, unconfigure it.
        if let Some(ref vnode) = self.vnode {
            let _ = run_command(&["vnconfig", "-u", vnode]);
        }
    }
}


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

/// Helper to find the softraid sd device associated with the newly attached vnode partition.
fn find_softraid_device_for_vnode(vnode_part: &str) -> Result<String, io::Error> {
    let output = run_and_capture(&["bioctl", "softraid0"])?;
    
    // Search from bottom to top (rev) to find the newest matching vnode partition line
    for line in output.lines().rev() {
        if line.contains(vnode_part) {
            for part in line.split_whitespace() {
                if part.starts_with("sd") && part[2..].chars().all(|c| c.is_ascii_digit()) {
                    return Ok(part.to_string());
                }
            }
        }
    }
    
    // Fallback: Search from bottom to top for the most recent CRYPTO volume
    for line in output.lines().rev() {
        if line.contains("CRYPTO") {
            for part in line.split_whitespace() {
                if part.starts_with("sd") && part[2..].chars().all(|c| c.is_ascii_digit()) {
                    return Ok(part.to_string());
                }
            }
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "Softraid device not found for vnode."))
}

/// Mounts the OpenBSD encrypted container utilizing RAII for cleanup.
fn mount_container(container: &str, mountpoint: &str) -> Result<(), io::Error> {
    if !fs::metadata(container).is_ok() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Container file not found: {}", container)));
    }

    if !fs::metadata(mountpoint).is_ok() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Mount point directory does not exist: {}", mountpoint)));
    }

    // Initialize RAII guard
    let mut guard = ContainerGuard::new();

    let vnode = find_free_vnode_device()?;
    let vnode_partition = format!("{}a", vnode);

    // Step 1: Attach container to vnode
    run_command(&["vnconfig", &vnode, container])?;
    guard.vnode = Some(vnode.clone());

    // Step 2: Attach crypto volume via bioctl (prompts for passphrase)
    // If user enters wrong password or bioctl fails, `guard` drops and unconfigures vnode.
    run_command(&["bioctl", "-c", "C", "-l", &vnode_partition, "softraid0"])?;

    // Step 3: Find the created softraid device (e.g., sd2)
    let sd_device = find_softraid_device_for_vnode(&vnode_partition)?;
    guard.sd_device = Some(sd_device.clone());

    let device_partition = format!("/dev/{}a", sd_device);

    // Step 4: Mount the decrypted partition.
    // If mount fails, `guard` drops, detaching softraid and unconfiguring vnode automatically.
    run_command(&["mount", &device_partition, mountpoint])?;

    // Success: Disarm guard so resources remain attached
    guard.disarm();
    Ok(())
}

/// Unmounts the OpenBSD encrypted container:
fn umount_container(container: &str, mountpoint: &str) -> Result<(), io::Error> {
    if !fs::metadata(mountpoint).is_ok() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Mount point directory does not exist: {}", mountpoint)));
    }

    let vnode = find_vnode_for_container(container)?;
    let vnode_partition = format!("{}a", vnode);
    let sd_device = find_softraid_device_for_vnode(&vnode_partition)?;

    run_command(&["umount", mountpoint])?;
    run_command(&["bioctl", "-d", &sd_device])?;
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
