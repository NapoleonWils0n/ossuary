//==============================================================================
// ossuary-freebsd
// Description: Mount and unmount encrypted containers on FreeBSD using RAII
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

/// RAII Guard responsible for automatic teardown of FreeBSD memory disks and GELI 
/// encryption layers if mounting fails mid-way.
struct FreeBSDGuard {
    loopdevice: Option<String>,
    loopcrypt: Option<String>,
}

impl FreeBSDGuard {
    fn new() -> Self {
        Self {
            loopdevice: None,
            loopcrypt: None,
        }
    }

    /// Disarms the guard when mounting succeeds so automatic cleanup is disabled.
    fn disarm(mut self) {
        self.loopdevice = None;
        self.loopcrypt = None;
    }
}

impl Drop for FreeBSDGuard {
    fn drop(&mut self) {
        // If GELI provider was attached before failure, detach it first.
        if let Some(ref crypt) = self.loopcrypt {
            let _ = run_command(&["geli", "detach", crypt]);
        }
        // If the mdconfig memory disk was created before failure, destroy it.
        if let Some(ref dev) = self.loopdevice {
            let _ = run_command(&["mdconfig", "-du", dev]);
        }
    }
}

/// CLI arguments structure parsed via `clap` to handle user input flags.
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Manage FreeBSD encrypted containers",
    after_help = "Examples:\n  mount:\n    ossuary -m mount -f /path/to/container -k /path/to/key\n\n  umount:\n    ossuary -m umount -f /path/to/container\n",
    override_usage = "ossuary -m <action> -f <container> [-k <gelikey>]"
)]
#[clap(disable_version_flag = true, disable_help_flag = true)]
struct Args {
    /// Action to perform: 'mount' or 'umount'
    #[arg(short = 'm', help = "Action to perform")]
    action: String,

    /// Path to the container disk image file
    #[arg(short = 'f', help = "Path to the container")]
    container: String,

    /// Path to the GELI encryption key file (required for mount)
    #[arg(short = 'k', help = "Path to the GELI key", required_if_eq("action", "mount"))]
    gelikey: Option<String>,

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

/// Queries active `mdconfig` memory disk devices to find the loop device unit 
/// associated with the target container file. Filters out stale devices by checking 
/// for an active `.eli` provider.
fn get_loop_device(container: &str) -> io::Result<String> {
    let filename = std::path::Path::new(container)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(container);

    let output = run_and_capture(&["mdconfig", "-lv"])?;
    let mut matching_devices = Vec::new();

    for line in output.lines() {
        if line.contains(filename) {
            if let Some(dev) = line.split_whitespace().next() {
                matching_devices.push(dev.to_string());
            }
        }
    }

    // Prefer the device that has an active .eli provider attached (checking newest first)
    for dev in matching_devices.iter().rev() {
        let eli_path = format!("/dev/{}.eli", dev);
        if std::path::Path::new(&eli_path).exists() {
            return Ok(dev.clone());
        }
    }

    // Fallback to the last match if no .eli is found
    if let Some(dev) = matching_devices.last() {
        return Ok(dev.clone());
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "Container not found in mdconfig list."))
}

/// Extracts the ZFS pool name from the encrypted loop device labels using `zdb`.
fn get_pool_name(loopcrypt: &str) -> io::Result<String> {
    let output = run_and_capture(&["zdb", "-l", loopcrypt])?;
    for line in output.lines() {
        if line.contains("name") {
            let parts: Vec<&str> = line.split('\'').collect();
            if parts.len() >= 2 {
                return Ok(parts[1].to_string());
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Failed to query ZFS pool name."))
}

/// Handles the full container mount sequence using the RAII Guard pattern:
/// 1. Validates that the container image and GELI key exist.
/// 2. Attaches the container as a vnode-backed memory disk via `mdconfig`.
/// 3. Attaches encryption using `geli` on the raw device path.
/// 4. Queries the pool name and imports the ZFS pool.
/// If any step fails, the guard automatically cleans up.
fn mount_container(container: &str, gelikey: &str) -> io::Result<()> {
    if !fs::metadata(container).is_ok() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Container file not found: {}", container)));
    }

    if !fs::metadata(gelikey).is_ok() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("GELI key not found: {}", gelikey)));
    }

    // Initialize RAII guard
    let mut guard = FreeBSDGuard::new();

    let loopdevice = run_and_capture(&["mdconfig", "-a", "-t", "vnode", "-f", container])?;
    guard.loopdevice = Some(loopdevice.clone());

    let raw_device = format!("/dev/{}", loopdevice);
    let loopcrypt = format!("/dev/{}.eli", loopdevice);

    run_command(&["geli", "attach", "-k", gelikey, &raw_device])?;
    guard.loopcrypt = Some(loopcrypt.clone());

    let poolname = get_pool_name(&loopcrypt)?;
    run_command(&["zpool", "import", &poolname])?;

    // Success: disarm guard so resources remain active
    guard.disarm();
    Ok(())
}

/// Handles the clean teardown and unmount sequence for an active container:
/// 1. Identifies the active loop device linked to the container.
/// 2. Unmounts the ZFS dataset and exports the zpool.
/// 3. Detaches the GELI encryption layer.
/// 4. Destroys the memory disk (`mdconfig -du`).
fn umount_container(container: &str) -> io::Result<()> {
    let loopdevice = get_loop_device(container)?;
    let loopcrypt = format!("/dev/{}.eli", loopdevice);
    let poolname = get_pool_name(&loopcrypt)?;

    let _ = run_command(&["zfs", "umount", &poolname]);
    run_command(&["zpool", "export", &poolname])?;
    thread::sleep(Duration::from_secs(1));
    run_command(&["geli", "detach", &loopcrypt])?;
    run_command(&["mdconfig", "-du", &loopdevice])?;
    Ok(())
}

/// Main entry point: checks root permissions, parses command line options, 
/// and routes execution to either `mount_container` or `umount_container`.
fn main() {
    check_root();

    let args = Args::parse();

    match args.action.as_str() {
        "mount" => {
            if let Err(e) = mount_container(&args.container, args.gelikey.as_deref().unwrap()) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        "umount" => {
            if let Err(e) = umount_container(&args.container) {
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
