//================================================================================
// lib.rs
// Description: Shared library containing common logic and helper functions
// Version: 0.1.0
//================================================================================

// Import the Command struct to spawn and execute external system processes
use std::process::Command; 

// Import standard I/O library types for handling errors and result wrappers
use std::io; //


/// [LIB-01] run_command
/// Executes a system command with the given arguments and waits for it to finish.
/// Returns `Ok(())` if the command exits with a successful status code (0), 
/// or an `io::Error` with the failed command details if it fails.
pub fn run_command(args: &[&str]) -> io::Result<()> {
    let status = Command::new(args[0])
        .args(&args[1..])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::Other, format!("Command failed: {:?}", args)))
    }
}


/// [LIB-02] run_and_capture
/// Executes a system command with the given arguments, captures its standard output,
/// and returns the trimmed output as a String on success. 
/// Returns an `io::Error` if the command fails or exits with a non-zero status.
pub fn run_and_capture(args: &[&str]) -> io::Result<String> {
    let output = Command::new(args[0])
        .args(&args[1..])
        .output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(io::Error::new(io::ErrorKind::Other, format!("Command failed: {:?}", args)))
    }
}
