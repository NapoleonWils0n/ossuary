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

