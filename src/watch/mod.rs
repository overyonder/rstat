//! The watcher Waybar runs for a section: it subscribes to the daemon and copies each line it sends to
//! standard output.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use crate::section::{Section, daemon_socket_path};

/// # Errors
///
/// Fails if the daemon can't be reached, or when it closes the connection, so Waybar restarts the
/// watcher.
pub fn print_section_updates(section: Section) -> Result<(), Box<dyn std::error::Error>> {
    let path = daemon_socket_path();
    let mut stream = UnixStream::connect(&path).map_err(|error| {
        format!(
            "cannot reach the rstat daemon at {}: {error}",
            path.display()
        )
    })?;
    stream.write_all(format!("{}\n", section.name()).as_bytes())?;
    let mut output = std::io::stdout().lock();
    for line in BufReader::new(stream).lines() {
        writeln!(output, "{}", line?)?;
        output.flush()?;
    }
    Err("the rstat daemon closed the connection".into())
}
