//! rstat: a low-overhead Linux system monitor for Waybar.
//!
//!   rstat daemon [--config PATH]           sample the sections watchers ask for and serve their output
//!   rstat watch cpu|memory|disks|network|gpu   print one section's Waybar JSON line on every change

use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let result = match arguments.as_slice() {
        ["daemon"] => rstat::daemon::serve_sections_to_watchers(None),
        ["daemon", "--config", path] => rstat::daemon::serve_sections_to_watchers(Some(path.as_ref())),
        ["watch", name] => rstat::section::Section::from_name(name).map_or_else(
            || Err(format!("unknown section {name}: use cpu, memory, disks, network or gpu").into()),
            rstat::watch::print_section_updates,
        ),
        _ => Err("usage: rstat daemon [--config PATH] | rstat watch SECTION".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rstat: {error}");
            ExitCode::FAILURE
        }
    }
}
