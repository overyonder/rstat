//! rstat: a low-overhead Linux system monitor for Waybar.
//!
//!   rstat daemon [--interval-ms N]         sample the sections watchers ask for and serve their output
//!   rstat watch cpu|memory|disks|network|gpu   print one section's Waybar JSON line on every change
//!   rstat sample-process-memory OUTPUT     write per-process proportional memory (run as root, periodically)

use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let result = match arguments.as_slice() {
        ["daemon"] => rstat::daemon::serve_sections_to_watchers(rstat::daemon::DEFAULT_SAMPLE_INTERVAL),
        ["daemon", "--interval-ms", milliseconds] => match milliseconds.parse::<u64>() {
            Ok(milliseconds) if milliseconds >= 100 => {
                rstat::daemon::serve_sections_to_watchers(std::time::Duration::from_millis(milliseconds))
            }
            _ => Err("--interval-ms needs a whole number of at least 100".into()),
        },
        ["watch", name] => rstat::section::Section::from_name(name).map_or_else(
            || Err(format!("unknown section {name}: use cpu, memory, disks, network or gpu").into()),
            rstat::watch::print_section_updates,
        ),
        ["sample-process-memory", output] => rstat::process_memory::write_process_memory_report(output.as_ref()),
        _ => Err("usage: rstat daemon [--interval-ms N] | rstat watch SECTION | rstat sample-process-memory OUTPUT".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rstat: {error}");
            ExitCode::FAILURE
        }
    }
}
