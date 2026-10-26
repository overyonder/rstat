//! Per-process proportional memory, sampled separately from the daemon.
//!
//! Reading every process's `smaps_rollup` takes a few hundred milliseconds and needs root, so a system
//! service runs `rstat sample-process-memory` about once a minute and the memory section reads the
//! report it leaves.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Owners shown by name in the report; the rest are summed as other processes.
const LISTED_OWNERS: usize = 12;

/// One owner's proportional anonymous memory, in KiB.
#[derive(Default)]
struct OwnerMemory {
    resident_kib:  u64,  // Pss_Anon
    swapped_kib:   u64,  // SwapPss
    process_count: u64,
}

/// Names the program a process belongs to: the executable named by argv[0], with Nix's wrapper
/// decoration removed, so a browser's content processes count with the browser rather than under
/// their thread names. Falls back to the kernel's command name.
pub(crate) fn process_owner_label(process_id: u32) -> String {
    let directory = Path::new("/proc").join(process_id.to_string());
    let command_line = std::fs::read(directory.join("cmdline")).unwrap_or_default();
    let program = command_line.split(|byte| *byte == 0).next().map(String::from_utf8_lossy).unwrap_or_default();
    let program = program.split_whitespace().next().unwrap_or_default();
    let name = program.rsplit('/').next().unwrap_or_default();
    let name = name.strip_prefix('.').and_then(|name| name.strip_suffix("-wrapped")).unwrap_or(name);
    if name.is_empty() {
        crate::procfs_file::read_trimmed(directory.join("comm")).unwrap_or_else(|| process_id.to_string())
    } else {
        name.to_owned()
    }
}

/// Writes the report as JSON: `timestamp` (Unix seconds), `duration` (seconds), `owners` (rows of
/// `name`, `processes`, `ram_gib`, `swap_gib`, largest first), `other_gib` and `inaccessible`.
/// # Errors
///
/// Fails if /proc can't be listed or the report can't be written.
pub fn write_process_memory_report(output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let mut owners: BTreeMap<String, OwnerMemory> = BTreeMap::new();
    let mut inaccessible = 0;
    for entry in std::fs::read_dir("/proc")?.flatten() {
        let Some(process_id) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else { continue };
        let rollup = match std::fs::read_to_string(entry.path().join("smaps_rollup")) {
            Ok(rollup) => rollup,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                inaccessible += 1;
                continue;
            }
            Err(_) => continue,  // Exited, or a kernel thread with no memory map
        };
        let owner = owners.entry(process_owner_label(process_id)).or_default();
        owner.resident_kib += crate::procfs_file::keyed_value(&rollup, "Pss_Anon");
        owner.swapped_kib += crate::procfs_file::keyed_value(&rollup, "SwapPss");
        owner.process_count += 1;
    }
    let mut ranked: Vec<(String, OwnerMemory)> = owners.into_iter().collect();
    ranked.sort_by_key(|(_, memory)| std::cmp::Reverse(memory.resident_kib + memory.swapped_kib));
    let gib = |kib: u64| kib as f64 / 1_048_576.0;
    let listed: Vec<serde_json::Value> = ranked
        .iter()
        .take(LISTED_OWNERS)
        .map(|(name, memory)| {
            serde_json::json!({
                "name": name,
                "processes": memory.process_count,
                "ram_gib": gib(memory.resident_kib),
                "swap_gib": gib(memory.swapped_kib),
            })
        })
        .collect();
    let other_gib: f64 = ranked.iter().skip(LISTED_OWNERS).map(|(_, memory)| gib(memory.resident_kib + memory.swapped_kib)).sum();
    let report = serde_json::json!({
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64(),
        "duration": started.elapsed().as_secs_f64(),
        "owners": listed,
        "other_gib": other_gib,
        "inaccessible": inaccessible,
    });
    let temporary = output.with_extension("tmp");
    std::fs::write(&temporary, report.to_string())?;
    std::fs::set_permissions(&temporary, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
    std::fs::rename(&temporary, output)?;
    Ok(())
}
