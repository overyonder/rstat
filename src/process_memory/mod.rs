//! Per-process anonymous memory, grouped by the program each process belongs to.
//!
//! Each process's `/proc/PID/status` holds `RssAnon` and `VmSwap`, counters the kernel keeps as pages
//! are mapped and swapped, so reading them costs no page-table walk and needs no root. For anonymous
//! RAM they match the proportional `Pss_Anon` of `smaps_rollup`. `VmSwap` counts a swapped page shared
//! by forked processes in each of them, so for programs with forked helpers, such as browsers, swap is
//! an upper bound.

use std::collections::HashMap;
use std::path::Path;

use crate::procfs_file::{ProcfsFile, keyed_value};

/// One program's anonymous memory, summed over its processes.
pub(crate) struct OwnerAnonymousMemory {
    pub(crate) name:          String,
    pub(crate) process_count: u64,
    pub(crate) resident_kib:  u64,  // RssAnon
    pub(crate) swapped_kib:   u64,  // VmSwap
}

/// A process's status file, kept open between samples, and the program it belongs to.
struct TrackedProcess {
    status:       ProcfsFile,
    command_name: String,  // status Name when the label was derived; a change means an exec
    owner_label:  String,
}

/// What the walk knows about a PID listed in /proc.
enum TrackedTask {
    /// Has no address space and never will: a kernel thread, or a zombie whose memory is released.
    /// Not read again while its PID stays listed; PIDs are allocated in a cycle up to `pid_max`, so a
    /// PID isn't reused between two samples.
    WithoutMemory,
    Process(TrackedProcess),
}

/// Keeps every process's status file open and re-reads it each sample. A held descriptor refers to
/// its process, not its PID, so it reads nothing once the process exits, even if the PID is reused.
pub(crate) struct ProcessMemoryWalk {
    tasks: HashMap<u32, TrackedTask>,
}

impl ProcessMemoryWalk {
    /// Raises the soft open-file limit to the hard limit, since one descriptor is held per process and
    /// the usual soft limit of 1024 is near a desktop's process count.
    pub(crate) fn new() -> Self {
        use nix::sys::resource::{Resource, getrlimit, setrlimit};
        if let Ok((soft, hard)) = getrlimit(Resource::RLIMIT_NOFILE)
            && soft < hard
        {
            let _ = setrlimit(Resource::RLIMIT_NOFILE, hard, hard);  // Without it, processes past the limit go unlisted
        }
        Self { tasks: HashMap::new() }
    }

    /// Every program's anonymous memory, largest first. Tasks without an address space and processes
    /// that exit during the walk are skipped.
    pub(crate) fn sample_owners_by_anonymous_memory(&mut self) -> Vec<OwnerAnonymousMemory> {
        let mut owners: HashMap<String, OwnerAnonymousMemory> = HashMap::new();
        let mut tasks = HashMap::with_capacity(self.tasks.len());
        for entry in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
            let Some(process_id) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else { continue };
            let mut process = match self.tasks.remove(&process_id) {
                Some(TrackedTask::Process(process)) => process,
                Some(TrackedTask::WithoutMemory) => {
                    tasks.insert(process_id, TrackedTask::WithoutMemory);
                    continue;
                }
                None => {
                    let Some(status) = ProcfsFile::open(entry.path().join("status")) else { continue };
                    TrackedProcess { status, command_name: String::new(), owner_label: String::new() }
                }
            };
            let status = process.status.read();
            if status.is_empty() {
                continue;  // Exited
            }
            if !status.contains("\nRssAnon:") {
                tasks.insert(process_id, TrackedTask::WithoutMemory);
                continue;
            }
            let command_name = status.lines().find_map(|line| line.strip_prefix("Name:")).unwrap_or_default().trim();
            let (resident_kib, swapped_kib) = (keyed_value(status, "RssAnon"), keyed_value(status, "VmSwap"));
            if process.command_name != command_name {
                command_name.clone_into(&mut process.command_name);
                process.owner_label = process_owner_label(process_id);
            }
            let owner = owners.entry(process.owner_label.clone()).or_insert_with(|| OwnerAnonymousMemory {
                name:          process.owner_label.clone(),
                process_count: 0,
                resident_kib:  0,
                swapped_kib:   0,
            });
            owner.process_count += 1;
            owner.resident_kib += resident_kib;
            owner.swapped_kib += swapped_kib;
            tasks.insert(process_id, TrackedTask::Process(process));
        }
        self.tasks = tasks;
        let mut ranked: Vec<OwnerAnonymousMemory> = owners.into_values().collect();
        ranked.sort_by_key(|owner| std::cmp::Reverse(owner.resident_kib + owner.swapped_kib));
        ranked
    }
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
