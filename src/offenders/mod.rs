//! Which process sessions cause a strain: each process's contribution to one measure over a window,
//! summed by session. A session is a process and the children it started, unless they started their
//! own; a shell running a command line, or a terminal tab, is usually one.
//!
//! The window reads every process only while an alert's figure is above its threshold, so the walk,
//! which for thread states costs about 100 ms, runs only during strain.

use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;

use crate::procfs_file::{keyed_value, split_process_stat};

/// What a process contributes to a figure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Measure {
    CpuSeconds,                 // CPU time used during the window
    RunnableOrBlockedThreads,   // Threads runnable or in D state, averaged over the window
    BlockedThreads,             // Threads in D state, averaged over the window
    AnonymousMemoryBytes,       // RssAnon and VmSwap at the end of the window
    BlockIoBytes,               // Bytes read from and written to block devices during the window
}

impl Measure {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::CpuSeconds => "cpu_seconds",
            Self::RunnableOrBlockedThreads => "runnable_or_blocked_threads",
            Self::BlockedThreads => "blocked_threads",
            Self::AnonymousMemoryBytes => "anonymous_memory_bytes",
            Self::BlockIoBytes => "block_io_bytes",
        }
    }
}

/// One process's reading: its session and its cumulative counter or current level.
#[derive(Clone, Copy)]
struct ProcessReading {
    session: u32,
    amount:  f64,
}

type ProcessReadings = HashMap<u32, ProcessReading>;

/// One process session's share of a strain, as an alert reports it.
#[derive(Serialize)]
pub(crate) struct Offender {
    pub(crate) session:   u32,     // Session ID, the PID of its leader
    pub(crate) pid:       u32,     // The member contributing most
    pub(crate) command:   String,  // The leader's command line, or the top member's once the leader has exited
    pub(crate) processes: u32,
    pub(crate) amount:    f64,
    pub(crate) share:     f64,     // Fraction of the amount across all sessions
}

/// One session's contributions summed while ranking.
struct SessionTotal {
    amount:     f64,
    processes:  u32,
    top_pid:    u32,  // The member contributing most, and its contribution
    top_amount: f64,
}

/// Readings of one measure from the start of a window to its latest sample.
pub(crate) struct MeasureWindow {
    measure:     Measure,
    first:       ProcessReadings,
    accumulated: ProcessReadings,  // Thread counts summed over samples
    latest:      ProcessReadings,
    samples:     u32,
}

impl MeasureWindow {
    pub(crate) fn start(measure: Measure) -> Self {
        let readings = read_every_process(measure);
        Self { measure, first: readings.clone(), accumulated: readings.clone(), latest: readings, samples: 1 }
    }

    pub(crate) const fn measure(&self) -> Measure {
        self.measure
    }

    pub(crate) fn add_sample(&mut self) {
        let readings = read_every_process(self.measure);
        for (process_id, reading) in &readings {
            self.accumulated.entry(*process_id).and_modify(|sum| sum.amount += reading.amount).or_insert(*reading);
        }
        self.latest = readings;
        self.samples += 1;
    }

    /// Each process's contribution over the window. A process that exited during it isn't counted.
    fn contribution(&self, process_id: u32, latest: ProcessReading) -> f64 {
        match self.measure {
            Measure::CpuSeconds | Measure::BlockIoBytes => {
                latest.amount - self.first.get(&process_id).map_or(0.0, |first| first.amount)
            }
            Measure::RunnableOrBlockedThreads | Measure::BlockedThreads => {
                self.accumulated.get(&process_id).map_or(0.0, |sum| sum.amount) / f64::from(self.samples)
            }
            Measure::AnonymousMemoryBytes => latest.amount,
        }
    }

    /// The sessions contributing most, largest first.
    pub(crate) fn offenders(&self, count: usize) -> Vec<Offender> {
        let mut sessions: HashMap<u32, SessionTotal> = HashMap::new();
        for (process_id, reading) in &self.latest {
            let contribution = self.contribution(*process_id, *reading);
            let total = sessions.entry(reading.session).or_insert(SessionTotal { amount: 0.0, processes: 0, top_pid: *process_id, top_amount: contribution });
            total.amount += contribution;
            total.processes += 1;
            if contribution > total.top_amount {
                (total.top_pid, total.top_amount) = (*process_id, contribution);
            }
        }
        let overall: f64 = sessions.values().map(|total| total.amount).sum();
        let mut ranked: Vec<(u32, SessionTotal)> = sessions.into_iter().filter(|(_, total)| total.amount > 0.0).collect();
        ranked.sort_by(|left, right| right.1.amount.total_cmp(&left.1.amount));
        ranked.truncate(count);
        ranked
            .into_iter()
            .map(|(session, total)| Offender {
                session,
                pid: total.top_pid,
                command: session_command_line(session, total.top_pid),
                processes: total.processes,
                amount: total.amount,
                share: if overall > 0.0 { total.amount / overall } else { 0.0 },
            })
            .collect()
    }
}

/// Reads the measure from every process that can be read. Kernel threads, in session 0, and processes
/// whose files the daemon may not read, such as another user's I/O counters, are left out.
fn read_every_process(measure: Measure) -> ProcessReadings {
    let ticks_per_second = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK).ok().flatten().unwrap_or(100) as f64;
    let mut readings = HashMap::new();
    for entry in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(process_id) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else { continue };
        let directory = entry.path();
        let Ok(stat) = std::fs::read_to_string(directory.join("stat")) else { continue };
        let Some((_, fields)) = split_process_stat(&stat) else { continue };
        let fields: Vec<&str> = fields.collect();
        let field = |index: usize| fields.get(index).and_then(|field| field.parse::<u64>().ok()).unwrap_or(0);
        let session = field(3) as u32;
        if session == 0 {
            continue;
        }
        let amount = match measure {
            Measure::CpuSeconds => (field(11) + field(12)) as f64 / ticks_per_second,
            Measure::RunnableOrBlockedThreads => count_threads(&directory, |state| state == 'R' || state == 'D'),
            Measure::BlockedThreads => count_threads(&directory, |state| state == 'D'),
            Measure::AnonymousMemoryBytes => {
                let Ok(status) = std::fs::read_to_string(directory.join("status")) else { continue };
                (keyed_value(&status, "RssAnon") + keyed_value(&status, "VmSwap")) as f64 * 1024.0
            }
            Measure::BlockIoBytes => {
                let Ok(io) = std::fs::read_to_string(directory.join("io")) else { continue };
                (keyed_value(&io, "read_bytes") + keyed_value(&io, "write_bytes")) as f64
            }
        };
        readings.insert(process_id, ProcessReading { session, amount });
    }
    readings
}

fn count_threads(process_directory: &Path, counts: impl Fn(char) -> bool) -> f64 {
    let mut count = 0;
    for thread in std::fs::read_dir(process_directory.join("task")).into_iter().flatten().flatten() {
        let Ok(stat) = std::fs::read_to_string(thread.path().join("stat")) else { continue };
        let state = split_process_stat(&stat).and_then(|(_, mut fields)| fields.next()?.chars().next());
        if state.is_some_and(&counts) {
            count += 1;
        }
    }
    f64::from(count)
}

/// The command line of a session's leader, or of the given member once the leader has exited, with
/// arguments joined by spaces and cut to a readable length.
fn session_command_line(session: u32, member: u32) -> String {
    const LONGEST: usize = 300;
    let read = |process_id: u32| std::fs::read(format!("/proc/{process_id}/cmdline")).ok().filter(|line| !line.is_empty());
    let Some(line) = read(session).or_else(|| read(member)) else { return String::new() };
    let text = String::from_utf8_lossy(&line).trim_end_matches('\0').replace('\0', " ");
    match text.char_indices().nth(LONGEST) {
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text,
    }
}
