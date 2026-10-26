//! Disks section: local block devices, dirty pages, the root filesystem, I/O pressure and tasks blocked
//! in uninterruptible sleep. Headline: average number of requests queued on local disks.

use std::collections::BTreeMap;
use std::time::Instant;

use crate::markup::{Markup, MarkupColors, Severity, WaybarReport};
use crate::procfs_file::{ProcfsFile, keyed_value, parse_pressure};

/// Fields of /sys/block/*/stat (Documentation/block/stat.rst) used here. Sectors are 512 bytes.
#[derive(Clone, Copy, Default)]
struct DiskCounters {
    reads:                  u64,
    sectors_read:           u64,
    read_milliseconds:      u64,
    writes:                 u64,
    sectors_written:        u64,
    write_milliseconds:     u64,
    in_flight:              u64,
    busy_milliseconds:      u64,
    weighted_milliseconds:  u64,  // Time requests spent queued or in service, summed over requests
}

struct Disk {
    name: String,
    stat: ProcfsFile,
}

pub(crate) struct DisksSampler {
    disks:    Vec<Disk>,
    meminfo:  ProcfsFile,
    stat:     ProcfsFile,
    pressure: ProcfsFile,
    previous: Option<(Instant, Vec<DiskCounters>)>,
}

impl DisksSampler {
    pub(crate) fn open() -> std::io::Result<Self> {
        let open = |path: &str| ProcfsFile::open(path).ok_or_else(|| std::io::Error::other(format!("cannot open {path}")));
        // Physical disks only: partitions, device-mapper, loop and zram devices would double count.
        let mut disks: Vec<Disk> = std::fs::read_dir("/sys/block")?
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                let physical = ["nvme", "sd", "vd", "mmcblk"].iter().any(|prefix| name.starts_with(prefix));
                physical.then(|| Some(Disk { stat: ProcfsFile::open(entry.path().join("stat"))?, name }))?
            })
            .collect();
        disks.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(Self { disks, meminfo: open("/proc/meminfo")?, stat: open("/proc/stat")?, pressure: open("/proc/pressure/io")?, previous: None })
    }

    pub(crate) fn sample(&mut self, colors: &MarkupColors) -> WaybarReport {
        let now = Instant::now();
        let counters: Vec<DiskCounters> = self.disks.iter_mut().map(|disk| parse_disk_counters(disk.stat.read())).collect();
        let Some((previous_time, previous)) = self.previous.replace((now, counters.clone())) else {
            return WaybarReport::collecting_first_sample();
        };
        let seconds = now.duration_since(previous_time).as_secs_f64();

        let mut tooltip = Markup::new(colors);
        tooltip.heading("Local disks");
        let mut total_queue = 0.0;
        for ((disk, current), earlier) in self.disks.iter().zip(&counters).zip(&previous) {
            let delta = |field: fn(&DiskCounters) -> u64| field(current).saturating_sub(field(earlier)) as f64;
            let busy = (delta(|counters| counters.busy_milliseconds) / (seconds * 10.0)).min(100.0);
            let queue = delta(|counters| counters.weighted_milliseconds) / (seconds * 1000.0);
            total_queue += queue;
            let (reads, writes) = (delta(|counters| counters.reads), delta(|counters| counters.writes));
            let read_wait = if reads > 0.0 { delta(|counters| counters.read_milliseconds) / reads } else { 0.0 };
            let write_wait = if writes > 0.0 { delta(|counters| counters.write_milliseconds) / writes } else { 0.0 };
            tooltip
                .line()
                .value(&disk.name)
                .label(": ")
                .high(busy, &format!("{busy:.0}%"), 70.0, 95.0)
                .label(" busy · queue ")
                .high(queue, &format!("{queue:.2}"), 4.0, 16.0)
                .label(" · in flight ")
                .value(&current.in_flight.to_string());
            tooltip
                .line()
                .label("  read ")
                .value(&format!("{:.0}/s, {:.1} MiB/s", reads / seconds, delta(|counters| counters.sectors_read) * 512.0 / 1_048_576.0 / seconds))
                .label(", wait ")
                .high(read_wait, &format!("{read_wait:.2} ms"), 20.0, 100.0);
            tooltip
                .line()
                .label("  write ")
                .value(&format!("{:.0}/s, {:.1} MiB/s", writes / seconds, delta(|counters| counters.sectors_written) * 512.0 / 1_048_576.0 / seconds))
                .label(", wait ")
                .high(write_wait, &format!("{write_wait:.2} ms"), 20.0, 100.0);
        }
        let meminfo = self.meminfo.read();
        tooltip
            .line()
            .label("Dirty pages: ")
            .value(&format!("{:.1} MiB", keyed_value(meminfo, "Dirty") as f64 / 1024.0))
            .label(" · under writeback: ")
            .value(&format!("{:.1} MiB", keyed_value(meminfo, "Writeback") as f64 / 1024.0));
        let mut root_percent = 0.0;
        if let Ok(root) = nix::sys::statvfs::statvfs("/") {
            let fragment = root.fragment_size() as f64;
            let size = root.blocks() as f64 * fragment;
            let free = root.blocks_free() as f64 * fragment;
            let available = root.blocks_available() as f64 * fragment;
            let used = size - free;
            // As df computes it: used over the space ordinary users can reach.
            let percent = if used + available > 0.0 { (100.0 * used / (used + available)).ceil() } else { 0.0 };
            root_percent = percent;
            tooltip
                .line()
                .label("Root filesystem: ")
                .value(&format!("{:.1} of {:.1} GiB", used / 1_073_741_824.0, size / 1_073_741_824.0))
                .label(" used (")
                .high(percent, &format!("{percent:.0}%"), 90.0, 97.0)
                .label("), ")
                .value(&format!("{:.1} GiB", available / 1_073_741_824.0))
                .label(" free");
        }

        let (some, full) = parse_pressure(self.pressure.read());
        tooltip.heading("I/O pressure, local disks and NAS together (10s / 60s / 300s)");
        tooltip
            .line()
            .label("Some tasks stalled: ")
            .high(some.ten_seconds, &format!("{:.2}", some.ten_seconds), 10.0, 40.0)
            .label(" / ")
            .high(some.one_minute, &format!("{:.2}", some.one_minute), 10.0, 40.0)
            .label(" / ")
            .high(some.five_minutes, &format!("{:.2}%", some.five_minutes), 10.0, 40.0);
        tooltip
            .line()
            .label("All tasks stalled: ")
            .high(full.ten_seconds, &format!("{:.2}", full.ten_seconds), 2.0, 10.0)
            .label(" / ")
            .high(full.one_minute, &format!("{:.2}", full.one_minute), 2.0, 10.0)
            .label(" / ")
            .high(full.five_minutes, &format!("{:.2}%", full.five_minutes), 2.0, 10.0);
        let blocked = keyed_value(self.stat.read(), "procs_blocked");
        tooltip.line().label("Blocked in D state: ").high(blocked as f64, &blocked.to_string(), 4.0, 16.0);
        // Scanning every thread costs about 100 ms, so it runs only while the kernel reports blocked tasks.
        if blocked > 0 {
            for (count, name) in blocked_threads_by_command() {
                tooltip.line().label("  ").high(count as f64, &format!("{count:5}"), 4.0, 16.0).label("  ").value(&name);
            }
        }

        // The tooltip's pressure figures are shared with NAS waits, so only the queue and the root
        // filesystem decide this section's state.
        let mut headline = Markup::new(colors);
        headline.high(total_queue, &format!("{total_queue:.2}"), 8.0, 32.0);
        let severity = headline.worst_severity().max(Severity::of_high(root_percent, 90.0, 97.0));
        WaybarReport::new(headline.into_text(), tooltip.into_text(), severity)
    }
}

fn parse_disk_counters(text: &str) -> DiskCounters {
    let fields: Vec<u64> = text.split_whitespace().map(|field| field.parse().unwrap_or(0)).collect();
    let field = |index: usize| fields.get(index).copied().unwrap_or(0);
    DiskCounters {
        reads:                 field(0),
        sectors_read:          field(2),
        read_milliseconds:     field(3),
        writes:                field(4),
        sectors_written:       field(6),
        write_milliseconds:    field(7),
        in_flight:             field(8),
        busy_milliseconds:     field(9),
        weighted_milliseconds: field(10),
    }
}

/// Threads in uninterruptible sleep (D state), counted by command name, largest eight groups.
fn blocked_threads_by_command() -> Vec<(u64, String)> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for process in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        if !process.file_name().to_string_lossy().bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        for thread in std::fs::read_dir(process.path().join("task")).into_iter().flatten().flatten() {
            let Ok(stat) = std::fs::read_to_string(thread.path().join("stat")) else { continue };
            // The command name is parenthesised and may contain spaces or parentheses itself.
            let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else { continue };
            if stat[close + 1..].trim_start().starts_with('D') {
                *counts.entry(stat[open + 1..close].to_owned()).or_default() += 1;
            }
        }
    }
    let mut ranked: Vec<(u64, String)> = counts.into_iter().map(|(name, count)| (count, name)).collect();
    ranked.sort_by_key(|(count, _)| std::cmp::Reverse(*count));
    ranked.truncate(8);
    ranked
}
