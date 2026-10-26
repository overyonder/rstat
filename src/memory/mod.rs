//! Memory section: pressure, paging and reclaim, RAM composition including zram, and the per-process
//! report. Headline: memory pressure (all tasks stalled, 10s) · available RAM.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::config::MemoryConfig;
use crate::markup::{Markup, MarkupColors, Severity, WaybarReport};
use crate::procfs_file::{ProcfsFile, keyed_value, parse_pressure};

/// Written by `rstat sample-process-memory`, run as root by a system service.
pub(crate) const PROCESS_MEMORY_REPORT: &str = "/run/waybar-memory-processes.json";

const GIB: f64 = 1_073_741_824.0;
const MIB: f64 = 1_048_576.0;

pub(crate) struct MemorySampler {
    meminfo:   ProcfsFile,
    vmstat:    ProcfsFile,
    pressure:  ProcfsFile,
    zram:      Vec<ProcfsFile>,  // mm_stat per zram device, in bytes
    page_size: f64,
    previous:  Option<(Instant, HashMap<String, u64>)>,
    items:     MemoryConfig,
}

impl MemorySampler {
    pub(crate) fn open(items: MemoryConfig) -> std::io::Result<Self> {
        let open = |path: &str| ProcfsFile::open(path).ok_or_else(|| std::io::Error::other(format!("cannot open {path}")));
        let zram = if items.zram {
            std::fs::read_dir("/sys/block")
                .into_iter()
                .flatten()
                .flatten()
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("zram"))
                .filter_map(|entry| ProcfsFile::open(entry.path().join("mm_stat")))
                .collect()
        } else {
            Vec::new()
        };
        Ok(Self {
            meminfo:   open("/proc/meminfo")?,
            vmstat:    open("/proc/vmstat")?,
            pressure:  open("/proc/pressure/memory")?,
            zram,
            page_size: nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE).ok().flatten().unwrap_or(4096) as f64,
            previous:  None,
            items,
        })
    }

    pub(crate) fn sample(&mut self, colors: &MarkupColors) -> WaybarReport {
        let now = Instant::now();
        let counters: HashMap<String, u64> = self
            .vmstat
            .read()
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once(' ')?;
                Some((name.to_owned(), value.trim().parse().ok()?))
            })
            .collect();
        let Some((previous_time, previous)) = self.previous.replace((now, counters.clone())) else {
            return WaybarReport::collecting_first_sample();
        };
        let seconds = now.duration_since(previous_time).as_secs_f64();
        let delta = |name: &str| counters.get(name).copied().unwrap_or(0).saturating_sub(previous.get(name).copied().unwrap_or(0)) as f64;
        let per_second = |name: &str| delta(name) / seconds;
        let allocation_stalls: f64 = counters.keys().filter(|name| name.starts_with("allocstall_")).map(|name| per_second(name)).sum();

        let meminfo = self.meminfo.read().to_owned();
        let bytes = |name: &str| keyed_value(&meminfo, name) as f64 * 1024.0;
        let (mut zram_logical, mut zram_payload, mut zram_physical) = (0.0, 0.0, 0.0);
        for device in &mut self.zram {
            let fields: Vec<f64> = device.read().split_whitespace().take(3).filter_map(|field| field.parse().ok()).collect();
            if let [logical, payload, physical] = fields[..] {
                zram_logical += logical;
                zram_payload += payload;
                zram_physical += physical;
            }
        }
        let (some, full) = parse_pressure(self.pressure.read());
        let total = bytes("MemTotal");
        let available = bytes("MemAvailable");
        let available_percent = if total > 0.0 { 100.0 * available / total } else { 0.0 };
        let oom_kills = delta("oom_kill");

        let items = self.items;
        let mut tooltip = Markup::new(colors);
        if items.pressure {
            tooltip.heading("Pressure (10s / 60s / 300s)");
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

        }

        let swap_in = per_second("pswpin") * self.page_size / MIB;
        let swap_out = per_second("pswpout") * self.page_size / MIB;
        let refault_anonymous = per_second("workingset_refault_anon");
        let refault_file = per_second("workingset_refault_file");
        let major_faults = per_second("pgmajfault");
        let compaction_stalls = per_second("compact_stall");
        if items.paging || items.reclaim {
            tooltip.heading("Paging and reclaim");
        }
        if items.paging {
            tooltip
                .line()
                .label("Swap-in: ")
                .high(swap_in, &format!("{swap_in:.2} MiB/s"), 1.0, 20.0)
                .label(" · swap-out: ")
                .high(swap_out, &format!("{swap_out:.2} MiB/s"), 1.0, 20.0);
            tooltip.line().label("Major page faults: ").high(major_faults, &format!("{major_faults:.0}/s"), 500.0, 5000.0);
            tooltip
                .line()
                .label("Refaults of evicted pages: anonymous ")
                .high(refault_anonymous, &format!("{refault_anonymous:.0}/s"), 1000.0, 10000.0)
                .label(", file ")
                .high(refault_file, &format!("{refault_file:.0}/s"), 1000.0, 10000.0);
        }
        if items.reclaim {
            tooltip
                .line()
                .label("Direct reclaim: ")
                .high(allocation_stalls, &format!("{allocation_stalls:.1} stalls/s"), 1.0, 10.0)
                .label(", ")
                .value(&format!("{:.0} pages scanned/s", per_second("pgscan_direct")))
                .label(" · background (kswapd): ")
                .value(&format!("{:.0} pages scanned/s", per_second("pgscan_kswapd")));
            tooltip.line().label("Compaction stalls: ").high(compaction_stalls, &format!("{compaction_stalls:.1}/s"), 1.0, 10.0);
            tooltip
                .line()
                .label("OOM kills: ")
                .high(oom_kills, &format!("{oom_kills:.0}"), 1.0, 1.0)
                .label(&format!(" in the last {seconds:.0}s, "))
                .value(&counters.get("oom_kill").copied().unwrap_or(0).to_string())
                .label(" since boot");
        }

        let outside_zram = total - bytes("MemFree") - zram_physical;
        let cache = bytes("Cached") + bytes("Buffers");
        let kernel_other = bytes("PageTables") + bytes("SecPageTables") + bytes("KernelStack") + bytes("Percpu");
        let other = outside_zram - bytes("AnonPages") - cache - bytes("Slab") - kernel_other - bytes("SwapCached");
        if items.ram || items.zram {
            tooltip.heading("RAM");
        }
        if items.ram {
            tooltip
                .line()
                .label("Available (includes reclaimable): ")
                .low(available / GIB, &format!("{:.2} GiB", available / GIB), total * 0.15 / GIB, total * 0.05 / GIB)
                .label(" of ")
                .value(&format!("{:.2} GiB", total / GIB))
                .label(" (")
                .low(available_percent, &format!("{available_percent:.0}%"), 15.0, 5.0)
                .label(")");
            tooltip
                .line()
                .label("Free physical: ")
                .value(&format!("{:.2} GiB", bytes("MemFree") / GIB))
                .label(" · swap used: ")
                .value(&format!("{:.2} of {:.2} GiB", (bytes("SwapTotal") - bytes("SwapFree")) / GIB, bytes("SwapTotal") / GIB));
            tooltip.line().label("In use outside zram: ").value(&format!("{:.2} GiB", outside_zram / GIB));
            tooltip
                .line()
                .label("  anonymous ")
                .value(&format!("{:.2}", bytes("AnonPages") / GIB))
                .label(" · file cache and shared ")
                .value(&format!("{:.2}", cache / GIB))
                .label(" · slab ")
                .value(&format!("{:.2}", bytes("Slab") / GIB))
                .label(" · page tables, stacks, per-CPU ")
                .value(&format!("{:.2}", kernel_other / GIB))
                .label(" · swap cache ")
                .value(&format!("{:.2}", bytes("SwapCached") / GIB))
                .label(" · other ")
                .value(&format!("{:.2} GiB", other / GIB));
        }
        if items.zram {
            tooltip
                .line()
                .label("Zram: ")
                .value(&format!("{:.2} GiB", zram_logical / GIB))
                .label(" stored in ")
                .value(&format!("{:.2} GiB", zram_physical / GIB))
                .label(" (payload ")
                .value(&format!("{:.2}", zram_payload / GIB))
                .label(", allocator overhead ")
                .value(&format!("{:.2} GiB", (zram_physical - zram_payload) / GIB))
                .label(")");
        }
        if items.processes {
            write_process_memory_rows(&mut tooltip);
        }

        let mut headline = Markup::new(colors);
        headline
            .high(full.ten_seconds, &format!("{:.1}%", full.ten_seconds), 2.0, 10.0)
            .label(" · ")
            .low(available / GIB, &format!("{:.1}G", available / GIB), total * 0.15 / GIB, total * 0.05 / GIB);
        let severity = if oom_kills > 0.0 { Severity::Critical } else { tooltip.worst_severity().max(headline.worst_severity()) };
        WaybarReport::new(headline.into_text(), tooltip.into_text(), severity)
    }
}

/// Appends the per-process table from the root sampler's report. Its figures are descriptive, so they
/// don't affect the section's severity; only a stale report is flagged.
fn write_process_memory_rows(tooltip: &mut Markup<'_>) {
    let report: Option<serde_json::Value> =
        std::fs::read_to_string(PathBuf::from(PROCESS_MEMORY_REPORT)).ok().and_then(|text| serde_json::from_str(&text).ok());
    let Some(report) = report else {
        tooltip.line().line().label("Process memory sampler unavailable (requires the system service).");
        return;
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |elapsed| elapsed.as_secs_f64());
    let age = now - report["timestamp"].as_f64().unwrap_or(0.0);
    tooltip.heading("Processes: anonymous RAM + swap, GiB, proportional");
    tooltip.line().label(&format!("Sampled {age:.0}s ago, every 60s"));
    if age > 120.0 {
        tooltip.label(" ").toned(Severity::Warning, "stale");
    }
    tooltip.line().label(&format!("{:<28} {:>6} {:>6} {:>6}", "Owner (processes)", "RAM", "Swap", "Total"));
    for owner in report["owners"].as_array().into_iter().flatten() {
        let name = format!("{} ({})", owner["name"].as_str().unwrap_or("?"), owner["processes"].as_u64().unwrap_or(0));
        let ram = owner["ram_gib"].as_f64().unwrap_or(0.0);
        let swap = owner["swap_gib"].as_f64().unwrap_or(0.0);
        let name: String = name.chars().take(28).collect();
        tooltip.line().value(&format!("{name:<28} {ram:>6.2} {swap:>6.2} {:>6.2}", ram + swap));
    }
    tooltip.line().label("Other processes: ").value(&format!("{:.2} GiB", report["other_gib"].as_f64().unwrap_or(0.0)));
    tooltip.line().label("File-backed pages are included in file cache, not these rows.");
    let inaccessible = report["inaccessible"].as_u64().unwrap_or(0);
    if inaccessible > 0 {
        tooltip.line().label(&format!("{inaccessible} processes inaccessible; ownership is incomplete."));
    }
}
