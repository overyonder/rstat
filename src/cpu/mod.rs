//! CPU section: load, CPU and interrupt pressure, utilization, and frequency and cooling.
//! Headline: 1-minute load · CPU pressure (some, 10s).

use std::time::Instant;

use crate::markup::{Markup, MarkupColors, Severity, WaybarReport};
use crate::procfs_file::{ProcfsFile, parse_pressure, read_trimmed};

/// Cumulative /proc/stat counters at one sample.
#[derive(Clone, Copy, Default)]
struct CpuCounters {
    user:              u64,  // Includes nice
    system:            u64,
    idle:              u64,
    iowait:            u64,
    interrupts:        u64,  // irq + softirq
    steal:             u64,
    context_switches:  u64,
    forks:             u64,
}

/// Drivers whose hwmon temperatures are the CPU's own sensors.
const CPU_TEMPERATURE_DRIVERS: [&str; 3] = ["k10temp", "zenpower", "coretemp"];

/// One CPU temperature sensor, in millidegrees Celsius.
struct CpuTemperature {
    input: ProcfsFile,
    name:  String,  // The sensor's label, such as Tctl or Package id 0
}

/// Intel's thermal throttling event counters, per CPU, under `cpuN/thermal_throttle`.
/// Package counters repeat on every CPU of the package, so only the largest is used.
struct ThrottleCounters {
    core:    Vec<ProcfsFile>,
    package: Vec<ProcfsFile>,
}

struct Fan {
    speed: ProcfsFile,
    name:  String,  // "sensor / label"
}

pub(crate) struct CpuSampler {
    stat:             ProcfsFile,
    loadavg:          ProcfsFile,
    cpu_pressure:     ProcfsFile,
    irq_pressure:     Option<ProcfsFile>,
    current_freqs:    Vec<ProcfsFile>,  // scaling_cur_freq per CPU, kHz
    fans:             Vec<Fan>,
    temperatures:     Vec<CpuTemperature>,
    throttle:         ThrottleCounters,
    previous_throttle: Option<(u64, u64)>,  // Core events summed, package events at the last sample
    cpu_count:        f64,
    previous:         Option<(Instant, CpuCounters)>,
}

impl CpuSampler {
    pub(crate) fn open() -> std::io::Result<Self> {
        let mut current_freqs = Vec::new();
        let mut cpu_count = 0.0;
        let mut core_throttle = Vec::new();
        let mut package_throttle = Vec::new();
        for entry in std::fs::read_dir("/sys/devices/system/cpu")?.flatten() {
            let name = entry.file_name();
            let Some(index) = name.to_str().and_then(|name| name.strip_prefix("cpu")) else { continue };
            if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            cpu_count += 1.0;
            core_throttle.extend(ProcfsFile::open(entry.path().join("thermal_throttle/core_throttle_count")));
            package_throttle.extend(ProcfsFile::open(entry.path().join("thermal_throttle/package_throttle_count")));
            if let Some(file) = ProcfsFile::open(entry.path().join("cpufreq/scaling_cur_freq")) {
                current_freqs.push(file);
            }
        }
        let mut fans = Vec::new();
        let mut temperatures = Vec::new();
        for sensor in std::fs::read_dir("/sys/class/hwmon").into_iter().flatten().flatten() {
            let sensor_name = read_trimmed(sensor.path().join("name")).unwrap_or_default();
            if CPU_TEMPERATURE_DRIVERS.contains(&sensor_name.as_str()) {
                for input in std::fs::read_dir(sensor.path()).into_iter().flatten().flatten() {
                    let file_name = input.file_name().to_string_lossy().into_owned();
                    let Some(stem) = file_name.strip_suffix("_input").filter(|stem| stem.starts_with("temp")) else { continue };
                    let name = read_trimmed(sensor.path().join(format!("{stem}_label"))).unwrap_or_else(|| stem.to_owned());
                    if let Some(input) = ProcfsFile::open(input.path()) {
                        temperatures.push(CpuTemperature { input, name });
                    }
                }
            }
            for input in std::fs::read_dir(sensor.path()).into_iter().flatten().flatten() {
                let file_name = input.file_name().to_string_lossy().into_owned();
                let Some(stem) = file_name.strip_prefix("fan").and_then(|rest| rest.strip_suffix("_input")) else { continue };
                let label = read_trimmed(sensor.path().join(format!("fan{stem}_label"))).unwrap_or_else(|| format!("fan{stem}"));
                if let Some(speed) = ProcfsFile::open(input.path()) {
                    fans.push(Fan { speed, name: format!("{sensor_name} / {label}") });
                }
            }
        }
        Ok(Self {
            stat: ProcfsFile::open("/proc/stat").ok_or_else(|| std::io::Error::other("cannot open /proc/stat"))?,
            loadavg: ProcfsFile::open("/proc/loadavg").ok_or_else(|| std::io::Error::other("cannot open /proc/loadavg"))?,
            cpu_pressure: ProcfsFile::open("/proc/pressure/cpu").ok_or_else(|| std::io::Error::other("cannot open /proc/pressure/cpu"))?,
            irq_pressure: ProcfsFile::open("/proc/pressure/irq"),
            current_freqs,
            fans,
            temperatures,
            throttle: ThrottleCounters { core: core_throttle, package: package_throttle },
            previous_throttle: None,
            cpu_count,
            previous: None,
        })
    }

    pub(crate) fn sample(&mut self, colors: &MarkupColors) -> WaybarReport {
        let now = Instant::now();
        let (counters, running, blocked) = read_cpu_counters(self.stat.read());
        let Some((previous_time, previous)) = self.previous.replace((now, counters)) else {
            return WaybarReport::collecting_first_sample();
        };
        let seconds = now.duration_since(previous_time).as_secs_f64();

        let loads: Vec<f64> = self.loadavg.read().split_whitespace().take(3).filter_map(|field| field.parse().ok()).collect();
        let [load_one_minute, load_five_minutes, load_fifteen_minutes] = [0, 1, 2].map(|index| loads.get(index).copied().unwrap_or(0.0));
        let (cpu_some, _) = parse_pressure(self.cpu_pressure.read());
        let cpus = self.cpu_count;

        let mut tooltip = Markup::new(colors);
        tooltip.heading("Load").line().label("1 / 5 / 15 min: ");
        for (index, load) in [load_one_minute, load_five_minutes, load_fifteen_minutes].into_iter().enumerate() {
            if index > 0 {
                tooltip.label(" / ");
            }
            tooltip.high(load, &format!("{load:.2}"), cpus, 2.0 * cpus);
        }
        tooltip
            .label(" · per CPU: ")
            .high(load_one_minute / cpus, &format!("{:.2}", load_one_minute / cpus), 1.0, 2.0)
            .label(" over ")
            .value(&format!("{cpus:.0}"))
            .label(" CPUs");
        tooltip
            .line()
            .label("Runnable: ")
            .value(&running.to_string())
            .label(" · blocked in D state: ")
            .high(blocked as f64, &blocked.to_string(), 4.0, 16.0);
        tooltip.line().label("Load counts tasks waiting on local disks and on the NAS; the disk and network sections separate them.");

        tooltip.heading("Pressure, some tasks waiting (10s / 60s / 300s)").line().label("CPU: ");
        write_pressure_triple(&mut tooltip, cpu_some, 10.0, 40.0);
        if let Some(irq_pressure) = &mut self.irq_pressure {
            let (_, irq_full) = parse_pressure(irq_pressure.read());
            tooltip.line().label("Time lost to interrupts: ");
            write_pressure_triple(&mut tooltip, irq_full, 5.0, 20.0);
        }

        let delta = |current: u64, earlier: u64| current.saturating_sub(earlier) as f64;
        let user = delta(counters.user, previous.user);
        let system = delta(counters.system, previous.system);
        let idle = delta(counters.idle, previous.idle);
        let iowait = delta(counters.iowait, previous.iowait);
        let interrupts = delta(counters.interrupts, previous.interrupts);
        let steal = delta(counters.steal, previous.steal);
        let total = (user + system + idle + iowait + interrupts + steal).max(1.0);
        let percent = |part: f64| 100.0 * part / total;
        let busy = percent(total - idle - iowait);
        tooltip
            .heading("Utilization")
            .line()
            .label("Busy: ")
            .high(busy, &format!("{busy:.1}%"), 80.0, 95.0)
            .label(" · user ")
            .value(&format!("{:.1}", percent(user)))
            .label(" · system ")
            .value(&format!("{:.1}", percent(system)))
            .label(" · interrupts ")
            .value(&format!("{:.1}", percent(interrupts)))
            .label(" · I/O wait ")
            .high(percent(iowait), &format!("{:.1}", percent(iowait)), 10.0, 30.0)
            .label(" · steal ")
            .high(percent(steal), &format!("{:.1}", percent(steal)), 5.0, 20.0);
        tooltip
            .line()
            .label("Context switches: ")
            .value(&format!("{:.0}/s", delta(counters.context_switches, previous.context_switches) / seconds))
            .label(" · forks: ")
            .value(&format!("{:.0}/s", delta(counters.forks, previous.forks) / seconds));

        tooltip.heading("Frequency and cooling");
        let freqs: Vec<f64> = self.current_freqs.iter_mut().filter_map(ProcfsFile::read_value::<f64>).map(|khz| khz / 1e6).collect();
        if !freqs.is_empty() {
            let average = freqs.iter().sum::<f64>() / freqs.len() as f64;
            let minimum = freqs.iter().copied().fold(f64::INFINITY, f64::min);
            let maximum = freqs.iter().copied().fold(0.0, f64::max);
            tooltip
                .line()
                .label("Reported: ")
                .value(&format!("{average:.2} GHz average, {minimum:.2}–{maximum:.2} GHz across threads"));
        }
        for line in cpu_scaling_lines() {
            tooltip.field(&line);
        }
        if self.fans.is_empty() {
            tooltip.field("Fans: not exposed by hardware sensors");
        }
        for fan in &mut self.fans {
            let speed = fan.speed.read_value::<u64>().unwrap_or(0);
            tooltip.field(&format!("Fan {}: {speed} RPM", fan.name));
        }
        // Temperature and throttling raise the section to a warning at most; load and pressure decide the rest.
        let mut thermal_severity = Severity::Ok;
        self.temperatures.sort_by(|left, right| left.name.cmp(&right.name));
        if !self.temperatures.is_empty() {
            tooltip.line().label("Temperature: ");
            for (index, sensor) in self.temperatures.iter_mut().enumerate() {
                let celsius = sensor.input.read_value::<f64>().unwrap_or(0.0) / 1000.0;
                if index > 0 {
                    tooltip.label(", ");
                }
                thermal_severity = thermal_severity.max(Severity::of_high(celsius, 85.0, 95.0));
                tooltip.label(&format!("{} ", sensor.name)).high(celsius, &format!("{celsius:.0} C"), 85.0, 95.0);
            }
        }
        if !self.throttle.core.is_empty() {
            let core: u64 = self.throttle.core.iter_mut().filter_map(ProcfsFile::read_value::<u64>).sum();
            let package = self.throttle.package.iter_mut().filter_map(ProcfsFile::read_value::<u64>).max().unwrap_or(0);
            if let Some((previous_core, previous_package)) = self.previous_throttle.replace((core, package)) {
                let core_events = core.saturating_sub(previous_core) as f64;
                let package_events = package.saturating_sub(previous_package) as f64;
                thermal_severity = thermal_severity.max(Severity::of_high(core_events + package_events, 1.0, 100.0));
                tooltip
                    .line()
                    .label("Thermal throttling events: cores ")
                    .high(core_events, &format!("{core_events:.0}"), 1.0, 100.0)
                    .label(", package ")
                    .high(package_events, &format!("{package_events:.0}"), 1.0, 100.0)
                    .label(&format!(" in the last {seconds:.0}s"));
            }
        }

        let mut headline = Markup::new(colors);
        headline
            .high(load_one_minute, &format!("{load_one_minute:.2}"), cpus, 2.0 * cpus)
            .label(" · ")
            .high(cpu_some.ten_seconds, &format!("{:.1}%", cpu_some.ten_seconds), 10.0, 40.0);
        let severity = headline.worst_severity().max(thermal_severity.min(Severity::Warning));
        WaybarReport::new(headline.into_text(), tooltip.into_text(), severity)
    }
}

pub(crate) fn write_pressure_triple(markup: &mut Markup<'_>, pressure: crate::procfs_file::PressureLine, warning: f64, critical: f64) {
    markup
        .high(pressure.ten_seconds, &format!("{:.2}", pressure.ten_seconds), warning, critical)
        .label(" / ")
        .high(pressure.one_minute, &format!("{:.2}", pressure.one_minute), warning, critical)
        .label(" / ")
        .high(pressure.five_minutes, &format!("{:.2}%", pressure.five_minutes), warning, critical);
}

/// Parses the aggregate counters, runnable tasks and blocked tasks from /proc/stat.
fn read_cpu_counters(text: &str) -> (CpuCounters, u64, u64) {
    let mut counters = CpuCounters::default();
    let (mut running, mut blocked) = (0, 0);
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let key = fields.next().unwrap_or("");
        let values: Vec<u64> = fields.filter_map(|field| field.parse().ok()).collect();
        let at = |index: usize| values.get(index).copied().unwrap_or(0);
        match key {
            "cpu" => {
                counters.user = at(0) + at(1);
                counters.system = at(2);
                counters.idle = at(3);
                counters.iowait = at(4);
                counters.interrupts = at(5) + at(6);
                counters.steal = at(7);
            }
            "ctxt" => counters.context_switches = at(0),
            "processes" => counters.forks = at(0),
            "procs_running" => running = at(0),
            "procs_blocked" => blocked = at(0),
            _ => {}
        }
    }
    (counters, running, blocked)
}

/// Frequency-scaling settings across all policies, as `Name: value` lines.
fn cpu_scaling_lines() -> Vec<String> {
    let mut drivers = std::collections::BTreeSet::new();
    let mut governors = std::collections::BTreeSet::new();
    let mut preferences = std::collections::BTreeSet::new();
    let mut boosts = std::collections::BTreeSet::new();
    let (mut minimum, mut maximum) = (u64::MAX, 0);
    for policy in std::fs::read_dir("/sys/devices/system/cpu/cpufreq").into_iter().flatten().flatten() {
        let path = policy.path();
        drivers.extend(read_trimmed(path.join("scaling_driver")));
        governors.extend(read_trimmed(path.join("scaling_governor")));
        preferences.extend(read_trimmed(path.join("energy_performance_preference")));
        if let Some(boost) = read_trimmed(path.join("boost")) {
            boosts.insert(if boost == "1" { "enabled" } else { "disabled" });
        }
        if let Some(frequency) = read_trimmed(path.join("scaling_min_freq")).and_then(|text| text.parse().ok()) {
            minimum = minimum.min(frequency);
        }
        if let Some(frequency) = read_trimmed(path.join("scaling_max_freq")).and_then(|text| text.parse::<u64>().ok()) {
            maximum = maximum.max(frequency);
        }
    }
    let join = |set: std::collections::BTreeSet<String>| set.into_iter().collect::<Vec<_>>().join(", ");
    let mut lines = Vec::new();
    if !drivers.is_empty() {
        lines.push(format!("Scaling driver: {}", join(drivers)));
        lines.push(format!("Governor: {}", join(governors)));
        lines.push(format!("Energy preference: {}", if preferences.is_empty() { "unavailable".to_owned() } else { join(preferences) }));
        lines.push(format!("Frequency limits: {:.2}–{:.2} GHz", minimum as f64 / 1e6, maximum as f64 / 1e6));
    }
    if !boosts.is_empty() {
        lines.push(format!("Boost: {}", boosts.into_iter().collect::<Vec<_>>().join(", ")));
    }
    if let Some(no_turbo) = read_trimmed("/sys/devices/system/cpu/intel_pstate/no_turbo") {
        lines.push(format!("Turbo: {}", if no_turbo == "0" { "enabled" } else { "disabled" }));
    }
    lines
}
