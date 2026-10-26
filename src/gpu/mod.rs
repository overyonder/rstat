//! NVIDIA GPU section, read through NVML (the library nvidia-smi itself uses), loaded once while the
//! section is watched. Headline: GPU utilization · VRAM use.

use std::time::{Duration, Instant};

use nvml_wrapper::Nvml;
use nvml_wrapper::enum_wrappers::device::{Clock, PcieUtilCounter, PerformancePolicy, TemperatureSensor, TemperatureThreshold};
use nvml_wrapper::enums::device::UsedGpuMemory;

use crate::config::GpuConfig;
use crate::markup::{Markup, MarkupColors, WaybarReport};

/// Clock-limiting policies whose cumulative violation time NVML reports, and whether time spent under
/// each one is strain (thermal and board limits) or ordinary operation (power management, low load).
const VIOLATION_POLICIES: [(PerformancePolicy, &str, bool); 6] = [
    (PerformancePolicy::Power,          "power limit",     false),
    (PerformancePolicy::Thermal,        "thermal",         true),
    (PerformancePolicy::BoardLimit,     "board limit",     true),
    (PerformancePolicy::Reliability,    "reliability",     true),
    (PerformancePolicy::SyncBoost,      "sync boost",      false),
    (PerformancePolicy::LowUtilization, "low utilization", false),
];

/// NVML measures PCIe throughput over a window on every call, costing about 20 ms of wall time each
/// way, so it is re-measured at this interval rather than on every sample.
const PCIE_TRAFFIC_INTERVAL: Duration = Duration::from_secs(10);

/// Reading the six violation counters costs about 6 ms of CPU. They are cumulative, so reading them at
/// this interval gives the same percentages over a longer window.
const VIOLATION_INTERVAL: Duration = Duration::from_secs(10);

/// Time under each clock-limit policy over the latest completed window, as percentages.
#[derive(Clone, Copy)]
struct ViolationWindow {
    measured:    Instant,
    nanoseconds: [Option<u64>; VIOLATION_POLICIES.len()],  // Cumulative counters at `measured`
    percents:    Option<([Option<f64>; VIOLATION_POLICIES.len()], f64)>,  // With the window's length in seconds
}

/// Device properties that don't change while the driver is loaded.
struct DeviceConstants {
    maximum_graphics_clock: Option<u32>,  // MHz
    maximum_memory_clock:   Option<u32>,  // MHz
    fan_count:              u32,
}

/// One PCIe throughput measurement, in KB/s.
#[derive(Clone, Copy)]
struct PcieTraffic {
    measured: Instant,
    send:     Option<u32>,
    receive:  Option<u32>,
}


pub(crate) struct GpuSampler {
    nvml:         Option<Nvml>,                          // None when the driver library can't be loaded
    previous:     Option<(Instant, Vec<Option<u32>>)>,   // PCIe replay counters per device
    pcie_traffic: Vec<Option<PcieTraffic>>,              // Latest measurement per device
    violations:   Vec<Option<ViolationWindow>>,          // Per device
    constants:    Vec<DeviceConstants>,                  // Per device
    items:        GpuConfig,
}

impl GpuSampler {
    pub(crate) fn open(items: GpuConfig) -> Self {
        let nvml = Nvml::init().ok();
        let constants = nvml.as_ref().map_or_else(Vec::new, |nvml| {
            (0..nvml.device_count().unwrap_or(0))
                .map(|index| {
                    let device = nvml.device_by_index(index).ok();
                    DeviceConstants {
                        maximum_graphics_clock: device.as_ref().and_then(|device| device.max_clock_info(Clock::Graphics).ok()),
                        maximum_memory_clock:   device.as_ref().and_then(|device| device.max_clock_info(Clock::Memory).ok()),
                        fan_count:              device.as_ref().and_then(|device| device.num_fans().ok()).unwrap_or(0),
                    }
                })
                .collect()
        });
        Self { nvml, previous: None, pcie_traffic: Vec::new(), violations: Vec::new(), constants, items }
    }

    pub(crate) fn sample(&mut self, colors: &MarkupColors) -> WaybarReport {
        let Some(nvml) = &self.nvml else {
            return WaybarReport::unavailable("NVIDIA telemetry unavailable");
        };
        let items = &self.items;
        let now = Instant::now();
        let devices: Vec<(usize, _)> = (0..nvml.device_count().unwrap_or(0))
            .filter(|index| items.devices.is_empty() || items.devices.contains(index))
            .filter_map(|index| Some((index as usize, nvml.device_by_index(index).ok()?)))
            .collect();
        let counters: Vec<Option<u32>> =
            devices.iter().map(|(_, device)| if items.pcie { device.pcie_replay_counter().ok() } else { None }).collect();
        let previous = self.previous.replace((now, counters.clone()));
        let Some((previous_time, previous_counters)) = previous.filter(|(_, earlier)| earlier.len() == counters.len()) else {
            return WaybarReport::collecting_first_sample();
        };
        let seconds = now.duration_since(previous_time).as_secs_f64();

        let mut tooltip = Markup::new(colors);
        let mut headline = Markup::new(colors);
        for (position, (index, device)) in devices.iter().enumerate() {
            let index = *index;
            let constants = self.constants.get(index);
            if position > 0 {
                headline.label(" / ");
            }
            let memory = device.memory_info().ok();
            let (used, capacity, reserved) = memory.map_or((0.0, 0.0, 0.0), |memory| {
                let mib = |bytes: u64| bytes as f64 / 1_048_576.0;
                // The driver reservation is never available to processes, so it is excluded from capacity.
                (mib(memory.used), mib(memory.total.saturating_sub(memory.reserved)), mib(memory.reserved))
            });
            let vram_percent = if capacity > 0.0 { 100.0 * used / capacity } else { 0.0 };
            let utilization = device.utilization_rates().ok();
            let gpu_percent = f64::from(utilization.as_ref().map_or(0, |rates| rates.gpu));

            tooltip.heading(&device.name().unwrap_or_else(|_| "NVIDIA GPU".to_owned()));
            if let Ok(state) = device.performance_state() {
                tooltip.line().label("Performance state: ").value(&format!("P{}", state.as_c()));
            }

            if items.utilization || items.vram {
                tooltip.heading("Utilization");
            }
            if items.utilization {
                tooltip
                    .line()
                    .label("GPU: ")
                    .high(gpu_percent, &format!("{gpu_percent:.0}%"), 95.0, 101.0)
                    .label(" · memory bandwidth ")
                    .value(&utilization.map_or_else(|| "N/A".to_owned(), |rates| format!("{}%", rates.memory)))
                    .label(" · encoder ")
                    .value(&device.encoder_utilization().map_or_else(|_| "N/A".to_owned(), |info| format!("{}%", info.utilization)))
                    .label(" · decoder ")
                    .value(&device.decoder_utilization().map_or_else(|_| "N/A".to_owned(), |info| format!("{}%", info.utilization)));
            }
            if items.vram {
                tooltip
                    .line()
                    .label("VRAM: ")
                    .high(vram_percent, &format!("{used:.0}"), 90.0, 97.0)
                    .label(" of ")
                    .value(&format!("{capacity:.0} MiB"))
                    .label(" usable (")
                    .high(vram_percent, &format!("{vram_percent:.0}%"), 90.0, 97.0)
                    .label(") · driver reserved ")
                    .value(&format!("{reserved:.0} MiB"));
            }

            if items.clock_limits {
                if self.violations.len() <= index {
                    self.violations.resize(index + 1, None);
                }
                let window = match self.violations[index] {
                    Some(window) if now.duration_since(window.measured) < VIOLATION_INTERVAL => window,
                    earlier => {
                        let nanoseconds =
                            VIOLATION_POLICIES.map(|(policy, _, _)| device.violation_status(policy).ok().map(|time| time.violation_time));
                        let percents = earlier.map(|earlier| {
                            let window_seconds = now.duration_since(earlier.measured).as_secs_f64();
                            let mut percents = [None; VIOLATION_POLICIES.len()];
                            for (policy_index, percent) in percents.iter_mut().enumerate() {
                                if let (Some(now_ns), Some(then_ns)) = (nanoseconds[policy_index], earlier.nanoseconds[policy_index]) {
                                    *percent = Some((100.0 * now_ns.saturating_sub(then_ns) as f64 / (window_seconds * 1e9)).min(100.0));
                                }
                            }
                            (percents, window_seconds)
                        });
                        let window = ViolationWindow { measured: now, nanoseconds, percents };
                        self.violations[index] = Some(window);
                        window
                    }
                };
                match window.percents {
                    None => {
                        tooltip
                            .heading("Time under clock limits")
                            .line()
                            .label(&format!("Measuring over the first {}s.", VIOLATION_INTERVAL.as_secs()));
                    }
                    Some((percents, window_seconds)) => {
                        tooltip.heading(&format!("Time under clock limits over {window_seconds:.0}s")).line();
                        for (policy_index, (_, name, is_strain)) in VIOLATION_POLICIES.iter().enumerate() {
                            if policy_index > 0 {
                                tooltip.label(", ");
                            }
                            tooltip.label(&format!("{name} "));
                            match percents[policy_index] {
                                Some(percent) if *is_strain => {
                                    tooltip.high(percent, &format!("{percent:.0}%"), 0.01, 20.0);
                                }
                                Some(percent) => {
                                    tooltip.value(&format!("{percent:.0}%"));
                                }
                                None => {
                                    tooltip.value("n/a");
                                }
                            }
                        }
                    }
                }
                let active: Vec<String> = device
                    .current_throttle_reasons()
                    .map(|reasons| reasons.iter_names().map(|(name, _)| name.to_lowercase().replace('_', " ")).collect())
                    .unwrap_or_default();
                tooltip.line().label("Active limit reasons: ").value(&if active.is_empty() { "none".to_owned() } else { active.join(", ") });
            }
            if items.clocks {
                let clock = |kind: Clock, maximum: Option<u32>| {
                    let current = device.clock_info(kind).map_or_else(|_| "N/A".to_owned(), |mhz| format!("{mhz} MHz"));
                    let maximum = maximum.map_or_else(|| "N/A".to_owned(), |mhz| format!("{mhz} MHz"));
                    format!("{current} of {maximum}")
                };
                if !items.clock_limits {
                    tooltip.heading("Clocks");
                }
                tooltip
                    .line()
                    .label("Clocks: graphics ")
                    .value(&clock(Clock::Graphics, constants.and_then(|constants| constants.maximum_graphics_clock)))
                    .label(", memory ")
                    .value(&clock(Clock::Memory, constants.and_then(|constants| constants.maximum_memory_clock)));
            }

            if items.power || items.temperature || items.fans {
                tooltip.heading("Power and cooling");
            }
            if items.power {
                let power_watts = device.power_usage().map_or(0.0, |milliwatts| f64::from(milliwatts) / 1000.0);
                let limit_watts = device.enforced_power_limit().map_or(0.0, |milliwatts| f64::from(milliwatts) / 1000.0);
                let power_percent = if limit_watts > 0.0 { 100.0 * power_watts / limit_watts } else { 0.0 };
                tooltip
                    .line()
                    .label("Power: ")
                    .high(power_percent, &format!("{power_watts:.0} W"), 95.0, 101.0)
                    .label(" of ")
                    .value(&format!("{limit_watts:.0} W"))
                    .label(" limit");
            }
            if items.temperature {
                let temperature = device.temperature(TemperatureSensor::Gpu).ok();
                tooltip.line().label("Temperature: ").value(&temperature.map_or_else(|| "N/A".to_owned(), |celsius| format!("{celsius} C")));
                if let (Some(temperature), Ok(slowdown)) = (temperature, device.temperature_threshold(TemperatureThreshold::Slowdown)) {
                    let headroom = f64::from(slowdown) - f64::from(temperature);
                    tooltip.label(", ").low(headroom, &format!("{headroom:.0} C"), 10.0, 5.0).label(" below the slowdown limit");
                }
            }
            if items.fans {
                let fans: Vec<String> = (0..constants.map_or(0, |constants| constants.fan_count))
                    .filter_map(|fan| device.fan_speed(fan).ok())
                    .map(|speed| format!("{speed}%"))
                    .collect();
                tooltip.line().label("Fans: ").value(&if fans.is_empty() { "N/A".to_owned() } else { fans.join(", ") });
            }

            if items.pcie || items.pcie_traffic {
                tooltip.heading("PCIe");
            }
            if items.pcie {
                let link = |current: Result<u32, _>, maximum: Result<u32, _>| {
                    let text = |value: Result<u32, _>| value.map_or_else(|_| "N/A".to_owned(), |value| value.to_string());
                    format!("{} of {}", text(current), text(maximum))
                };
                let replays = match (counters[position], previous_counters[position]) {
                    (Some(now_count), Some(then_count)) => f64::from(now_count.saturating_sub(then_count)),
                    _ => 0.0,
                };
                tooltip
                    .line()
                    .label("Link: gen ")
                    .value(&link(device.current_pcie_link_gen(), device.max_pcie_link_gen()))
                    .label(", width ")
                    .value(&link(device.current_pcie_link_width(), device.max_pcie_link_width()))
                    .label(&format!(" · replays in {seconds:.0}s: "))
                    .high(replays, &format!("{replays:.0}"), 1.0, 100.0);
            }
            if items.pcie_traffic {
                if self.pcie_traffic.len() <= index {
                    self.pcie_traffic.resize(index + 1, None);
                }
                let traffic = match self.pcie_traffic[index] {
                    Some(traffic) if now.duration_since(traffic.measured) < PCIE_TRAFFIC_INTERVAL => traffic,
                    _ => {
                        let traffic = PcieTraffic {
                            measured: now,
                            send:     device.pcie_throughput(PcieUtilCounter::Send).ok(),
                            receive:  device.pcie_throughput(PcieUtilCounter::Receive).ok(),
                        };
                        self.pcie_traffic[index] = Some(traffic);
                        traffic
                    }
                };
                let throughput = |kilobytes: Option<u32>| kilobytes.map_or_else(|| "N/A".to_owned(), |kilobytes| format!("{kilobytes} KB/s"));
                tooltip
                    .line()
                    .label("Traffic: send ")
                    .value(&throughput(traffic.send))
                    .label(", receive ")
                    .value(&throughput(traffic.receive))
                    .label(&format!(" ({:.0}s ago)", now.duration_since(traffic.measured).as_secs_f64()));
            }

            if items.processes {
                let mut owners: std::collections::BTreeMap<String, f64> = std::collections::BTreeMap::new();
                let mut unknown = 0;
                let processes =
                    device.running_graphics_processes().unwrap_or_default().into_iter().chain(device.running_compute_processes().unwrap_or_default());
                for process in processes {
                    match process.used_gpu_memory {
                        UsedGpuMemory::Used(bytes) => {
                            *owners.entry(crate::process_memory::process_owner_label(process.pid)).or_default() += bytes as f64 / 1_048_576.0;
                        }
                        UsedGpuMemory::Unavailable => unknown += 1,
                    }
                }
                let mut ranked: Vec<(String, f64)> = owners.into_iter().collect();
                ranked.sort_by(|left, right| right.1.total_cmp(&left.1));
                tooltip.heading("Graphics and compute processes, VRAM");
                let attributed: f64 = ranked.iter().map(|(_, mib)| mib).sum();
                for (owner, mib) in &ranked {
                    tooltip.line().value(owner).label(": ").value(&format!("{mib:.0} MiB"));
                }
                tooltip.line().label("Unattributed / accounting difference: ").value(&format!("{:.0} MiB", used - attributed));
                if unknown > 0 {
                    tooltip.line().label(&format!("{unknown} processes have unavailable memory counters."));
                }
            }

            headline
                .high(gpu_percent, &format!("{gpu_percent:.0}%"), 95.0, 101.0)
                .label(" · ")
                .high(vram_percent, &format!("{vram_percent:.0}%"), 90.0, 97.0);
        }
        let severity = tooltip.worst_severity().max(headline.worst_severity());
        WaybarReport::new(headline.into_text(), tooltip.into_text(), severity)
    }
}
