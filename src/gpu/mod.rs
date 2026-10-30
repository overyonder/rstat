//! NVIDIA GPU section, read through NVML (the library nvidia-smi itself uses), loaded once while the
//! section is watched. Headline: GPU utilization · available VRAM.

use std::time::{Duration, Instant};

use nvml_wrapper::Nvml;
use nvml_wrapper::enum_wrappers::device::{
    Clock, PcieUtilCounter, PerformancePolicy, TemperatureSensor, TemperatureThreshold,
};
use nvml_wrapper::enums::device::UsedGpuMemory;
use nvml_wrapper::struct_wrappers::device::ViolationTime;

use crate::config::GpuConfig;
use crate::markup::{Markup, MarkupColors, WaybarReport};

/// Clock-limiting policies whose cumulative violation time NVML reports, and whether time spent under
/// each one is strain (thermal throttling) or ordinary operation (power management, voltage and board limits, low load).
const VIOLATION_POLICIES: [(PerformancePolicy, &str, bool); 6] = [
    (PerformancePolicy::Power, "power limit", false),
    (PerformancePolicy::Thermal, "thermal", true),
    (PerformancePolicy::BoardLimit, "board limit", false),
    (PerformancePolicy::Reliability, "reliability", false),
    (PerformancePolicy::SyncBoost, "sync boost", false),
    (PerformancePolicy::LowUtilization, "low utilization", false),
];

/// NVML measures PCIe throughput over a window on every call, costing about 20 ms of wall time each
/// way, so it is re-measured at this interval rather than on every sample.
const PCIE_TRAFFIC_INTERVAL: Duration = Duration::from_secs(10);

/// Reading the six violation counters costs about 6 ms of CPU. They are cumulative, so reading them at
/// this interval gives the same percentages over a longer window.
const VIOLATION_INTERVAL: Duration = Duration::from_secs(10);

/// Time under each clock-limit policy over the latest completed window, as percentages.
#[derive(Clone)]
struct ViolationWindow {
    measured: Instant,
    counters: [Option<ViolationTime>; VIOLATION_POLICIES.len()],
    percents: Option<([Option<f64>; VIOLATION_POLICIES.len()], f64)>, // With the window's length in seconds
}

/// Device properties that don't change while the driver is loaded.
struct DeviceConstants {
    maximum_graphics_clock: Option<u32>, // MHz
    maximum_memory_clock: Option<u32>,   // MHz
    fan_count: u32,
}

/// One PCIe throughput measurement, in KB/s.
#[derive(Clone, Copy)]
struct PcieTraffic {
    measured: Instant,
    send: Option<u32>,
    receive: Option<u32>,
}

pub(crate) struct GpuSampler {
    nvml: Option<Nvml>, // None when the driver library can't be loaded
    previous: Option<(Instant, Vec<Option<u32>>)>, // PCIe replay counters per device
    pcie_traffic: Vec<Option<PcieTraffic>>, // Latest measurement per device
    violations: Vec<Option<ViolationWindow>>, // Per device
    constants: Vec<DeviceConstants>, // Per device
    items: GpuConfig,
}

impl GpuSampler {
    pub(crate) fn open(items: GpuConfig) -> Self {
        let nvml = Nvml::init().ok();
        let constants = nvml.as_ref().map_or_else(Vec::new, |nvml| {
            (0..nvml.device_count().unwrap_or(0))
                .map(|index| {
                    let device = nvml.device_by_index(index).ok();
                    DeviceConstants {
                        maximum_graphics_clock: device
                            .as_ref()
                            .and_then(|device| device.max_clock_info(Clock::Graphics).ok()),
                        maximum_memory_clock: device
                            .as_ref()
                            .and_then(|device| device.max_clock_info(Clock::Memory).ok()),
                        fan_count: device
                            .as_ref()
                            .and_then(|device| device.num_fans().ok())
                            .unwrap_or(0),
                    }
                })
                .collect()
        });
        Self {
            nvml,
            previous: None,
            pcie_traffic: Vec::new(),
            violations: Vec::new(),
            constants,
            items,
        }
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
        if devices.is_empty() {
            return WaybarReport::unavailable("No selected NVIDIA GPU available");
        }
        let counters: Vec<Option<u32>> = devices
            .iter()
            .map(|(_, device)| {
                if items.pcie {
                    device.pcie_replay_counter().ok()
                } else {
                    None
                }
            })
            .collect();
        let previous = self.previous.replace((now, counters.clone()));
        let Some((previous_time, previous_counters)) =
            previous.filter(|(_, earlier)| earlier.len() == counters.len())
        else {
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
            let memory_values = memory.as_ref().map(|memory| {
                let mib = |bytes: u64| bytes as f64 / 1_048_576.0;
                // The driver reservation is never available to processes, so it is excluded from capacity.
                (
                    mib(memory.used),
                    mib(memory.total.saturating_sub(memory.reserved)),
                    mib(memory.reserved),
                    mib(memory.free),
                )
            });
            let vram_percent = memory_values
                .filter(|(_, capacity, _, _)| *capacity > 0.0)
                .map(|(used, capacity, _, _)| 100.0 * used / capacity);
            let utilization = device.utilization_rates().ok();
            let gpu_percent = utilization.as_ref().map(|rates| f64::from(rates.gpu));

            tooltip.heading(&device.name().unwrap_or_else(|_| "NVIDIA GPU".to_owned()));
            if let Ok(state) = device.performance_state() {
                tooltip
                    .line()
                    .label("Performance state: ")
                    .value(&format!("P{}", state.as_c()));
            }

            if items.utilization || items.vram {
                tooltip.heading("Utilization");
            }
            if items.utilization {
                tooltip.line().label("GPU active: ");
                if let Some(percent) = gpu_percent {
                    tooltip.value(&format!("{percent:.0}%"));
                } else {
                    tooltip.value("N/A");
                }
                tooltip
                    .label(" · memory read/write active ")
                    .value(
                        &utilization
                            .as_ref()
                            .map_or_else(|| "N/A".to_owned(), |rates| format!("{}%", rates.memory)),
                    )
                    .label(" · encoder ")
                    .value(&device.encoder_utilization().map_or_else(
                        |_| "N/A".to_owned(),
                        |info| format!("{}%", info.utilization),
                    ))
                    .label(" · decoder ")
                    .value(&device.decoder_utilization().map_or_else(
                        |_| "N/A".to_owned(),
                        |info| format!("{}%", info.utilization),
                    ));
            }
            if items.vram {
                tooltip.line().label("VRAM used: ");
                if let (Some((used, capacity, reserved, free)), Some(percent)) =
                    (memory_values, vram_percent)
                {
                    tooltip
                        .high(percent, &format!("{:.2}", used / 1024.0), 90.0, 97.0)
                        .label(" of ")
                        .value(&format!("{:.2} GiB", capacity / 1024.0))
                        .label(" usable (")
                        .high(percent, &format!("{percent:.0}%"), 90.0, 97.0)
                        .label(") · available ")
                        .value(&format!("{:.2} GiB", free / 1024.0))
                        .label(" · driver reserved ")
                        .value(&format!("{:.2} GiB", reserved / 1024.0));
                } else {
                    tooltip.value("N/A");
                }
            }

            if items.clock_limits {
                if self.violations.len() <= index {
                    self.violations.resize(index + 1, None);
                }
                let window = match self.violations[index].clone() {
                    Some(window) if now.duration_since(window.measured) < VIOLATION_INTERVAL => {
                        window
                    }
                    earlier => {
                        let counters = VIOLATION_POLICIES
                            .map(|(policy, _, _)| device.violation_status(policy).ok());
                        let percents = earlier.map(|earlier| {
                            let window_seconds = now.duration_since(earlier.measured).as_secs_f64();
                            let mut percents = [None; VIOLATION_POLICIES.len()];
                            for (policy_index, percent) in percents.iter_mut().enumerate() {
                                if let (Some(current), Some(previous)) =
                                    (&counters[policy_index], &earlier.counters[policy_index])
                                    && current.reference_time > previous.reference_time
                                    && current.violation_time >= previous.violation_time
                                {
                                    let elapsed_ns =
                                        (current.reference_time - previous.reference_time) as f64
                                            * 1000.0;
                                    *percent = Some(
                                        100.0
                                            * (current.violation_time - previous.violation_time)
                                                as f64
                                            / elapsed_ns,
                                    );
                                }
                            }
                            (percents, window_seconds)
                        });
                        let window = ViolationWindow {
                            measured: now,
                            counters,
                            percents,
                        };
                        self.violations[index] = Some(window.clone());
                        window
                    }
                };
                match window.percents {
                    None => {
                        tooltip
                            .heading("Time under clock limits")
                            .line()
                            .label(&format!(
                                "Measuring over the first {}s.",
                                VIOLATION_INTERVAL.as_secs()
                            ));
                    }
                    Some((percents, window_seconds)) => {
                        tooltip
                            .heading(&format!(
                                "Time under clock limits over {window_seconds:.0}s"
                            ))
                            .line();
                        for (policy_index, (_, name, is_strain)) in
                            VIOLATION_POLICIES.iter().enumerate()
                        {
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
                let active = device.current_throttle_reasons().map(|reasons| {
                    reasons
                        .iter_names()
                        .map(|(name, _)| name.to_lowercase().replace('_', " "))
                        .collect::<Vec<_>>()
                });
                let active = active.map_or_else(
                    |_| "N/A".to_owned(),
                    |reasons| {
                        if reasons.is_empty() {
                            "none".to_owned()
                        } else {
                            reasons.join(", ")
                        }
                    },
                );
                tooltip
                    .line()
                    .label("Active limit reasons: ")
                    .value(&active);
            }
            if items.clocks {
                let clock = |kind: Clock, maximum: Option<u32>| {
                    let current = device
                        .clock_info(kind)
                        .map_or_else(|_| "N/A".to_owned(), |mhz| format!("{mhz} MHz"));
                    let maximum =
                        maximum.map_or_else(|| "N/A".to_owned(), |mhz| format!("{mhz} MHz"));
                    format!("{current} of {maximum}")
                };
                if !items.clock_limits {
                    tooltip.heading("Clocks");
                }
                tooltip
                    .line()
                    .label("Clocks: graphics ")
                    .value(&clock(
                        Clock::Graphics,
                        constants.and_then(|constants| constants.maximum_graphics_clock),
                    ))
                    .label(", memory ")
                    .value(&clock(
                        Clock::Memory,
                        constants.and_then(|constants| constants.maximum_memory_clock),
                    ));
            }

            if items.power || items.temperature || items.fans {
                tooltip.heading("Power and cooling");
            }
            if items.power {
                let watts = |milliwatts: u32| f64::from(milliwatts) / 1000.0;
                let power_watts = device.power_usage().ok().map(watts);
                let limit_watts = device
                    .enforced_power_limit()
                    .ok()
                    .map(watts)
                    .filter(|limit| *limit > 0.0);
                tooltip.line().label("Power: ");
                if let (Some(power), Some(limit)) = (power_watts, limit_watts) {
                    tooltip.high(100.0 * power / limit, &format!("{power:.0} W"), 95.0, 105.0);
                } else {
                    tooltip.value(
                        &power_watts
                            .map_or_else(|| "N/A".to_owned(), |watts| format!("{watts:.0} W")),
                    );
                }
                tooltip
                    .label(" of ")
                    .value(
                        &limit_watts
                            .map_or_else(|| "N/A".to_owned(), |watts| format!("{watts:.0} W")),
                    )
                    .label(" limit");
            }
            if items.temperature {
                let temperature = device.temperature(TemperatureSensor::Gpu).ok();
                tooltip.line().label("Temperature: ").value(
                    &temperature.map_or_else(|| "N/A".to_owned(), |celsius| format!("{celsius} C")),
                );
                if let (Some(temperature), Ok(slowdown)) = (
                    temperature,
                    device.temperature_threshold(TemperatureThreshold::Slowdown),
                ) {
                    let headroom = f64::from(slowdown) - f64::from(temperature);
                    tooltip
                        .label(", ")
                        .low(headroom, &format!("{headroom:.0} C"), 10.0, 5.0)
                        .label(" below the slowdown limit");
                }
            }
            if items.fans {
                let fans: Vec<String> = (0..constants.map_or(0, |constants| constants.fan_count))
                    .map(|fan| {
                        device
                            .fan_speed(fan)
                            .map_or_else(|_| "N/A".to_owned(), |speed| format!("{speed}%"))
                    })
                    .collect();
                tooltip
                    .line()
                    .label("Fan speed targets: ")
                    .value(&if fans.is_empty() {
                        "N/A".to_owned()
                    } else {
                        fans.join(", ")
                    });
            }

            if items.pcie || items.pcie_traffic {
                tooltip.heading("PCIe");
            }
            if items.pcie {
                let link = |current: Result<u32, _>, maximum: Result<u32, _>| {
                    let text = |value: Result<u32, _>| {
                        value.map_or_else(|_| "N/A".to_owned(), |value| value.to_string())
                    };
                    format!("{} of {}", text(current), text(maximum))
                };
                let replays = match (counters[position], previous_counters[position]) {
                    (Some(now_count), Some(then_count)) if now_count >= then_count => {
                        Some(f64::from(now_count - then_count))
                    }
                    _ => None,
                };
                tooltip
                    .line()
                    .label("Link: gen ")
                    .value(&link(
                        device.current_pcie_link_gen(),
                        device.max_pcie_link_gen(),
                    ))
                    .label(", width ")
                    .value(&link(
                        device.current_pcie_link_width(),
                        device.max_pcie_link_width(),
                    ))
                    .label(&format!(" · replays in {seconds:.0}s: "));
                if let Some(replays) = replays {
                    tooltip.high(replays, &format!("{replays:.0}"), 1.0, 100.0);
                } else {
                    tooltip.value("N/A");
                }
            }
            if items.pcie_traffic {
                if self.pcie_traffic.len() <= index {
                    self.pcie_traffic.resize(index + 1, None);
                }
                let traffic = match self.pcie_traffic[index] {
                    Some(traffic)
                        if now.duration_since(traffic.measured) < PCIE_TRAFFIC_INTERVAL =>
                    {
                        traffic
                    }
                    _ => {
                        let traffic = PcieTraffic {
                            measured: now,
                            send: device.pcie_throughput(PcieUtilCounter::Send).ok(),
                            receive: device.pcie_throughput(PcieUtilCounter::Receive).ok(),
                        };
                        self.pcie_traffic[index] = Some(traffic);
                        traffic
                    }
                };
                let throughput = |kilobytes: Option<u32>| {
                    kilobytes
                        .map_or_else(|| "N/A".to_owned(), |kilobytes| format!("{kilobytes} KB/s"))
                };
                tooltip
                    .line()
                    .label("Traffic: send ")
                    .value(&throughput(traffic.send))
                    .label(", receive ")
                    .value(&throughput(traffic.receive))
                    .label(&format!(
                        " ({:.0}s ago)",
                        now.duration_since(traffic.measured).as_secs_f64()
                    ));
            }

            if items.processes {
                let mut owners: std::collections::BTreeMap<String, f64> =
                    std::collections::BTreeMap::new();
                let mut unknown = 0;
                let graphics = device.running_graphics_processes();
                let compute = device.running_compute_processes();
                let mut processes = std::collections::BTreeMap::new();
                for process in graphics
                    .as_ref()
                    .into_iter()
                    .flatten()
                    .chain(compute.as_ref().into_iter().flatten())
                {
                    let key = (
                        process.pid,
                        process.gpu_instance_id,
                        process.compute_instance_id,
                    );
                    // Both lists report the process's allocation, not separate graphics/compute allocations.
                    processes.insert(key, process);
                }
                for process in processes.into_values() {
                    match process.used_gpu_memory {
                        UsedGpuMemory::Used(bytes) => {
                            *owners
                                .entry(crate::process_memory::process_owner_label(process.pid))
                                .or_default() += bytes as f64 / 1_048_576.0;
                        }
                        UsedGpuMemory::Unavailable => unknown += 1,
                    }
                }
                let mut ranked: Vec<(String, f64)> = owners.into_iter().collect();
                ranked.sort_by(|left, right| right.1.total_cmp(&left.1));
                tooltip.heading("Graphics and compute processes, VRAM");
                if graphics.is_err() {
                    tooltip.line().label("Graphics process list: ").value("N/A");
                }
                if compute.is_err() {
                    tooltip.line().label("Compute process list: ").value("N/A");
                }
                let attributed: f64 = ranked.iter().map(|(_, mib)| mib).sum();
                for (owner, mib) in &ranked {
                    tooltip
                        .line()
                        .value(owner)
                        .label(": ")
                        .value(&format!("{mib:.0} MiB"));
                }
                if let Some((used, _, _, _)) = memory_values {
                    tooltip
                        .line()
                        .label("Device used minus listed processes: ")
                        .value(&format!("{:.0} MiB", used - attributed));
                }
                if unknown > 0 {
                    tooltip.line().label(&format!(
                        "{unknown} processes have unavailable memory counters."
                    ));
                }
            }

            if let Some(percent) = gpu_percent {
                headline.value(&format!("{percent:.0}%"));
            } else {
                headline.value("N/A");
            }
            headline.label(" · ");
            if let (Some((_, _, _, free)), Some(percent)) = (memory_values, vram_percent) {
                headline.high(percent, &format!("{:.1}G", free / 1024.0), 90.0, 97.0);
            } else {
                headline.value("N/A");
            }
        }
        let severity = tooltip.worst_severity().max(headline.worst_severity());
        WaybarReport::new(headline.into_text(), tooltip.into_text(), severity)
    }
}
