//! The daemon's configuration: which sections are served, which groups of tooltip lines each shows,
//! the sampling interval and the markup colours. Read from TOML; every field is optional and defaults
//! to on. A disabled group isn't sampled, so it costs nothing.
//!
//! ```toml
//! interval_ms = 1000
//! [colors]
//! ok = "#a6e3a1"
//! [cpu]
//! fans = false
//! [gpu]
//! devices = [0]
//! processes = false
//! [[alerts]]
//! figure = "cpu.load"
//! above = 20
//! command = ["notify-send", "rstat"]
//! ```

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::alerts::Figure;
use crate::section::Section;

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) interval_ms: u64,
    pub(crate) colors:      ColorConfig,
    pub(crate) cpu:         CpuConfig,
    pub(crate) memory:      MemoryConfig,
    pub(crate) disks:       DisksConfig,
    pub(crate) network:     NetworkConfig,
    pub(crate) gpu:         GpuConfig,
    pub(crate) alerts:      Vec<AlertConfig>,
}

/// A command to run when a figure stays above a threshold; see the alerts module.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertConfig {
    pub(crate) figure:          Figure,
    pub(crate) above:           f64,
    #[serde(default = "default_sustain_seconds")]
    pub(crate) sustain_seconds: u64,          // How long the figure must stay above before the command runs
    #[serde(default = "default_repeat_seconds")]
    pub(crate) repeat_seconds:  u64,          // How long after running the command it may run again
    pub(crate) command:         Vec<String>,  // Program and arguments; receives the alert as JSON on stdin
}

const fn default_sustain_seconds() -> u64 {
    5
}

const fn default_repeat_seconds() -> u64 {
    600
}

/// Pango colours: strain figures use ok, warning and critical; labels are dim and headings stand out.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ColorConfig {
    pub(crate) ok:       String,
    pub(crate) warning:  String,
    pub(crate) critical: String,
    pub(crate) label:    String,
    pub(crate) value:    String,
    pub(crate) heading:  String,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(default, deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // One switch per tooltip group is the configuration's purpose
pub(crate) struct CpuConfig {
    pub(crate) enable:             bool,
    pub(crate) load:               bool,  // Load averages, runnable and blocked tasks
    pub(crate) pressure:           bool,  // CPU pressure stall information
    pub(crate) interrupt_pressure: bool,  // Time lost to interrupts
    pub(crate) utilization:        bool,  // Busy, user, system, interrupts, I/O wait, steal
    pub(crate) scheduler:          bool,  // Context switches and forks
    pub(crate) frequency:          bool,  // Current frequencies across threads
    pub(crate) scaling:            bool,  // Driver, governor, energy preference, limits, boost
    pub(crate) fans:               bool,  // hwmon fan speeds
    pub(crate) temperature:        bool,  // k10temp, zenpower or coretemp sensors
    pub(crate) thermal_throttling: bool,  // Intel thermal throttling events
    pub(crate) acpi_throttling:    bool,  // ACPI processor cooling devices in a throttled state
}

#[derive(Deserialize, Clone, Copy)]
#[serde(default, deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct MemoryConfig {
    pub(crate) enable:    bool,
    pub(crate) pressure:  bool,  // Memory pressure stall information
    pub(crate) paging:    bool,  // Swap traffic, major faults and refaults
    pub(crate) reclaim:   bool,  // Direct and background reclaim, compaction stalls, OOM kills
    pub(crate) ram:       bool,  // Available and free memory, swap use and composition
    pub(crate) zswap:     bool,  // Compressed swap cache in RAM
    pub(crate) zram:      bool,  // Compressed swap in RAM
    pub(crate) processes: bool,  // Anonymous RAM and swap by program
}

#[derive(Deserialize, Clone, Copy)]
#[serde(default, deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct DisksConfig {
    pub(crate) enable:          bool,
    pub(crate) devices:         bool,  // Busy time, queue, throughput and latency per disk
    pub(crate) dirty_pages:     bool,  // Dirty pages and pages under writeback
    pub(crate) root_filesystem: bool,  // Use of the filesystem mounted at /
    pub(crate) pressure:        bool,  // I/O pressure stall information
    pub(crate) blocked_tasks:   bool,  // Tasks in D state, and which commands they are
}

#[derive(Deserialize, Clone, Copy)]
#[serde(default, deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct NetworkConfig {
    pub(crate) enable:          bool,
    pub(crate) nas:             bool,  // SMB requests outstanding, rate and latency
    pub(crate) retransmissions: bool,  // TCP retransmissions and timeouts
    pub(crate) connections:     bool,  // Established and new TCP connections
    pub(crate) listen_queue:    bool,  // TCP listen overflows and drops
    pub(crate) udp_errors:      bool,  // UDP buffer errors
    pub(crate) kernel_backlog:  bool,  // Softnet drops and time squeezes
    pub(crate) interfaces:      bool,  // Default route, addresses, link and traffic per interface
}

#[derive(Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct GpuConfig {
    pub(crate) enable:       bool,
    pub(crate) devices:      Vec<u32>,  // NVML device indices; empty means every device
    pub(crate) utilization:  bool,      // GPU, memory bandwidth, encoder and decoder
    pub(crate) vram:         bool,      // VRAM use and driver reservation
    pub(crate) clock_limits: bool,      // Time under each clock-limit policy, active limit reasons
    pub(crate) clocks:       bool,      // Graphics and memory clocks
    pub(crate) power:        bool,      // Power draw against the limit
    pub(crate) temperature:  bool,      // Temperature and headroom below the slowdown limit
    pub(crate) fans:         bool,      // Fan speeds
    pub(crate) pcie:         bool,      // Link generation and width, replays
    pub(crate) pcie_traffic: bool,      // Throughput, measured every 10 s
    pub(crate) processes:    bool,      // VRAM by process
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interval_ms: 1000,
            colors:      ColorConfig::default(),
            cpu:         CpuConfig::default(),
            memory:      MemoryConfig::default(),
            disks:       DisksConfig::default(),
            network:     NetworkConfig::default(),
            gpu:         GpuConfig::default(),
            alerts:      Vec::new(),
        }
    }
}

impl Default for ColorConfig {
    fn default() -> Self {
        Self {
            ok:       "#a6e3a1".to_owned(),
            warning:  "#fab387".to_owned(),
            critical: "#f38ba8".to_owned(),
            label:    "#7f849c".to_owned(),
            value:    "#cdd6f4".to_owned(),
            heading:  "#89b4fa".to_owned(),
        }
    }
}

impl Default for CpuConfig {
    fn default() -> Self {
        Self {
            enable:             true,
            load:               true,
            pressure:           true,
            interrupt_pressure: true,
            utilization:        true,
            scheduler:          true,
            frequency:          true,
            scaling:            true,
            fans:               true,
            temperature:        true,
            thermal_throttling: true,
            acpi_throttling:    true,
        }
    }
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self { enable: true, pressure: true, paging: true, reclaim: true, ram: true, zswap: true, zram: true, processes: true }
    }
}

impl Default for DisksConfig {
    fn default() -> Self {
        Self { enable: true, devices: true, dirty_pages: true, root_filesystem: true, pressure: true, blocked_tasks: true }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enable:          true,
            nas:             true,
            retransmissions: true,
            connections:     true,
            listen_queue:    true,
            udp_errors:      true,
            kernel_backlog:  true,
            interfaces:      true,
        }
    }
}

impl Default for GpuConfig {
    fn default() -> Self {
        Self {
            enable:       true,
            devices:      Vec::new(),
            utilization:  true,
            vram:         true,
            clock_limits: true,
            clocks:       true,
            power:        true,
            temperature:  true,
            fans:         true,
            pcie:         true,
            pcie_traffic: true,
            processes:    true,
        }
    }
}

impl Config {
    /// Reads the file at `path`, or `$XDG_CONFIG_HOME/rstat/config.toml` when no path is given. A
    /// missing default file means every default; a missing named file is an error.
    pub(crate) fn load(path: Option<&Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let (path, required) = path.map_or_else(|| (default_config_path(), false), |path| (path.to_owned(), true));
        let config: Self = match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?,
            Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(error) => return Err(format!("{}: {error}", path.display()).into()),
        };
        for alert in &config.alerts {
            if alert.command.is_empty() {
                return Err(format!("{}: the {} alert has an empty command", path.display(), alert.figure.name()).into());
            }
            if !config.serves(alert.figure.section()) {
                return Err(format!("{}: the {} alert's section is disabled", path.display(), alert.figure.name()).into());
            }
        }
        Ok(config)
    }

    pub(crate) const fn serves(&self, section: Section) -> bool {
        match section {
            Section::Cpu => self.cpu.enable,
            Section::Memory => self.memory.enable,
            Section::Disks => self.disks.enable,
            Section::Network => self.network.enable,
            Section::Gpu => self.gpu.enable,
        }
    }
}

fn default_config_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_default()
        .join("rstat/config.toml")
}
