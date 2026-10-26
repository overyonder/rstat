//! Alerts: a command run when a section's figure stays above a threshold, told which process sessions
//! caused the strain.
//!
//! An alert's sections are sampled whether or not a watcher is connected. When its figure rises above
//! the threshold the alert starts measuring each process session's share of the strain, and if the
//! figure is still above after `sustain_seconds` it runs the command with a JSON description on
//! standard input. It fires again after `repeat_seconds` while the figure stays above.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::config::AlertConfig;
use crate::offenders::{Measure, MeasureWindow};
use crate::section::Section;

/// A figure an alert can watch, named `section.figure` in the configuration.
#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Figure {
    #[serde(rename = "cpu.load")]
    CpuLoad,  // 1-minute load average
    #[serde(rename = "cpu.pressure")]
    CpuPressure,  // Percent of time some tasks waited for a CPU, over 10 s
    #[serde(rename = "memory.pressure_some")]
    MemoryPressureSome,  // Percent of time some tasks stalled on memory, over 10 s
    #[serde(rename = "memory.pressure_full")]
    MemoryPressureFull,  // Percent of time all non-idle tasks stalled on memory, over 10 s
    #[serde(rename = "disks.queue")]
    DisksQueue,  // Average requests queued on local disks
    #[serde(rename = "disks.pressure_some")]
    DisksPressureSome,  // Percent of time some tasks stalled on I/O, over 10 s
    #[serde(rename = "disks.pressure_full")]
    DisksPressureFull,  // Percent of time all non-idle tasks stalled on I/O, over 10 s
    #[serde(rename = "network.nas_wait")]
    NetworkNasWait,  // Average NAS (SMB) requests outstanding
}

impl Figure {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::CpuLoad => "cpu.load",
            Self::CpuPressure => "cpu.pressure",
            Self::MemoryPressureSome => "memory.pressure_some",
            Self::MemoryPressureFull => "memory.pressure_full",
            Self::DisksQueue => "disks.queue",
            Self::DisksPressureSome => "disks.pressure_some",
            Self::DisksPressureFull => "disks.pressure_full",
            Self::NetworkNasWait => "network.nas_wait",
        }
    }

    pub(crate) const fn section(self) -> Section {
        match self {
            Self::CpuLoad | Self::CpuPressure => Section::Cpu,
            Self::MemoryPressureSome | Self::MemoryPressureFull => Section::Memory,
            Self::DisksQueue | Self::DisksPressureSome | Self::DisksPressureFull => Section::Disks,
            Self::NetworkNasWait => Section::Network,
        }
    }

    /// What a process contributes to this figure. Load counts runnable and blocked tasks, so its
    /// share is threads in those states; NAS waits block their tasks, so theirs is blocked threads.
    const fn measure(self) -> Measure {
        match self {
            Self::CpuLoad => Measure::RunnableOrBlockedThreads,
            Self::CpuPressure => Measure::CpuSeconds,
            Self::MemoryPressureSome | Self::MemoryPressureFull => Measure::AnonymousMemoryBytes,
            Self::DisksQueue | Self::DisksPressureSome | Self::DisksPressureFull => Measure::BlockIoBytes,
            Self::NetworkNasWait => Measure::BlockedThreads,
        }
    }
}

/// How many process sessions an alert names, largest share first.
const OFFENDERS_REPORTED: usize = 5;

enum AlertState {
    Below,
    Above { since: Instant, window: MeasureWindow },
    Fired { at: Instant },
}

pub(crate) struct Alert {
    config: AlertConfig,
    state:  AlertState,
}

impl Alert {
    pub(crate) const fn new(config: AlertConfig) -> Self {
        Self { config, state: AlertState::Below }
    }

    pub(crate) const fn section(&self) -> Section {
        self.config.figure.section()
    }

    /// Advances the alert with the figures its section reported this sample, and runs its command
    /// once the figure has stayed above the threshold for the sustain period.
    pub(crate) fn observe(&mut self, figures: &[(Figure, f64)]) {
        let Some(value) = figures.iter().find(|(figure, _)| *figure == self.config.figure).map(|(_, value)| *value) else { return };
        let now = Instant::now();
        let above = value > self.config.above;
        self.state = match std::mem::replace(&mut self.state, AlertState::Below) {
            AlertState::Below | AlertState::Above { .. } if !above => AlertState::Below,
            AlertState::Below => AlertState::Above { since: now, window: MeasureWindow::start(self.config.figure.measure()) },
            AlertState::Above { since, mut window } => {
                window.add_sample();
                if now.duration_since(since) >= Duration::from_secs(self.config.sustain_seconds) {
                    self.run_command(value, now.duration_since(since), &window);
                    AlertState::Fired { at: now }
                } else {
                    AlertState::Above { since, window }
                }
            }
            AlertState::Fired { at } if now.duration_since(at) < Duration::from_secs(self.config.repeat_seconds) => AlertState::Fired { at },
            AlertState::Fired { .. } => AlertState::Below,
        };
    }

    /// Starts the command with the alert's description on standard input; a thread feeds and reaps it
    /// so a slow command never holds up sampling.
    fn run_command(&self, value: f64, window: Duration, measurements: &MeasureWindow) {
        let offenders = measurements.offenders(OFFENDERS_REPORTED);
        let description = serde_json::json!({
            "figure": self.config.figure.name(),
            "value": value,
            "above": self.config.above,
            "window_seconds": window.as_secs_f64(),
            "measure": measurements.measure().name(),
            "offenders": offenders,
        })
        .to_string();
        let Some((program, arguments)) = self.config.command.split_first() else { return };
        let child = Command::new(program).args(arguments).stdin(Stdio::piped()).spawn();
        let figure = self.config.figure.name();
        match child {
            Ok(mut child) => {
                std::thread::spawn(move || {
                    if let Some(mut stdin) = child.stdin.take() {
                        let _ = stdin.write_all(description.as_bytes());
                    }
                    match child.wait() {
                        Ok(status) if !status.success() => eprintln!("rstat: the {figure} alert command exited with {status}"),
                        Err(error) => eprintln!("rstat: the {figure} alert command could not be waited for: {error}"),
                        Ok(_) => {}
                    }
                });
            }
            Err(error) => eprintln!("rstat: the {figure} alert command could not be started: {error}"),
        }
    }
}
