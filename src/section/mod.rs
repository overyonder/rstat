//! The Waybar sections rstat serves, and where their watchers connect.

use std::path::PathBuf;

/// One Waybar module's worth of output.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Section {
    Cpu,
    Memory,
    Disks,
    Network,
    Gpu,
}

impl Section {
    pub const ALL: [Self; 5] = [Self::Cpu, Self::Memory, Self::Disks, Self::Network, Self::Gpu];

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|section| section.name() == name)
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Disks => "disks",
            Self::Network => "network",
            Self::Gpu => "gpu",
        }
    }
}

/// The daemon's listening socket: `$XDG_RUNTIME_DIR/rstat.sock`.
#[must_use]
pub fn daemon_socket_path() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from).join("rstat.sock")
}
