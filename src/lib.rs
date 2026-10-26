//! rstat samples Linux kernel counters through file descriptors it keeps open, and serves each Waybar
//! section's headline and tooltip to the watchers subscribed to it. Nothing is sampled while no watcher
//! is connected, and each section is sampled only while someone watches it.

pub mod daemon;
pub mod process_memory;
pub mod section;
pub mod watch;

mod config;
mod cpu;
mod disks;
mod gpu;
mod markup;
mod memory;
mod network;
mod procfs_file;
