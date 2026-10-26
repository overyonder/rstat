//! The daemon: accepts watchers on a Unix socket, samples each section only while someone watches it,
//! and sends a section's Waybar line to its watchers only when the line changes.
//!
//! Protocol: a watcher connects, writes a section name and a newline, then reads one JSON line per
//! change. It receives the latest line at once if the section is already being sampled.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::cpu::CpuSampler;
use crate::disks::DisksSampler;
use crate::gpu::GpuSampler;
use crate::markup::{MarkupColors, WaybarReport};
use crate::memory::MemorySampler;
use crate::network::NetworkSampler;
use crate::section::{Section, daemon_socket_path};

pub const DEFAULT_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

struct Watcher {
    id:     u64,
    stream: UnixStream,
}

/// State shared between the sampling loop and the connection threads.
#[derive(Default)]
struct Subscriptions {
    watchers:    HashMap<Section, Vec<Watcher>>,
    last_lines:  HashMap<Section, String>,  // The line each watched section last sent
    next_id:     u64,
}

impl Subscriptions {
    fn watched_sections(&self) -> Vec<Section> {
        Section::ALL.into_iter().filter(|section| self.watchers.get(section).is_some_and(|list| !list.is_empty())).collect()
    }

    /// Sends a line to every watcher of a section, dropping those whose connection has gone.
    fn send(&mut self, section: Section, line: &str) {
        if let Some(list) = self.watchers.get_mut(&section) {
            list.retain_mut(|watcher| watcher.stream.write_all(line.as_bytes()).is_ok());
        }
    }
}

/// One sampler per section, opened when the section gains its first watcher and closed when it loses
/// its last, so an unwatched section holds no files and, for the GPU, no driver library.
#[derive(Default)]
struct Samplers {
    cpu:     Option<CpuSampler>,
    memory:  Option<MemorySampler>,
    disks:   Option<DisksSampler>,
    network: Option<NetworkSampler>,
    gpu:     Option<GpuSampler>,
}

impl Samplers {
    fn sample(&mut self, section: Section, colors: &MarkupColors) -> WaybarReport {
        fn sample_with<S>(slot: &mut Option<S>, open: impl FnOnce() -> std::io::Result<S>, sample: impl FnOnce(&mut S) -> WaybarReport) -> WaybarReport {
            if slot.is_none() {
                match open() {
                    Ok(sampler) => *slot = Some(sampler),
                    Err(error) => return WaybarReport::unavailable(&error.to_string()),
                }
            }
            slot.as_mut().map_or_else(|| WaybarReport::unavailable("sampler missing"), sample)
        }
        match section {
            Section::Cpu => sample_with(&mut self.cpu, CpuSampler::open, |sampler| sampler.sample(colors)),
            Section::Memory => sample_with(&mut self.memory, MemorySampler::open, |sampler| sampler.sample(colors)),
            Section::Disks => sample_with(&mut self.disks, DisksSampler::open, |sampler| sampler.sample(colors)),
            Section::Network => sample_with(&mut self.network, NetworkSampler::open, |sampler| sampler.sample(colors)),
            Section::Gpu => sample_with(&mut self.gpu, || Ok(GpuSampler::open()), |sampler| sampler.sample(colors)),
        }
    }

    fn close_unwatched(&mut self, watched: &[Section]) {
        let unwatched = |section| !watched.contains(&section);
        if unwatched(Section::Cpu) {
            self.cpu = None;
        }
        if unwatched(Section::Memory) {
            self.memory = None;
        }
        if unwatched(Section::Disks) {
            self.disks = None;
        }
        if unwatched(Section::Network) {
            self.network = None;
        }
        if unwatched(Section::Gpu) {
            self.gpu = None;
        }
    }
}

/// Runs until the process is stopped.
///
/// # Errors
///
/// Fails if another daemon already listens on the socket, or the socket can't be bound.
pub fn serve_sections_to_watchers(interval: Duration) -> Result<(), Box<dyn std::error::Error>> {
    let path = daemon_socket_path();
    if UnixStream::connect(&path).is_ok() {
        return Err(format!("another rstat daemon is already listening on {}", path.display()).into());
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    let shared = Arc::new((Mutex::new(Subscriptions::default()), Condvar::new()));
    {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || serve_watcher(stream, &shared));
            }
        });
    }

    let colors = MarkupColors::from_environment();
    let mut samplers = Samplers::default();
    let (subscriptions, changed) = &*shared;
    let mut next_sample = Instant::now();
    loop {
        let watched = {
            let mut state = subscriptions.lock().map_err(|_| "subscription lock poisoned")?;
            // Wait for the next sample time, or indefinitely while nothing is watched; a new watcher
            // wakes the loop early so its section is sampled at once.
            loop {
                let watched = state.watched_sections();
                let unsampled = watched.iter().any(|section| !state.last_lines.contains_key(section));
                let now = Instant::now();
                if !watched.is_empty() && (unsampled || now >= next_sample) {
                    break watched;
                }
                state = if watched.is_empty() {
                    changed.wait(state).map_err(|_| "subscription lock poisoned")?
                } else {
                    changed.wait_timeout(state, next_sample - now).map_err(|_| "subscription lock poisoned")?.0
                };
            }
        };
        next_sample = Instant::now() + interval;
        samplers.close_unwatched(&watched);
        let lines: Vec<(Section, String)> = watched.iter().map(|section| (*section, samplers.sample(*section, &colors).to_json_line())).collect();

        let mut state = subscriptions.lock().map_err(|_| "subscription lock poisoned")?;
        for (section, line) in lines {
            if state.last_lines.get(&section) != Some(&line) {
                state.send(section, &line);
                state.last_lines.insert(section, line);
            }
        }
        let still_watched = state.watched_sections();
        state.last_lines.retain(|section, _| still_watched.contains(section));
    }
}

/// Reads the watcher's section, registers it, and holds the connection until the watcher closes it.
fn serve_watcher(stream: UnixStream, shared: &(Mutex<Subscriptions>, Condvar)) {
    let Ok(reader_stream) = stream.try_clone() else { return };
    let mut reader = BufReader::new(reader_stream);
    let mut request = String::new();
    if reader.read_line(&mut request).is_err() {
        return;
    }
    let Some(section) = Section::from_name(request.trim()) else {
        let _ = (&stream).write_all(b"{\"text\":\"?\",\"tooltip\":\"rstat: unknown section\",\"class\":\"critical\"}\n");
        return;
    };
    let (subscriptions, changed) = shared;
    let id = {
        let Ok(mut state) = subscriptions.lock() else { return };
        let id = state.next_id;
        state.next_id += 1;
        let mut watcher = Watcher { id, stream };
        if let Some(line) = state.last_lines.get(&section)
            && watcher.stream.write_all(line.as_bytes()).is_err()
        {
            return;
        }
        state.watchers.entry(section).or_default().push(watcher);
        id
    };
    changed.notify_one();
    // A watcher sends nothing more; end of stream means it has gone, and its section may stop sampling.
    let mut rest = String::new();
    while matches!(reader.read_line(&mut rest), Ok(read) if read > 0) {
        rest.clear();
    }
    if let Ok(mut state) = subscriptions.lock()
        && let Some(list) = state.watchers.get_mut(&section)
    {
        list.retain(|watcher| watcher.id != id);
    }
}
