//! A kernel pseudo-file kept open and re-read from offset zero on every sample, which avoids an open
//! and close per read. Procfs and sysfs regenerate the content on each read at offset zero.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

pub(crate) struct ProcfsFile {
    file:   File,
    buffer: Vec<u8>,  // Reused across reads; grows to the largest content seen
}

impl ProcfsFile {
    pub(crate) fn open(path: impl AsRef<Path>) -> Option<Self> {
        File::open(path).ok().map(|file| Self { file, buffer: Vec::with_capacity(4096) })
    }

    /// The file's whole current content, or an empty string if the read fails.
    pub(crate) fn read(&mut self) -> &str {
        self.buffer.clear();
        let mut offset = 0;
        loop {
            if self.buffer.len() == self.buffer.capacity() {
                self.buffer.reserve(self.buffer.capacity().max(4096));
            }
            let spare = self.buffer.capacity() - self.buffer.len();
            let start = self.buffer.len();
            self.buffer.resize(start + spare, 0);
            match self.file.read_at(&mut self.buffer[start..], offset) {
                Ok(0) | Err(_) => {
                    self.buffer.truncate(start);
                    break;
                }
                Ok(read) => {
                    self.buffer.truncate(start + read);
                    offset += read as u64;
                    if read < spare {
                        break;  // A short read is the end; reading on would make the kernel regenerate the file
                    }
                }
            }
        }
        std::str::from_utf8(&self.buffer).unwrap_or("")
    }

    /// The first whitespace-separated value of the content, parsed.
    pub(crate) fn read_value<T: std::str::FromStr>(&mut self) -> Option<T> {
        self.read().split_whitespace().next()?.parse().ok()
    }
}

/// Reads a small file once, for values that change rarely or are read only occasionally.
pub(crate) fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|text| text.trim().to_owned())
}

/// The 10s, 60s and 300s averages and the cumulative total of one PSI line (`some` or `full`).
#[derive(Clone, Copy, Default)]
pub(crate) struct PressureLine {
    pub(crate) ten_seconds:   f64,
    pub(crate) one_minute:    f64,
    pub(crate) five_minutes:  f64,
}

/// Parses `/proc/pressure/*`: returns the `some` and `full` lines.
pub(crate) fn parse_pressure(text: &str) -> (PressureLine, PressureLine) {
    let mut some = PressureLine::default();
    let mut full = PressureLine::default();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let target = match fields.next() {
            Some("some") => &mut some,
            Some("full") => &mut full,
            _ => continue,
        };
        for field in fields {
            let Some((key, value)) = field.split_once('=') else { continue };
            let Ok(value) = value.parse::<f64>() else { continue };
            match key {
                "avg10" => target.ten_seconds = value,
                "avg60" => target.one_minute = value,
                "avg300" => target.five_minutes = value,
                _ => {}
            }
        }
    }
    (some, full)
}

/// Looks up `name` in `key value` lines such as /proc/vmstat, or `key: value kB` lines such as
/// /proc/meminfo (the trailing colon is ignored).
pub(crate) fn keyed_value(text: &str, name: &str) -> u64 {
    text.lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()?.trim_end_matches(':') == name).then(|| fields.next()?.parse().ok())?
        })
        .unwrap_or(0)
}

/// Splits a `/proc/PID/stat` or `/proc/PID/task/TID/stat` line into the command name and the fields
/// after it, starting with the state. The name is parenthesised and may contain spaces or parentheses.
pub(crate) fn split_process_stat(stat: &str) -> Option<(&str, std::str::SplitWhitespace<'_>)> {
    let (open, close) = (stat.find('(')?, stat.rfind(')')?);
    Some((stat.get(open + 1..close)?, stat.get(close + 1..)?.split_whitespace()))
}
