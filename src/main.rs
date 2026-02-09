use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_secs(2);
const PAGE_SIZE: u64 = 4096;
const GPU_DIR: &str = "/sys/class/drm/card1/gt/gt0";

// Display thresholds
const MIN_CPU_PCT: f64 = 1.0;
const MIN_MEM_MB: f64 = 250.0;
const MIN_IO_MBS: f64 = 1.0;

#[derive(Serialize)]
struct WaybarOutput {
    text: String,
    tooltip: String,
    class: String,
}

struct CpuSample {
    total: u64,
    idle: u64,
}

struct ProcInfo {
    pid: u32,
    comm: String,
    utime: u64,
    stime: u64,
    resident: u64, // bytes
    rb: u64,
    wb: u64,
}

struct Sample {
    cpu: CpuSample,
    mem_total: u64,
    mem_available: u64,
    load1: String,
    load5: String,
    load15: String,
    cores: u32,
    gpu_rc6_ms: u64,
    gpu_freq: String,
    gpu_max: String,
    cpu_temp: u64,
    cpu_freq: u64,
    cpu_fmax: u64,
    throttled: Vec<String>,
    profile: String,
    procs: Vec<ProcInfo>,
    ts: Instant,
}

fn read_file(p: &str) -> Option<String> {
    fs::read_to_string(p).ok()
}

fn read_u64(p: &str) -> u64 {
    read_file(p)
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn read_str(p: &str) -> String {
    read_file(p)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "?".into())
}

fn sample_cpu() -> CpuSample {
    let s = read_file("/proc/stat").unwrap_or_default();
    let l = s.lines().next().unwrap_or("");
    let v: Vec<u64> = l
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    let total: u64 = v.iter().sum();
    let idle = v.get(3).copied().unwrap_or(0) + v.get(4).copied().unwrap_or(0);
    CpuSample { total, idle }
}

fn sample_meminfo() -> (u64, u64) {
    let s = read_file("/proc/meminfo").unwrap_or_default();
    let mut mt = 0u64;
    let mut ma = 0u64;
    for l in s.lines() {
        if let Some(r) = l.strip_prefix("MemTotal:") {
            mt = r.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0);
        } else if let Some(r) = l.strip_prefix("MemAvailable:") {
            ma = r.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0);
        }
        if mt > 0 && ma > 0 {
            break;
        }
    }
    (mt, ma)
}

fn sample_loadavg() -> (String, String, String) {
    let s = read_file("/proc/loadavg").unwrap_or_default();
    let mut p = s.split_whitespace();
    let l1 = p.next().unwrap_or("?").to_string();
    let l5 = p.next().unwrap_or("?").to_string();
    let l15 = p.next().unwrap_or("?").to_string();
    (l1, l5, l15)
}

fn nproc() -> u32 {
    let s = read_file("/proc/cpuinfo").unwrap_or_default();
    s.lines().filter(|l| l.starts_with("processor")).count() as u32
}

fn sample_throttle() -> Vec<String> {
    let mut v = Vec::new();
    let Ok(rd) = fs::read_dir(GPU_DIR) else {
        return v;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        let n = name.to_string_lossy();
        if !n.starts_with("throttle_reason_") {
            continue;
        }
        let r = &n["throttle_reason_".len()..];
        if r == "status" || r.starts_with("pl") {
            continue;
        }
        if read_str(&format!("{GPU_DIR}/{n}")) == "1" {
            v.push(r.to_string());
        }
    }
    v
}

fn sample_profile() -> String {
    Command::new("powerprofilesctl")
        .arg("get")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "?".into())
}

fn my_pid() -> u32 {
    std::process::id()
}

fn parent_pid() -> u32 {
    read_file("/proc/self/stat")
        .and_then(|s| {
            let after = s.rfind(')')?;
            let rest = &s[after + 2..];
            let mut p = rest.split_whitespace();
            p.next(); // state
            p.next()?.parse().ok()
        })
        .unwrap_or(0)
}

// Single walk of /proc -- reads stat, statm, io, comm for each PID
fn sample_procs(skip: &[u32]) -> Vec<ProcInfo> {
    let mut v = Vec::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return v;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        let n = name.to_string_lossy();
        let Ok(pid) = n.parse::<u32>() else { continue };
        if skip.contains(&pid) {
            continue;
        }
        let base = format!("/proc/{pid}");

        // stat -> comm, utime, stime
        let Some(st) = read_file(&format!("{base}/stat")) else { continue };
        let Some(lp) = st.find('(') else { continue };
        let Some(rp) = st.rfind(')') else { continue };
        let comm = st[lp + 1..rp].to_string();
        let rest: Vec<&str> = st[rp + 2..].split_whitespace().collect();
        let utime = rest.get(11).and_then(|x| x.parse().ok()).unwrap_or(0u64);
        let stime = rest.get(12).and_then(|x| x.parse().ok()).unwrap_or(0u64);

        // statm -> resident pages
        let resident = read_file(&format!("{base}/statm"))
            .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
            .unwrap_or(0)
            * PAGE_SIZE;

        // io -> read_bytes, write_bytes (may fail for kernel threads)
        let (mut rb, mut wb) = (0u64, 0u64);
        if let Some(s) = read_file(&format!("{base}/io")) {
            for l in s.lines() {
                if let Some(r) = l.strip_prefix("read_bytes: ") {
                    rb = r.trim().parse().unwrap_or(0);
                } else if let Some(r) = l.strip_prefix("write_bytes: ") {
                    wb = r.trim().parse().unwrap_or(0);
                }
            }
        }

        v.push(ProcInfo { pid, comm, utime, stime, resident, rb, wb });
    }
    v
}

fn take_sample(skip: &[u32]) -> Sample {
    let cpu = sample_cpu();
    let (mt, ma) = sample_meminfo();
    let (l1, l5, l15) = sample_loadavg();
    let cores = nproc();
    let rc6 = read_u64(&format!("{GPU_DIR}/rc6_residency_ms"));
    let gf = read_str(&format!("{GPU_DIR}/rps_act_freq_mhz"));
    let gm = read_str(&format!("{GPU_DIR}/rps_max_freq_mhz"));
    let ct = read_u64("/sys/class/thermal/thermal_zone0/temp");
    let cf = read_u64("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq");
    let cfm = read_u64("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq");
    let thr = sample_throttle();
    let prof = sample_profile();
    let procs = sample_procs(skip);
    Sample {
        cpu, mem_total: mt, mem_available: ma,
        load1: l1, load5: l5, load15: l15, cores,
        gpu_rc6_ms: rc6, gpu_freq: gf, gpu_max: gm,
        cpu_temp: ct, cpu_freq: cf, cpu_fmax: cfm,
        throttled: thr, profile: prof, procs, ts: Instant::now(),
    }
}

fn fmt_top_cpu(prev: &[ProcInfo], cur: &[ProcInfo], dt: u64) -> String {
    if dt == 0 {
        return "  ?".into();
    }
    let pm: HashMap<u32, u64> = prev.iter().map(|p| (p.pid, p.utime + p.stime)).collect();
    let mut d: Vec<(f64, &str)> = cur
        .iter()
        .filter_map(|p| {
            let prev_t = pm.get(&p.pid)?;
            let delta = (p.utime + p.stime).saturating_sub(*prev_t);
            let pct = delta as f64 * 100.0 / dt as f64;
            if pct < MIN_CPU_PCT { return None; }
            Some((pct, p.comm.as_str()))
        })
        .collect();
    d.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    d.truncate(5);
    if d.is_empty() { return String::new(); }
    d.iter().map(|(pct, n)| format!("{pct:5.1}%  {n}")).collect::<Vec<_>>().join("\n")
}

fn fmt_top_mem(cur: &[ProcInfo]) -> String {
    let mut d: Vec<(f64, &str)> = cur
        .iter()
        .filter_map(|p| {
            let mb = p.resident as f64 / 1_048_576.0;
            if mb < MIN_MEM_MB { return None; }
            Some((mb, p.comm.as_str()))
        })
        .collect();
    d.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    d.truncate(5);
    if d.is_empty() { return String::new(); }
    d.iter().map(|(mb, n)| format!("{mb:5.0}M  {n}")).collect::<Vec<_>>().join("\n")
}

fn fmt_top_io(prev: &[ProcInfo], cur: &[ProcInfo], elapsed_s: f64) -> String {
    if elapsed_s <= 0.0 {
        return "  ?".into();
    }
    let pm: HashMap<u32, (u64, u64)> = prev.iter().map(|p| (p.pid, (p.rb, p.wb))).collect();
    let mut d: Vec<(f64, f64, f64, &str)> = cur
        .iter()
        .filter_map(|p| {
            let (prb, pwb) = pm.get(&p.pid)?;
            let dr = p.rb.saturating_sub(*prb);
            let dw = p.wb.saturating_sub(*pwb);
            let total = (dr + dw) as f64 / 1_048_576.0 / elapsed_s;
            if total < MIN_IO_MBS { return None; }
            Some((total, dr as f64 / 1_048_576.0 / elapsed_s, dw as f64 / 1_048_576.0 / elapsed_s, p.comm.as_str()))
        })
        .collect();
    d.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    d.truncate(5);
    if d.is_empty() { return String::new(); }
    d.iter()
        .map(|(t, r, w, n)| format!("{t:5.1}M/s  {n} (R:{r:.1} W:{w:.1})"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn emit(prev: &Sample, cur: &Sample, first: bool, sample_dur: Duration) {
    let elapsed = cur.ts.duration_since(prev.ts);
    let elapsed_s = elapsed.as_secs_f64();

    // CPU %
    let cpu_pct = if first {
        "?".into()
    } else {
        let dt = cur.cpu.total.saturating_sub(prev.cpu.total);
        let di = cur.cpu.idle.saturating_sub(prev.cpu.idle);
        if dt == 0 { "0".into() }
        else { format!("{:.0}", 100.0 * (1.0 - di as f64 / dt as f64)) }
    };

    // Memory
    let mt = cur.mem_total;
    let ma = cur.mem_available;
    let mpct = if mt > 0 { 100 * (mt - ma) / mt } else { 0 };
    let mused = (mt - ma) as f64 / 1_048_576.0;
    let mtotal = mt as f64 / 1_048_576.0;

    // Load
    let ratio = cur.load1.parse::<f64>().unwrap_or(0.0) / cur.cores.max(1) as f64;
    let class = if ratio >= 2.0 { "critical" }
        else if ratio >= 1.0 { "warning" }
        else { "normal" };

    // GPU busy %
    let gpu_busy = if first {
        None
    } else {
        let dt_ms = elapsed.as_millis() as u64;
        if dt_ms > 0 {
            let d = cur.gpu_rc6_ms.saturating_sub(prev.gpu_rc6_ms);
            let busy = 100.0 - (d as f64 * 100.0 / dt_ms as f64);
            Some(format!("{:.0}", busy.max(0.0)))
        } else {
            None
        }
    };

    // CPU temp/freq
    let ct = cur.cpu_temp / 1000;
    let cf = cur.cpu_freq as f64 / 1_000_000.0;
    let cfm = cur.cpu_fmax as f64 / 1_000_000.0;

    // Top procs
    let cpu_dt = cur.cpu.total.saturating_sub(prev.cpu.total);
    let top_cpu = if first { String::new() } else {
        fmt_top_cpu(&prev.procs, &cur.procs, cpu_dt)
    };
    let top_mem = fmt_top_mem(&cur.procs);
    let top_io = if first { String::new() } else {
        fmt_top_io(&prev.procs, &cur.procs, elapsed_s)
    };

    // Build tooltip
    let mut tt = format!("CPU: {ct}°C  {cpu_pct}% @ {cf:.1}/{cfm:.1} GHz");
    tt.push_str(&format!("\nMemory: {mused:.1}/{mtotal:.1} GiB ({mpct}%)"));
    tt.push_str(&format!(
        "\nLoad: {} {} {} ({} cores)",
        cur.load1, cur.load5, cur.load15, cur.cores
    ));
    match &gpu_busy {
        Some(b) => tt.push_str(&format!("\niGPU: {b}% @ {}/{} MHz", cur.gpu_freq, cur.gpu_max)),
        None => tt.push_str(&format!("\niGPU: {}/{} MHz", cur.gpu_freq, cur.gpu_max)),
    }
    tt.push_str(&format!("\nProfile: {}", cur.profile));
    if !cur.throttled.is_empty() {
        tt.push_str(&format!("\n⚠ Throttled: {}", cur.throttled.join(", ")));
    }
    if !top_cpu.is_empty() {
        tt.push_str(&format!("\n\n CPU\n{top_cpu}"));
    }
    if !top_mem.is_empty() {
        tt.push_str(&format!("\n\n Memory\n{top_mem}"));
    }
    if !top_io.is_empty() {
        tt.push_str(&format!("\n\n IO/s\n{top_io}"));
    }
    tt.push_str(&format!(
        "\n\nSampled in {:.1}ms",
        sample_dur.as_secs_f64() * 1000.0
    ));

    let out = WaybarOutput {
        text: cur.load1.clone(),
        tooltip: tt,
        class: class.into(),
    };
    let j = serde_json::to_string(&out).unwrap_or_default();
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    let _ = writeln!(lock, "{j}");
    let _ = lock.flush();
}

fn main() {
    let me = my_pid();
    let parent = parent_pid();
    let skip = [me, parent];

    let mut prev = take_sample(&skip);
    emit(&prev, &prev, true, Duration::ZERO);

    loop {
        thread::sleep(INTERVAL);
        let t0 = Instant::now();
        let cur = take_sample(&skip);
        let dur = t0.elapsed();
        emit(&prev, &cur, false, dur);
        prev = cur;
    }
}
