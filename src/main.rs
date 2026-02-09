use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Seek, Write};
use std::os::fd::RawFd;
use std::thread;
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_secs(2);
const PAGE_SIZE: u64 = 4096;
const GPU_DIR: &str = "/sys/class/drm/card1/gt/gt0";
const TOP_N: usize = 5;

const MIN_CPU_PCT: f64 = 1.0;
const MIN_MEM_BYTES: u64 = 250 * 1048576;
const MIN_IO_BYTES: u64 = 1048576;

const COMM_LEN: usize = 16;

#[derive(Serialize)]
struct WaybarOutput {
    text: String,
    tooltip: String,
    class: String,
}

#[derive(Clone, Copy)]
struct TopEntry { val: u64, comm: [u8; COMM_LEN], comm_len: u8 }

#[derive(Clone, Copy)]
struct IoEntry { total: u64, dr: u64, dw: u64, comm: [u8; COMM_LEN], comm_len: u8 }

struct Top5 { e: [TopEntry; TOP_N], n: usize }
struct IoTop5 { e: [IoEntry; TOP_N], n: usize }

impl Top5 {
    fn new() -> Self {
        Self { e: [TopEntry { val: 0, comm: [0; COMM_LEN], comm_len: 0 }; TOP_N], n: 0 }
    }
    fn try_insert(&mut self, val: u64, comm: &[u8]) {
        if self.n < TOP_N {
            self.e[self.n] = Self::mk(val, comm);
            self.n += 1;
        } else if val > self.e[self.min_idx()].val {
            self.e[self.min_idx()] = Self::mk(val, comm);
        }
    }
    fn min_idx(&self) -> usize {
        let mut mi = 0;
        for i in 1..self.n { if self.e[i].val < self.e[mi].val { mi = i; } }
        mi
    }
    fn mk(val: u64, comm: &[u8]) -> TopEntry {
        let mut c = [0u8; COMM_LEN];
        let l = comm.len().min(COMM_LEN);
        c[..l].copy_from_slice(&comm[..l]);
        TopEntry { val, comm: c, comm_len: l as u8 }
    }
    fn sorted(&mut self) -> &[TopEntry] {
        self.e[..self.n].sort_by(|a, b| b.val.cmp(&a.val));
        &self.e[..self.n]
    }
}

impl IoTop5 {
    fn new() -> Self {
        Self { e: [IoEntry { total: 0, dr: 0, dw: 0, comm: [0; COMM_LEN], comm_len: 0 }; TOP_N], n: 0 }
    }
    fn try_insert(&mut self, total: u64, dr: u64, dw: u64, comm: &[u8]) {
        let entry = Self::mk(total, dr, dw, comm);
        if self.n < TOP_N {
            self.e[self.n] = entry;
            self.n += 1;
        } else {
            let mi = self.min_idx();
            if total > self.e[mi].total { self.e[mi] = entry; }
        }
    }
    fn min_idx(&self) -> usize {
        let mut mi = 0;
        for i in 1..self.n { if self.e[i].total < self.e[mi].total { mi = i; } }
        mi
    }
    fn mk(total: u64, dr: u64, dw: u64, comm: &[u8]) -> IoEntry {
        let mut c = [0u8; COMM_LEN];
        let l = comm.len().min(COMM_LEN);
        c[..l].copy_from_slice(&comm[..l]);
        IoEntry { total, dr, dw, comm: c, comm_len: l as u8 }
    }
    fn sorted(&mut self) -> &[IoEntry] {
        self.e[..self.n].sort_by(|a, b| b.total.cmp(&a.total));
        &self.e[..self.n]
    }
}

fn comm_str(c: &[u8; COMM_LEN], l: u8) -> &str {
    unsafe { std::str::from_utf8_unchecked(&c[..l as usize]) }
}

// sysfs file handles (no /proc)
struct SysFds {
    temp: fs::File,
    freq: fs::File,
    fmax: fs::File,
    rc6: fs::File,
    gpu_freq: fs::File,
    gpu_max: fs::File,
    profile: fs::File,
}

impl SysFds {
    fn open() -> Self {
        Self {
            temp: fs::File::open("/sys/class/thermal/thermal_zone0/temp").expect("thermal"),
            freq: fs::File::open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq").expect("freq"),
            fmax: fs::File::open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq").expect("fmax"),
            rc6: fs::File::open(&format!("{GPU_DIR}/rc6_residency_ms")).expect("rc6"),
            gpu_freq: fs::File::open(&format!("{GPU_DIR}/rps_act_freq_mhz")).expect("gpu_freq"),
            gpu_max: fs::File::open(&format!("{GPU_DIR}/rps_max_freq_mhz")).expect("gpu_max"),
            profile: fs::File::open("/sys/firmware/acpi/platform_profile").expect("profile"),
        }
    }
}

fn reread(f: &mut fs::File, buf: &mut [u8]) -> usize {
    let _ = f.seek(io::SeekFrom::Start(0));
    f.read(buf).unwrap_or(0)
}

fn reread_u64(f: &mut fs::File, buf: &mut [u8]) -> u64 {
    let n = reread(f, buf);
    parse_u64_trim(&buf[..n])
}

fn parse_u64_trim(b: &[u8]) -> u64 {
    let mut v = 0u64;
    let mut started = false;
    for &c in b {
        if c == b'\n' { break; }
        if c >= b'0' && c <= b'9' { v = v * 10 + (c - b'0') as u64; started = true; }
        else if started { break; }
    }
    v
}

fn read_raw(path: &str, buf: &mut [u8]) -> Option<usize> {
    let mut f = fs::File::open(path).ok()?;
    f.read(buf).ok()
}

// --- sysinfo() for memory + load averages ---

fn get_sysinfo() -> libc::sysinfo {
    let mut si: libc::sysinfo = unsafe { std::mem::zeroed() };
    unsafe { libc::sysinfo(&mut si) };
    si
}

// --- eBPF loader ---

const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_GET_NEXT_KEY: u32 = 4;
const BPF_PROG_LOAD: u32 = 5;

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;

const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_EVENT_IOC_ENABLE: u64 = 0x2400;
const PERF_EVENT_IOC_SET_BPF: u64 = 0x40042408;

const BPF_INSN_SIZE: usize = 8;
const BPF_LD_IMM64: u8 = 0x18;

#[repr(C)]
struct BpfAttrMapCreate {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
}

#[repr(C)]
#[derive(Clone)]
struct BpfMapDef {
    name: String,
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    fd: RawFd,
}

// Must match struct pid_stats in probe.bpf.c
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfPidStats {
    cpu_ns: u64,
    rss_pages: u64,
    io_rb: u64,
    io_wb: u64,
    comm: [u8; 16],
}

struct BpfLoader {
    maps: Vec<BpfMapDef>,
    prog_fds: Vec<RawFd>,
    perf_fds: Vec<RawFd>,
    stats_fd: RawFd,
}

unsafe fn bpf_sys(cmd: u32, attr: *const u8, size: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_bpf, cmd as i64, attr as i64, size as i64) }
}

fn bpf_map_create(map_type: u32, key_size: u32, val_size: u32, max_entries: u32) -> Option<RawFd> {
    let a = BpfAttrMapCreate { map_type, key_size, value_size: val_size, max_entries };
    let fd = unsafe { bpf_sys(BPF_MAP_CREATE, &a as *const _ as *const u8,
        std::mem::size_of::<BpfAttrMapCreate>() as u32) };
    if fd < 0 { None } else { Some(fd as RawFd) }
}

fn bpf_map_lookup(fd: RawFd, key: &[u8], val: &mut [u8]) -> bool {
    #[repr(C)]
    struct A { fd: u32, _p: u32, key: u64, val: u64 }
    let a = A { fd: fd as u32, _p: 0, key: key.as_ptr() as u64, val: val.as_mut_ptr() as u64 };
    unsafe { bpf_sys(BPF_MAP_LOOKUP_ELEM, &a as *const _ as *const u8, std::mem::size_of::<A>() as u32) == 0 }
}

fn bpf_map_get_next_key(fd: RawFd, key: Option<&[u8]>, next: &mut [u8]) -> bool {
    #[repr(C)]
    struct A { fd: u32, _p: u32, key: u64, next: u64 }
    let kp = key.map(|k| k.as_ptr() as u64).unwrap_or(0);
    let a = A { fd: fd as u32, _p: 0, key: kp, next: next.as_mut_ptr() as u64 };
    unsafe { bpf_sys(BPF_MAP_GET_NEXT_KEY, &a as *const _ as *const u8, std::mem::size_of::<A>() as u32) == 0 }
}

fn bpf_prog_load(prog_type: u32, insns: &[u8], license: &[u8], log_buf: &mut [u8]) -> Option<RawFd> {
    #[repr(C)]
    struct A {
        prog_type: u32, insn_cnt: u32, insns: u64, license: u64,
        log_level: u32, log_size: u32, log_buf: u64,
        kern_version: u32, prog_flags: u32,
        _pad: [u64; 16],
    }
    let a = A {
        prog_type, insn_cnt: (insns.len() / BPF_INSN_SIZE) as u32,
        insns: insns.as_ptr() as u64, license: license.as_ptr() as u64,
        log_level: if log_buf.is_empty() { 0 } else { 1 },
        log_size: log_buf.len() as u32, log_buf: log_buf.as_mut_ptr() as u64,
        kern_version: 0, prog_flags: 0, _pad: [0; 16],
    };
    let fd = unsafe { bpf_sys(BPF_PROG_LOAD, &a as *const _ as *const u8, std::mem::size_of::<A>() as u32) };
    if fd < 0 { None } else { Some(fd as RawFd) }
}

fn tracepoint_id(cat: &str, name: &str) -> Option<u64> {
    let p = format!("/sys/kernel/tracing/events/{cat}/{name}/id");
    let mut buf = [0u8; 32];
    let n = read_raw(&p, &mut buf)?;
    Some(parse_u64_trim(&buf[..n]))
}

fn perf_event_open_tracepoint(tp_id: u64, cpu: i32) -> Option<RawFd> {
    #[repr(C)]
    struct PerfEventAttr {
        type_: u32, size: u32, config: u64, sample_period: u64,
        sample_type: u64, read_format: u64, flags: u64,
        wakeup_events: u32, bp_type: u32, config1: u64,
    }
    let mut a: PerfEventAttr = unsafe { std::mem::zeroed() };
    a.type_ = PERF_TYPE_TRACEPOINT;
    a.size = std::mem::size_of::<PerfEventAttr>() as u32;
    a.config = tp_id;
    let fd = unsafe {
        libc::syscall(libc::SYS_perf_event_open, &a as *const _, -1i32, cpu, -1i32, 0u64)
    };
    if fd < 0 { None } else { Some(fd as RawFd) }
}

impl BpfLoader {
    fn load(obj_path: &str) -> Option<Self> {
        let data = fs::read(obj_path).ok()?;
        let elf = goblin::elf::Elf::parse(&data).ok()?;

        let mut maps = vec![
            BpfMapDef {
                name: "stats".into(), map_type: BPF_MAP_TYPE_HASH,
                key_size: 4, value_size: std::mem::size_of::<BpfPidStats>() as u32,
                max_entries: 8192, fd: -1,
            },
            BpfMapDef {
                name: "sys".into(), map_type: BPF_MAP_TYPE_ARRAY,
                key_size: 4, value_size: 8, // sizeof(sys_stats) = u64 idle_ns
                max_entries: 1, fd: -1,
            },
            BpfMapDef {
                name: "sched_start".into(), map_type: BPF_MAP_TYPE_HASH,
                key_size: 4, value_size: 8,
                max_entries: 8192, fd: -1,
            },
        ];

        for m in &mut maps {
            m.fd = bpf_map_create(m.map_type, m.key_size, m.value_size, m.max_entries)?;
        }

        let maps_shndx = elf.section_headers.iter().position(|s| {
            elf.shdr_strtab.get_at(s.sh_name).map(|n| n == ".maps").unwrap_or(false)
        });

        let mut sym_to_fd: HashMap<usize, RawFd> = HashMap::new();
        if let Some(mi) = maps_shndx {
            for (si, sym) in elf.syms.iter().enumerate() {
                if sym.st_shndx == mi {
                    let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
                    for m in &maps {
                        if m.name == name { sym_to_fd.insert(si, m.fd); }
                    }
                }
            }
        }

        let stats_fd = maps.iter().find(|m| m.name == "stats").map(|m| m.fd).unwrap_or(-1);

        let license = b"GPL\0";
        let mut prog_fds = Vec::new();
        let mut perf_fds = Vec::new();

        let prog_sections: Vec<(usize, String)> = elf.section_headers.iter().enumerate()
            .filter_map(|(i, s)| {
                let name = elf.shdr_strtab.get_at(s.sh_name)?;
                if name.starts_with("tracepoint/") && s.sh_type == goblin::elf::section_header::SHT_PROGBITS && s.sh_size > 0 {
                    Some((i, name.to_string()))
                } else { None }
            }).collect();

        for (shndx, sec_name) in &prog_sections {
            let sh = &elf.section_headers[*shndx];
            let mut insns = data[sh.sh_offset as usize..(sh.sh_offset + sh.sh_size) as usize].to_vec();

            for rel_sh in &elf.section_headers {
                if rel_sh.sh_type != goblin::elf::section_header::SHT_REL { continue; }
                if rel_sh.sh_info as usize != *shndx { continue; }

                let rd = &data[rel_sh.sh_offset as usize..(rel_sh.sh_offset + rel_sh.sh_size) as usize];
                let rc = rel_sh.sh_size as usize / 16;

                for i in 0..rc {
                    let off = i * 16;
                    let r_offset = u64::from_le_bytes(rd[off..off+8].try_into().unwrap());
                    let r_info = u64::from_le_bytes(rd[off+8..off+16].try_into().unwrap());
                    let sym_idx = (r_info >> 32) as usize;

                    if let Some(&fd) = sym_to_fd.get(&sym_idx) {
                        let io = r_offset as usize;
                        if io + 16 <= insns.len() && insns[io] == BPF_LD_IMM64 {
                            insns[io + 4..io + 8].copy_from_slice(&(fd as u32).to_le_bytes());
                            insns[io + 1] = (insns[io + 1] & 0x0f) | 0x10;
                        }
                    }
                }
            }

            let mut log = vec![0u8; 65536];
            let fd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, &insns, license, &mut log);
            let fd = match fd {
                Some(f) => f,
                None => {
                    let ls = std::str::from_utf8(&log).unwrap_or("").trim_end_matches('\0');
                    if !ls.is_empty() {
                        eprintln!("bpf: prog load failed for {sec_name}:\n{ls}");
                    } else {
                        eprintln!("bpf: prog load failed for {sec_name}: {}", std::io::Error::last_os_error());
                    }
                    for m in &maps { unsafe { libc::close(m.fd); } }
                    for f in &prog_fds { unsafe { libc::close(*f); } }
                    for f in &perf_fds { unsafe { libc::close(*f); } }
                    return None;
                }
            };
            prog_fds.push(fd);

            let parts = sec_name.splitn(3, '/').collect::<Vec<&str>>();
            if parts.len() != 3 { continue; }
            let (cat, tp_name) = (parts[1], parts[2]);

            let tp_id = match tracepoint_id(cat, tp_name) {
                Some(id) => id,
                None => { eprintln!("bpf: tracepoint {cat}/{tp_name} not found"); continue; }
            };

            let ncpu = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as i32;
            for cpu in 0..ncpu {
                let Some(pfd) = perf_event_open_tracepoint(tp_id, cpu) else { continue };
                if cpu == 0 {
                    let r = unsafe { libc::ioctl(pfd, PERF_EVENT_IOC_SET_BPF as libc::c_ulong, fd) };
                    if r < 0 {
                        eprintln!("bpf: attach failed for {sec_name}: {}", std::io::Error::last_os_error());
                        unsafe { libc::close(pfd); }
                        continue;
                    }
                }
                unsafe { libc::ioctl(pfd, PERF_EVENT_IOC_ENABLE as libc::c_ulong, 0) };
                perf_fds.push(pfd);
            }
        }

        if prog_fds.is_empty() {
            for m in &maps { unsafe { libc::close(m.fd); } }
            return None;
        }

        Some(BpfLoader { maps, prog_fds, perf_fds, stats_fd })
    }

    // Read all stats without deleting (cumulative values, userspace computes deltas)
    fn read_stats(&self) -> HashMap<u32, BpfPidStats> {
        let mut out = HashMap::new();
        let mut key = [0u8; 4];
        let mut prev_key: Option<[u8; 4]> = None;
        let mut val = BpfPidStats::default();

        while bpf_map_get_next_key(self.stats_fd, prev_key.as_ref().map(|k| k.as_slice()), &mut key) {
            if bpf_map_lookup(self.stats_fd, &key, unsafe {
                std::slice::from_raw_parts_mut(&mut val as *mut _ as *mut u8, std::mem::size_of::<BpfPidStats>())
            }) {
                out.insert(u32::from_ne_bytes(key), val);
            }
            prev_key = Some(key);
        }
        out
    }

}

impl Drop for BpfLoader {
    fn drop(&mut self) {
        for f in &self.perf_fds { unsafe { libc::close(*f); } }
        for f in &self.prog_fds { unsafe { libc::close(*f); } }
        for m in &self.maps { unsafe { libc::close(m.fd); } }
    }
}

fn sample_throttle(buf: &mut [u8]) -> ([u8; 64], usize) {
    let mut out = [0u8; 64];
    let mut pos = 0;
    let Ok(rd) = fs::read_dir(GPU_DIR) else { return (out, 0) };
    for e in rd.flatten() {
        let name = e.file_name();
        let n = name.as_encoded_bytes();
        if !n.starts_with(b"throttle_reason_") { continue; }
        let r = &n[16..];
        if r == b"status" || r.starts_with(b"pl") { continue; }
        let path = format!("{GPU_DIR}/{}", unsafe { std::str::from_utf8_unchecked(n) });
        if let Some(sz) = read_raw(&path, buf) {
            if sz > 0 && buf[0] == b'1' {
                if pos > 0 && pos + 2 < 64 { out[pos] = b','; out[pos+1] = b' '; pos += 2; }
                let l = r.len().min(64 - pos);
                out[pos..pos+l].copy_from_slice(&r[..l]);
                pos += l;
            }
        }
    }
    (out, pos)
}

struct Sample {
    cpu_pct: f64,       // system-wide CPU% from BPF idle tracking
    mem_total: u64,     // bytes, from sysinfo()
    mem_free_approx: u64, // freeram + bufferram, from sysinfo()
    load: [f64; 3],     // from sysinfo()
    cores: u32,
    gpu_rc6_ms: u64,
    gpu_freq: u64,
    gpu_max: u64,
    cpu_temp: u64,
    cpu_freq: u64,
    cpu_fmax: u64,
    throttle: ([u8; 64], usize),
    profile: [u8; 32],
    profile_len: u8,
    top_cpu: Top5,
    top_mem: Top5,
    top_io: IoTop5,
    ts: Instant,
}

// Previous BPF state for delta computation
struct PrevBpf {
    stats: HashMap<u32, BpfPidStats>,
}

impl PrevBpf {
    fn new() -> Self { Self { stats: HashMap::new() } }
}

fn take_sample(
    skip: &[u32],
    buf: &mut [u8],
    fds: &mut SysFds,
    cores: u32,
    elapsed_s: f64,
    bpf: &BpfLoader,
    prev: &mut PrevBpf,
) -> Sample {
    // sysinfo() for memory + load (no /proc)
    let si = get_sysinfo();
    let mu = si.mem_unit.max(1) as u64;
    let mem_total = si.totalram * mu;
    let mem_free_approx = (si.freeram + si.bufferram) * mu;
    let load = [
        si.loads[0] as f64 / 65536.0,
        si.loads[1] as f64 / 65536.0,
        si.loads[2] as f64 / 65536.0,
    ];

    // sysfs reads (local, not /proc)
    let rc6 = reread_u64(&mut fds.rc6, buf);
    let gf = reread_u64(&mut fds.gpu_freq, buf);
    let gm = reread_u64(&mut fds.gpu_max, buf);
    let ct = reread_u64(&mut fds.temp, buf);
    let cf = reread_u64(&mut fds.freq, buf);
    let cfm = reread_u64(&mut fds.fmax, buf);
    let thr = sample_throttle(buf);
    let pn = reread(&mut fds.profile, buf);
    let mut profile = [0u8; 32];
    let mut pl = pn;
    while pl > 0 && (buf[pl - 1] == b'\n' || buf[pl - 1] == b' ') { pl -= 1; }
    let pl = pl.min(32);
    profile[..pl].copy_from_slice(&buf[..pl]);

    // BPF: read stats map (no deletion, cumulative)
    let cur_stats = bpf.read_stats();

    let total_ns = (elapsed_s * 1_000_000_000.0 * cores as f64) as u64;

    // Per-PID deltas from BPF map
    let mut top_cpu = Top5::new();
    let mut top_mem = Top5::new();
    let mut top_io = IoTop5::new();
    let min_io_total = if elapsed_s > 0.0 { (MIN_IO_BYTES as f64 * elapsed_s) as u64 } else { u64::MAX };
    let total_cpu_ns = total_ns;
    let mut busy_ns = 0u64;

    for (&pid, st) in &cur_stats {
        if skip.contains(&pid) || pid == 0 { continue; }
        let cl = st.comm.iter().position(|&b| b == 0).unwrap_or(16);
        if cl == 0 { continue; }

        // CPU delta (nanoseconds)
        let prev_cpu = prev.stats.get(&pid).map(|p| p.cpu_ns).unwrap_or(0);
        let dcpu = st.cpu_ns.saturating_sub(prev_cpu);
        busy_ns += dcpu;
        if total_cpu_ns > 0 && dcpu > 0 {
            let threshold_ns = (MIN_CPU_PCT * total_cpu_ns as f64 / 100.0) as u64;
            if dcpu >= threshold_ns {
                top_cpu.try_insert(dcpu, &st.comm[..cl]);
            }
        }

        // Memory: RSS from BPF snapshot (pages → bytes)
        let rss_bytes = st.rss_pages * PAGE_SIZE;
        if rss_bytes >= MIN_MEM_BYTES {
            top_mem.try_insert(rss_bytes, &st.comm[..cl]);
        }

        // IO delta (cumulative counters)
        let (prev_rb, prev_wb) = prev.stats.get(&pid).map(|p| (p.io_rb, p.io_wb)).unwrap_or((0, 0));
        let drb = st.io_rb.saturating_sub(prev_rb);
        let dwb = st.io_wb.saturating_sub(prev_wb);
        let dt = drb + dwb;
        if dt >= min_io_total {
            top_io.try_insert(dt, drb, dwb, &st.comm[..cl]);
        }
    }

    // System CPU% from sum of all per-PID busy time
    let cpu_pct = if total_ns > 0 && elapsed_s > 0.0 {
        (busy_ns as f64 / total_ns as f64 * 100.0).clamp(0.0, 100.0)
    } else { 0.0 };

    // Rotate state
    prev.stats = cur_stats;

    Sample {
        cpu_pct, mem_total, mem_free_approx, load, cores,
        gpu_rc6_ms: rc6, gpu_freq: gf, gpu_max: gm,
        cpu_temp: ct, cpu_freq: cf, cpu_fmax: cfm,
        throttle: thr, profile, profile_len: pl as u8,
        top_cpu, top_mem, top_io, ts: Instant::now(),
    }
}

fn emit(prev: Option<&Sample>, cur: &mut Sample, dur: Duration) {
    let elapsed_s = prev.map(|p| cur.ts.duration_since(p.ts).as_secs_f64()).unwrap_or(0.0);

    let cpu_pct = if prev.is_some() { format!("{:.0}", cur.cpu_pct) } else { "?".into() };

    let mt = cur.mem_total;
    let mfree = cur.mem_free_approx;
    let mused = mt.saturating_sub(mfree);
    let mpct = if mt > 0 { 100 * mused / mt } else { 0 };
    let mused_g = mused as f64 / 1_073_741_824.0;
    let mtotal_g = mt as f64 / 1_073_741_824.0;

    let ratio = cur.load[0] / cur.cores.max(1) as f64;
    let class = if ratio >= 2.0 { "critical" } else if ratio >= 1.0 { "warning" } else { "normal" };

    let gpu_busy = match prev {
        None => None,
        Some(p) => {
            let dt_ms = (elapsed_s * 1000.0) as u64;
            if dt_ms > 0 {
                let d = cur.gpu_rc6_ms.saturating_sub(p.gpu_rc6_ms);
                Some(format!("{:.0}", (100.0 - d as f64 * 100.0 / dt_ms as f64).max(0.0)))
            } else { None }
        }
    };

    let ct = cur.cpu_temp / 1000;
    let cf = cur.cpu_freq as f64 / 1_000_000.0;
    let cfm = cur.cpu_fmax as f64 / 1_000_000.0;
    let prof = unsafe { std::str::from_utf8_unchecked(&cur.profile[..cur.profile_len as usize]) };

    let mut tt = String::with_capacity(512);
    tt.push_str(&format!("Load: {:.2} {:.2} {:.2} ({} cores)",
        cur.load[0], cur.load[1], cur.load[2], cur.cores));
    match &gpu_busy {
        Some(b) => tt.push_str(&format!("\niGPU: {b}% @ {}/{} MHz", cur.gpu_freq, cur.gpu_max)),
        None => tt.push_str(&format!("\niGPU: {}/{} MHz", cur.gpu_freq, cur.gpu_max)),
    }
    tt.push_str(&format!("\nProfile: {prof}"));
    if cur.throttle.1 > 0 {
        let ts = unsafe { std::str::from_utf8_unchecked(&cur.throttle.0[..cur.throttle.1]) };
        tt.push_str(&format!("\n⚠ Throttled: {ts}"));
    }

    tt.push_str(&format!("\n\n CPU    {ct}°C    {cpu_pct}%    {cf:.1}/{cfm:.1} GHz"));
    let cpu_entries = cur.top_cpu.sorted();
    if cpu_entries.is_empty() {
        tt.push_str("\n  ---");
    } else {
        let total_ns = elapsed_s * cur.cores as f64 * 1_000_000_000.0;
        for e in cpu_entries {
            let pct = if total_ns > 0.0 { e.val as f64 * 100.0 / total_ns } else { 0.0 };
            tt.push_str(&format!("\n{pct:5.1}%  {}", comm_str(&e.comm, e.comm_len)));
        }
    }

    tt.push_str(&format!("\n\n Memory    {mused_g:.1}/{mtotal_g:.1} GiB ({mpct}%)"));
    let mem_entries = cur.top_mem.sorted();
    if mem_entries.is_empty() {
        tt.push_str("\n  ---");
    } else {
        for e in mem_entries {
            let mb = e.val as f64 / 1_048_576.0;
            tt.push_str(&format!("\n{mb:5.0}M  {}", comm_str(&e.comm, e.comm_len)));
        }
    }

    tt.push_str("\n\n IO/s");
    let io_entries = cur.top_io.sorted();
    if io_entries.is_empty() {
        tt.push_str("\n  ---");
    } else {
        for e in io_entries {
            let t = e.total as f64 / 1_048_576.0 / elapsed_s;
            let r = e.dr as f64 / 1_048_576.0 / elapsed_s;
            let w = e.dw as f64 / 1_048_576.0 / elapsed_s;
            tt.push_str(&format!("\n{t:5.1}M/s  {} (R:{r:.1} W:{w:.1})", comm_str(&e.comm, e.comm_len)));
        }
    }

    tt.push_str(&format!("\n\nSampled in {:.1}ms", dur.as_secs_f64() * 1000.0));

    let out = WaybarOutput {
        text: format!("{:.2}", cur.load[0]),
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
    let mut buf = [0u8; 4096];
    let me = std::process::id();
    let parent = unsafe { libc::getppid() } as u32;
    let skip = [me, parent];
    let cores = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as u32;
    let mut fds = SysFds::open();
    let args: Vec<String> = std::env::args().skip(1).collect();

    let probe_path = args.iter().find(|a| a.ends_with(".bpf.o"))
        .cloned()
        .unwrap_or_else(|| {
            let exe = std::env::current_exe().unwrap_or_default();
            let dir = exe.parent().unwrap_or(std::path::Path::new("."));
            dir.join("probe.bpf.o").to_string_lossy().into_owned()
        });

    let bpf = BpfLoader::load(&probe_path).unwrap_or_else(|| {
        eprintln!("rstat: failed to load eBPF probe from {probe_path}");
        std::process::exit(1);
    });
    eprintln!("rstat: eBPF active ({probe_path})");

    let bench = args.iter().any(|a| a == "--bench");
    let bench_n: usize = if bench {
        args.iter().find_map(|a| a.parse::<usize>().ok()).unwrap_or(100)
    } else { 0 };

    let mut pb = PrevBpf::new();

    if bench {
        let mut prev = take_sample(&skip, &mut buf, &mut fds, cores, 0.0, &bpf, &mut pb);
        thread::sleep(Duration::from_millis(10));

        let mut times = Vec::with_capacity(bench_n);
        for _ in 0..bench_n {
            thread::sleep(Duration::from_millis(1));
            let t0 = Instant::now();
            let es = t0.duration_since(prev.ts).as_secs_f64();
            let cur = take_sample(&skip, &mut buf, &mut fds, cores, es, &bpf, &mut pb);
            times.push(t0.elapsed());
            prev = cur;
        }
        times.sort();
        let sum: Duration = times.iter().sum();
        let avg = sum / times.len() as u32;
        let p50 = times[times.len() / 2];
        let p95 = times[times.len() * 95 / 100];
        let p99 = times[times.len() * 99 / 100];
        eprintln!("n={bench_n}  avg={:.2}ms  p50={:.2}ms  p95={:.2}ms  p99={:.2}ms  min={:.2}ms  max={:.2}ms",
            avg.as_secs_f64() * 1000.0, p50.as_secs_f64() * 1000.0,
            p95.as_secs_f64() * 1000.0, p99.as_secs_f64() * 1000.0,
            times[0].as_secs_f64() * 1000.0, times.last().unwrap().as_secs_f64() * 1000.0);
        return;
    }

    let mut prev = take_sample(&skip, &mut buf, &mut fds, cores, 0.0, &bpf, &mut pb);
    emit(None, &mut prev, Duration::ZERO);

    loop {
        thread::sleep(INTERVAL);
        let t0 = Instant::now();
        let es = t0.duration_since(prev.ts).as_secs_f64();
        let mut cur = take_sample(&skip, &mut buf, &mut fds, cores, es, &bpf, &mut pb);
        let dur = t0.elapsed();
        emit(Some(&prev), &mut cur, dur);
        prev = cur;
    }
}
