use std::fmt::Write as FmtWrite;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::{fs, thread};

const INTERVALS: [u64; 6] = [2000, 1000, 250, 100, 25, 2000];
static INTERVAL_MS: AtomicU64 = AtomicU64::new(2000);
static SHOW_KTHREADS: AtomicBool = AtomicBool::new(false);
const PAGE_SIZE: u64 = 4096;
const GPU_DIR: &str = "/sys/class/drm/card1/gt/gt0";
const TOP_N: usize = 5;
const MIN_CPU_PCT: f64 = 1.0;
const MIN_MEM_BYTES: u64 = 250 * 1048576;
const MIN_IO_BYTES: u64 = 1048576;
const COMM_LEN: usize = 16;
const MAX_PIDS: usize = 8192;

// --- Top-N tracking (stack-allocated, no heap) ---

#[derive(Clone, Copy)]
struct TopEntry {
    val: u64,
    comm: [u8; COMM_LEN],
    cl: u8,
}
#[derive(Clone, Copy)]
struct IoEntry {
    total: u64,
    dr: u64,
    dw: u64,
    comm: [u8; COMM_LEN],
    cl: u8,
}

struct Top5 {
    e: [TopEntry; TOP_N],
    n: usize,
}
struct IoTop5 {
    e: [IoEntry; TOP_N],
    n: usize,
}

const EMPTY_TE: TopEntry = TopEntry {
    val: 0,
    comm: [0; COMM_LEN],
    cl: 0,
};
const EMPTY_IE: IoEntry = IoEntry {
    total: 0,
    dr: 0,
    dw: 0,
    comm: [0; COMM_LEN],
    cl: 0,
};

impl Top5 {
    fn new() -> Self {
        Self {
            e: [EMPTY_TE; TOP_N],
            n: 0,
        }
    }
    fn insert(&mut self, val: u64, comm: &[u8]) {
        let mut c = [0u8; COMM_LEN];
        let l = comm.len().min(COMM_LEN);
        c[..l].copy_from_slice(&comm[..l]);
        let e = TopEntry {
            val,
            comm: c,
            cl: l as u8,
        };
        if self.n < TOP_N {
            self.e[self.n] = e;
            self.n += 1;
        } else {
            let mi = self.min_idx();
            if val > self.e[mi].val {
                self.e[mi] = e;
            }
        }
    }
    fn min_idx(&self) -> usize {
        let (mut mi, mut mv) = (0, self.e[0].val);
        let mut i = 1;
        while i < self.n {
            if self.e[i].val < mv {
                mi = i;
                mv = self.e[i].val;
            }
            i += 1;
        }
        mi
    }
    fn sorted(&mut self) -> &[TopEntry] {
        self.e[..self.n].sort_unstable_by(|a, b| b.val.cmp(&a.val));
        &self.e[..self.n]
    }
}

impl IoTop5 {
    fn new() -> Self {
        Self {
            e: [EMPTY_IE; TOP_N],
            n: 0,
        }
    }
    fn insert(&mut self, total: u64, dr: u64, dw: u64, comm: &[u8]) {
        let mut c = [0u8; COMM_LEN];
        let l = comm.len().min(COMM_LEN);
        c[..l].copy_from_slice(&comm[..l]);
        let e = IoEntry {
            total,
            dr,
            dw,
            comm: c,
            cl: l as u8,
        };
        if self.n < TOP_N {
            self.e[self.n] = e;
            self.n += 1;
        } else {
            let mi = self.min_idx();
            if total > self.e[mi].total {
                self.e[mi] = e;
            }
        }
    }
    fn min_idx(&self) -> usize {
        let (mut mi, mut mv) = (0, self.e[0].total);
        let mut i = 1;
        while i < self.n {
            if self.e[i].total < mv {
                mi = i;
                mv = self.e[i].total;
            }
            i += 1;
        }
        mi
    }
    fn sorted(&mut self) -> &[IoEntry] {
        self.e[..self.n].sort_unstable_by(|a, b| b.total.cmp(&a.total));
        &self.e[..self.n]
    }
}

const MAX_BLOCKED: usize = 10;
#[derive(Clone, Copy)]
struct StateEntry {
    state: u8,
    comm: [u8; COMM_LEN],
    cl: u8,
}
const EMPTY_SE: StateEntry = StateEntry {
    state: 0,
    comm: [0; COMM_LEN],
    cl: 0,
};

struct StateList {
    e: [StateEntry; MAX_BLOCKED],
    n: usize,
}
impl StateList {
    fn new() -> Self {
        Self {
            e: [EMPTY_SE; MAX_BLOCKED],
            n: 0,
        }
    }
    fn push(&mut self, state: u8, comm: &[u8]) {
        if self.n >= MAX_BLOCKED {
            return;
        }
        let mut c = [0u8; COMM_LEN];
        let l = comm.len().min(COMM_LEN);
        c[..l].copy_from_slice(&comm[..l]);
        self.e[self.n] = StateEntry {
            state,
            comm: c,
            cl: l as u8,
        };
        self.n += 1;
    }
    fn sorted(&mut self) -> &[StateEntry] {
        self.e[..self.n].sort_unstable_by_key(|e| e.state);
        &self.e[..self.n]
    }
}

#[inline]
fn comm_str(c: &[u8; COMM_LEN], l: u8) -> &str {
    unsafe { std::str::from_utf8_unchecked(&c[..l as usize]) }
}

// --- sysfs file handles (pread, no seek syscall) ---

struct ThrottleFile {
    file: fs::File,
    name: [u8; 32],
    nl: u8,
}

struct SysFds {
    temp: fs::File,
    freq: fs::File,
    fmax: fs::File,
    rc6: fs::File,
    gpu_freq: fs::File,
    gpu_max: fs::File,
    profile: fs::File,
    throttle: Vec<ThrottleFile>,
}

impl SysFds {
    fn open() -> Self {
        let mut throttle = Vec::new();
        if let Ok(rd) = fs::read_dir(GPU_DIR) {
            for e in rd.flatten() {
                let fname = e.file_name();
                let n = fname.as_encoded_bytes();
                if !n.starts_with(b"throttle_reason_") {
                    continue;
                }
                let sfx = &n[16..];
                if sfx == b"status" || sfx.starts_with(b"pl") {
                    continue;
                }
                let path = format!("{GPU_DIR}/{}", unsafe { std::str::from_utf8_unchecked(n) });
                if let Ok(f) = fs::File::open(&path) {
                    let mut name = [0u8; 32];
                    let l = sfx.len().min(32);
                    name[..l].copy_from_slice(&sfx[..l]);
                    throttle.push(ThrottleFile {
                        file: f,
                        name,
                        nl: l as u8,
                    });
                }
            }
        }
        Self {
            temp: fs::File::open("/sys/class/thermal/thermal_zone0/temp").expect("thermal"),
            freq: fs::File::open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")
                .expect("freq"),
            fmax: fs::File::open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq")
                .expect("fmax"),
            rc6: fs::File::open(&format!("{GPU_DIR}/rc6_residency_ms")).expect("rc6"),
            gpu_freq: fs::File::open(&format!("{GPU_DIR}/rps_act_freq_mhz")).expect("gpu_freq"),
            gpu_max: fs::File::open(&format!("{GPU_DIR}/rps_max_freq_mhz")).expect("gpu_max"),
            profile: fs::File::open("/sys/firmware/acpi/platform_profile").expect("profile"),
            throttle,
        }
    }
}

#[inline]
fn pread_raw(f: &fs::File, buf: &mut [u8]) -> usize {
    let n = unsafe {
        libc::pread(
            f.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
        )
    };
    if n < 0 { 0 } else { n as usize }
}

#[inline]
fn pread_u64(f: &fs::File, buf: &mut [u8]) -> u64 {
    let n = pread_raw(f, buf);
    parse_u64_trim(&buf[..n])
}

fn parse_u64_trim(b: &[u8]) -> u64 {
    let mut v = 0u64;
    let mut started = false;
    for &c in b {
        if c == b'\n' {
            break;
        }
        if c >= b'0' && c <= b'9' {
            v = v * 10 + (c - b'0') as u64;
            started = true;
        } else if started {
            break;
        }
    }
    v
}

fn read_raw(path: &str, buf: &mut [u8]) -> Option<usize> {
    let mut f = fs::File::open(path).ok()?;
    std::io::Read::read(&mut f, buf).ok()
}

fn get_sysinfo() -> libc::sysinfo {
    let mut si: libc::sysinfo = unsafe { std::mem::zeroed() };
    unsafe { libc::sysinfo(&mut si) };
    si
}

// --- Sorted PID stats (zero-alloc steady state) ---

struct PidStats {
    entries: Vec<(u32, BpfPidStats)>,
}

impl PidStats {
    fn with_capacity(n: usize) -> Self {
        Self {
            entries: Vec::with_capacity(n),
        }
    }
    fn clear(&mut self) {
        self.entries.clear();
    }
    fn push(&mut self, pid: u32, st: BpfPidStats) {
        self.entries.push((pid, st));
    }
    fn sort(&mut self) {
        self.entries.sort_unstable_by_key(|e| e.0);
    }
    fn get(&self, pid: u32) -> Option<&BpfPidStats> {
        self.entries
            .binary_search_by_key(&pid, |e| e.0)
            .ok()
            .map(|i| &self.entries[i].1)
    }
}

// --- eBPF loader ---

const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_GET_NEXT_KEY: u32 = 4;
const BPF_PROG_LOAD: u32 = 5;
const BPF_MAP_LOOKUP_BATCH: u32 = 24;

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

#[derive(Clone, Copy)]
struct BpfMapDef {
    name: &'static str,
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    fd: RawFd,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfPidStats {
    cpu_ns: u64,
    rss_pages: u64,
    io_rb: u64,
    io_wb: u64,
    comm: [u8; 16],
    state: u8,
    seen: u8, // client sets on first observation; probe clears on exit/free
}

#[repr(C)]
struct BpfAttrBatch {
    in_batch: u64,
    out_batch: u64,
    keys: u64,
    values: u64,
    count: u32,
    map_fd: u32,
    elem_flags: u64,
    flags: u64,
}

struct BpfLoader {
    maps: [BpfMapDef; 4],
    prog_fds: Vec<RawFd>,
    perf_fds: Vec<RawFd>,
    stats_fd: RawFd,
    latency_fd: RawFd,
    use_batch: bool,
    bk: Vec<u32>,
    bv: Vec<BpfPidStats>,
}

unsafe fn bpf_sys(cmd: u32, attr: *const u8, size: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_bpf, cmd as i64, attr as i64, size as i64) }
}

fn bpf_map_create(mt: u32, ks: u32, vs: u32, me: u32) -> Option<RawFd> {
    let a = BpfAttrMapCreate {
        map_type: mt,
        key_size: ks,
        value_size: vs,
        max_entries: me,
    };
    let fd = unsafe {
        bpf_sys(
            BPF_MAP_CREATE,
            &a as *const _ as *const u8,
            std::mem::size_of::<BpfAttrMapCreate>() as u32,
        )
    };
    if fd < 0 { None } else { Some(fd as RawFd) }
}

fn bpf_map_lookup(fd: RawFd, key: &[u8], val: &mut [u8]) -> bool {
    #[repr(C)]
    struct A {
        fd: u32,
        _p: u32,
        key: u64,
        val: u64,
    }
    let a = A {
        fd: fd as u32,
        _p: 0,
        key: key.as_ptr() as u64,
        val: val.as_mut_ptr() as u64,
    };
    unsafe {
        bpf_sys(
            BPF_MAP_LOOKUP_ELEM,
            &a as *const _ as *const u8,
            std::mem::size_of::<A>() as u32,
        ) == 0
    }
}

fn bpf_map_update(fd: RawFd, key: &[u8], val: &[u8], flags: u64) -> bool {
    #[repr(C)]
    struct A {
        fd: u32,
        _p: u32,
        key: u64,
        val: u64,
        flags: u64,
    }
    let a = A {
        fd: fd as u32,
        _p: 0,
        key: key.as_ptr() as u64,
        val: val.as_ptr() as u64,
        flags,
    };
    unsafe {
        bpf_sys(
            BPF_MAP_UPDATE_ELEM,
            &a as *const _ as *const u8,
            std::mem::size_of::<A>() as u32,
        ) == 0
    }
}

fn bpf_map_get_next_key(fd: RawFd, key: Option<&[u8]>, next: &mut [u8]) -> bool {
    #[repr(C)]
    struct A {
        fd: u32,
        _p: u32,
        key: u64,
        next: u64,
    }
    let kp = key.map(|k| k.as_ptr() as u64).unwrap_or(0);
    let a = A {
        fd: fd as u32,
        _p: 0,
        key: kp,
        next: next.as_mut_ptr() as u64,
    };
    unsafe {
        bpf_sys(
            BPF_MAP_GET_NEXT_KEY,
            &a as *const _ as *const u8,
            std::mem::size_of::<A>() as u32,
        ) == 0
    }
}

fn bpf_prog_load(pt: u32, insns: &[u8], lic: &[u8], log: &mut [u8]) -> Option<RawFd> {
    #[repr(C)]
    struct A {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        _pad: [u64; 16],
    }
    let a = A {
        prog_type: pt,
        insn_cnt: (insns.len() / BPF_INSN_SIZE) as u32,
        insns: insns.as_ptr() as u64,
        license: lic.as_ptr() as u64,
        log_level: if log.is_empty() { 0 } else { 1 },
        log_size: log.len() as u32,
        log_buf: log.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        _pad: [0; 16],
    };
    let fd = unsafe {
        bpf_sys(
            BPF_PROG_LOAD,
            &a as *const _ as *const u8,
            std::mem::size_of::<A>() as u32,
        )
    };
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
    struct PEA {
        type_: u32,
        size: u32,
        config: u64,
        sample_period: u64,
        sample_type: u64,
        read_format: u64,
        flags: u64,
        wakeup_events: u32,
        bp_type: u32,
        config1: u64,
    }
    let mut a: PEA = unsafe { std::mem::zeroed() };
    a.type_ = PERF_TYPE_TRACEPOINT;
    a.size = std::mem::size_of::<PEA>() as u32;
    a.config = tp_id;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &a as *const _,
            -1i32,
            cpu,
            -1i32,
            0u64,
        )
    };
    if fd < 0 { None } else { Some(fd as RawFd) }
}

impl BpfLoader {
    fn load(obj_path: &str) -> Option<Self> {
        let data = fs::read(obj_path).ok()?;
        let elf = goblin::elf::Elf::parse(&data).ok()?;

        let mut maps = [
            BpfMapDef {
                name: "stats",
                map_type: BPF_MAP_TYPE_HASH,
                key_size: 4,
                value_size: std::mem::size_of::<BpfPidStats>() as u32,
                max_entries: MAX_PIDS as u32,
                fd: -1,
            },
            BpfMapDef {
                name: "sys",
                map_type: BPF_MAP_TYPE_ARRAY,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                fd: -1,
            },
            BpfMapDef {
                name: "sched_start",
                map_type: BPF_MAP_TYPE_HASH,
                key_size: 4,
                value_size: 8,
                max_entries: MAX_PIDS as u32,
                fd: -1,
            },
            BpfMapDef {
                name: "latency",
                map_type: BPF_MAP_TYPE_ARRAY,
                key_size: 4,
                value_size: 8,
                max_entries: 32,
                fd: -1,
            },
        ];
        for m in &mut maps {
            m.fd = bpf_map_create(m.map_type, m.key_size, m.value_size, m.max_entries)?;
        }

        let maps_shndx = elf.section_headers.iter().position(|s| {
            elf.shdr_strtab
                .get_at(s.sh_name)
                .map(|n| n == ".maps")
                .unwrap_or(false)
        });

        let mut sym_to_fd = std::collections::HashMap::new();
        if let Some(mi) = maps_shndx {
            for (si, sym) in elf.syms.iter().enumerate() {
                if sym.st_shndx == mi {
                    let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
                    for m in &maps {
                        if m.name == name {
                            sym_to_fd.insert(si, m.fd);
                        }
                    }
                }
            }
        }

        let stats_fd = maps[0].fd;
        let license = b"GPL\0";
        let mut prog_fds = Vec::new();
        let mut perf_fds = Vec::new();

        let prog_sections: Vec<(usize, String)> = elf
            .section_headers
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                let name = elf.shdr_strtab.get_at(s.sh_name)?;
                if name.starts_with("tracepoint/")
                    && s.sh_type == goblin::elf::section_header::SHT_PROGBITS
                    && s.sh_size > 0
                {
                    Some((i, name.to_string()))
                } else {
                    None
                }
            })
            .collect();

        for (shndx, sec_name) in &prog_sections {
            let sh = &elf.section_headers[*shndx];
            let mut insns =
                data[sh.sh_offset as usize..(sh.sh_offset + sh.sh_size) as usize].to_vec();

            for rel_sh in &elf.section_headers {
                if rel_sh.sh_type != goblin::elf::section_header::SHT_REL {
                    continue;
                }
                if rel_sh.sh_info as usize != *shndx {
                    continue;
                }
                let rd =
                    &data[rel_sh.sh_offset as usize..(rel_sh.sh_offset + rel_sh.sh_size) as usize];
                let rc = rel_sh.sh_size as usize / 16;
                for i in 0..rc {
                    let off = i * 16;
                    let r_offset = u64::from_le_bytes(rd[off..off + 8].try_into().unwrap());
                    let r_info = u64::from_le_bytes(rd[off + 8..off + 16].try_into().unwrap());
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
            let fd = match bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, &insns, license, &mut log) {
                Some(f) => f,
                None => {
                    let ls = std::str::from_utf8(&log)
                        .unwrap_or("")
                        .trim_end_matches('\0');
                    if !ls.is_empty() {
                        eprintln!("bpf: prog load failed for {sec_name}:\n{ls}");
                    } else {
                        eprintln!(
                            "bpf: prog load failed for {sec_name}: {}",
                            io::Error::last_os_error()
                        );
                    }
                    for m in &maps {
                        unsafe {
                            libc::close(m.fd);
                        }
                    }
                    for f in &prog_fds {
                        unsafe {
                            libc::close(*f);
                        }
                    }
                    for f in &perf_fds {
                        unsafe {
                            libc::close(*f);
                        }
                    }
                    return None;
                }
            };
            prog_fds.push(fd);

            let parts = sec_name.splitn(3, '/').collect::<Vec<&str>>();
            if parts.len() != 3 {
                continue;
            }
            let (cat, tp) = (parts[1], parts[2]);
            let tp_id = match tracepoint_id(cat, tp) {
                Some(id) => id,
                None => {
                    eprintln!("bpf: tracepoint {cat}/{tp} not found");
                    continue;
                }
            };

            let ncpu = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as i32;
            for cpu in 0..ncpu {
                let Some(pfd) = perf_event_open_tracepoint(tp_id, cpu) else {
                    continue;
                };
                if cpu == 0 {
                    let r =
                        unsafe { libc::ioctl(pfd, PERF_EVENT_IOC_SET_BPF as libc::c_ulong, fd) };
                    if r < 0 {
                        eprintln!(
                            "bpf: attach failed for {sec_name}: {}",
                            io::Error::last_os_error()
                        );
                        unsafe {
                            libc::close(pfd);
                        }
                        continue;
                    }
                }
                unsafe { libc::ioctl(pfd, PERF_EVENT_IOC_ENABLE as libc::c_ulong, 0) };
                perf_fds.push(pfd);
            }
        }

        if prog_fds.is_empty() {
            for m in &maps {
                unsafe {
                    libc::close(m.fd);
                }
            }
            return None;
        }

        let latency_fd = maps[3].fd;
        Some(BpfLoader {
            maps,
            prog_fds,
            perf_fds,
            stats_fd,
            latency_fd,
            use_batch: true,
            bk: vec![0u32; MAX_PIDS],
            bv: vec![BpfPidStats::default(); MAX_PIDS],
        })
    }

    fn read_stats(&mut self, out: &mut PidStats) {
        out.clear();
        if self.use_batch {
            if self.read_batch(out) {
                out.sort();
                return;
            }
            self.use_batch = false;
            eprintln!("rstat: batch lookup unsupported, using iterative");
        }
        self.read_iter(out);
        out.sort();
    }

    fn read_batch(&mut self, out: &mut PidStats) -> bool {
        let mut token: u64 = 0;
        let mut total = 0usize;
        let mut first = true;
        loop {
            let rem = MAX_PIDS - total;
            if rem == 0 {
                break;
            }
            let mut attr = BpfAttrBatch {
                in_batch: if first { 0 } else { &token as *const _ as u64 },
                out_batch: &mut token as *mut _ as u64,
                keys: unsafe { self.bk.as_mut_ptr().add(total) } as u64,
                values: unsafe { self.bv.as_mut_ptr().add(total) } as u64,
                count: rem as u32,
                map_fd: self.stats_fd as u32,
                elem_flags: 0,
                flags: 0,
            };
            let r = unsafe {
                bpf_sys(
                    BPF_MAP_LOOKUP_BATCH,
                    &mut attr as *mut _ as *const u8,
                    std::mem::size_of::<BpfAttrBatch>() as u32,
                )
            };
            total += attr.count as usize;
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ENOENT) {
                    break;
                }
                if total == 0 {
                    return false;
                }
                break;
            }
            first = false;
        }
        for i in 0..total {
            out.push(self.bk[i], self.bv[i]);
        }
        true
    }

    // Mark unseen zombies as seen. Only zombies still present with seen=1
    // on the next poll are displayed (they survived a full interval).
    fn ack_zombies(&self, stats: &PidStats) {
        for &(pid, ref st) in &stats.entries {
            if st.state == b'Z' && st.seen == 0 {
                let mut ack = *st;
                ack.seen = 1;
                let kb = pid.to_ne_bytes();
                let vb = unsafe {
                    std::slice::from_raw_parts(
                        &ack as *const _ as *const u8,
                        std::mem::size_of::<BpfPidStats>(),
                    )
                };
                bpf_map_update(self.stats_fd, &kb, vb, 2); // BPF_EXIST
            }
        }
    }

    fn read_iter(&self, out: &mut PidStats) {
        let mut key = [0u8; 4];
        let mut pk: Option<[u8; 4]> = None;
        let mut val = BpfPidStats::default();
        while bpf_map_get_next_key(self.stats_fd, pk.as_ref().map(|k| k.as_slice()), &mut key) {
            if bpf_map_lookup(self.stats_fd, &key, unsafe {
                std::slice::from_raw_parts_mut(
                    &mut val as *mut _ as *mut u8,
                    std::mem::size_of::<BpfPidStats>(),
                )
            }) {
                out.push(u32::from_ne_bytes(key), val);
            }
            pk = Some(key);
        }
    }
}

impl Drop for BpfLoader {
    fn drop(&mut self) {
        for f in &self.perf_fds {
            unsafe {
                libc::close(*f);
            }
        }
        for f in &self.prog_fds {
            unsafe {
                libc::close(*f);
            }
        }
        for m in &self.maps {
            unsafe {
                libc::close(m.fd);
            }
        }
    }
}

// --- Sampling ---

struct Sample {
    cpu_pct: f64,
    mem_total: u64,
    mem_free_approx: u64,
    load: [f64; 3],
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
    top_kthread: Top5,
    blocked: StateList,
    show_kthreads: bool,
    ts: Instant,
}

fn sample_throttle(files: &mut [ThrottleFile], buf: &mut [u8]) -> ([u8; 64], usize) {
    let mut out = [0u8; 64];
    let mut pos = 0;
    for tf in files.iter_mut() {
        let n = pread_raw(&tf.file, buf);
        if n > 0 && buf[0] == b'1' {
            if pos > 0 && pos + 2 < 64 {
                out[pos] = b',';
                out[pos + 1] = b' ';
                pos += 2;
            }
            let l = (tf.nl as usize).min(64 - pos);
            out[pos..pos + l].copy_from_slice(&tf.name[..l]);
            pos += l;
        }
    }
    (out, pos)
}

fn take_sample(
    me: u32,
    parent: u32,
    buf: &mut [u8],
    fds: &mut SysFds,
    cores: u32,
    elapsed_s: f64,
    cur: &PidStats,
    prev: &PidStats,
) -> Sample {
    let si = get_sysinfo();
    let mu = si.mem_unit.max(1) as u64;
    let mem_total = si.totalram * mu;
    let mem_free_approx = (si.freeram + si.bufferram) * mu;
    let load = [
        si.loads[0] as f64 / 65536.0,
        si.loads[1] as f64 / 65536.0,
        si.loads[2] as f64 / 65536.0,
    ];

    let rc6 = pread_u64(&fds.rc6, buf);
    let gf = pread_u64(&fds.gpu_freq, buf);
    let gm = pread_u64(&fds.gpu_max, buf);
    let ct = pread_u64(&fds.temp, buf);
    let cf = pread_u64(&fds.freq, buf);
    let cfm = pread_u64(&fds.fmax, buf);
    let thr = sample_throttle(&mut fds.throttle, buf);
    let pn = pread_raw(&fds.profile, buf);
    let mut profile = [0u8; 32];
    let mut pl = pn;
    while pl > 0 && (buf[pl - 1] == b'\n' || buf[pl - 1] == b' ') {
        pl -= 1;
    }
    let pl = pl.min(32);
    profile[..pl].copy_from_slice(&buf[..pl]);

    let total_ns = (elapsed_s * 1_000_000_000.0 * cores as f64) as u64;
    let show_kt = SHOW_KTHREADS.load(Ordering::Relaxed);
    let mut top_cpu = Top5::new();
    let mut top_mem = Top5::new();
    let mut top_io = IoTop5::new();
    let mut top_kthread = Top5::new();
    let mut blocked = StateList::new();
    let min_io = if elapsed_s > 0.0 {
        (MIN_IO_BYTES as f64 * elapsed_s) as u64
    } else {
        u64::MAX
    };
    let mut busy_ns = 0u64;

    for &(pid, ref st) in &cur.entries {
        if pid == me || pid == parent || pid == 0 {
            continue;
        }
        let cl = st.comm.iter().position(|&b| b == 0).unwrap_or(16);
        if cl == 0 {
            continue;
        }
        if st.state == b'D' || (st.state == b'Z' && st.seen != 0) {
            blocked.push(st.state, &st.comm[..cl]);
        }

        let prev_st = prev.get(pid);
        let prev_cpu = prev_st.map(|p| p.cpu_ns).unwrap_or(0);
        let dcpu = st.cpu_ns.saturating_sub(prev_cpu);
        busy_ns += dcpu;

        // Kernel threads have no mm, so rss_pages == 0
        let is_kthread = st.rss_pages == 0;

        if is_kthread {
            if show_kt && total_ns > 0 && dcpu > 0 {
                top_kthread.insert(dcpu, &st.comm[..cl]);
            }
            continue;
        }

        if total_ns > 0 && dcpu > 0 {
            let thr_ns = (MIN_CPU_PCT * total_ns as f64 / 100.0) as u64;
            if dcpu >= thr_ns {
                top_cpu.insert(dcpu, &st.comm[..cl]);
            }
        }

        let rss = st.rss_pages * PAGE_SIZE;
        if rss >= MIN_MEM_BYTES {
            top_mem.insert(rss, &st.comm[..cl]);
        }

        let (prb, pwb) = prev_st.map(|p| (p.io_rb, p.io_wb)).unwrap_or((0, 0));
        let drb = st.io_rb.saturating_sub(prb);
        let dwb = st.io_wb.saturating_sub(pwb);
        let dt = drb + dwb;
        if dt >= min_io {
            top_io.insert(dt, drb, dwb, &st.comm[..cl]);
        }
    }

    let cpu_pct = if total_ns > 0 && elapsed_s > 0.0 {
        (busy_ns as f64 / total_ns as f64 * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    };

    Sample {
        cpu_pct,
        mem_total,
        mem_free_approx,
        load,
        cores,
        gpu_rc6_ms: rc6,
        gpu_freq: gf,
        gpu_max: gm,
        cpu_temp: ct,
        cpu_freq: cf,
        cpu_fmax: cfm,
        throttle: thr,
        profile,
        profile_len: pl as u8,
        top_cpu,
        top_mem,
        top_io,
        top_kthread,
        blocked,
        show_kthreads: show_kt,
        ts: Instant::now(),
    }
}

// --- JSON output (hand-written, no serde) ---

fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for b in s.bytes() {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            c if c < 0x20 => {}
            c => unsafe { out.as_mut_vec().push(c) },
        }
    }
    out.push('"');
}

fn emit(
    prev: Option<&Sample>,
    cur: &mut Sample,
    dur: Duration,
    tt: &mut String,
    json: &mut String,
    text_buf: &mut String,
) {
    let elapsed_s = prev
        .map(|p| cur.ts.duration_since(p.ts).as_secs_f64())
        .unwrap_or(0.0);

    let mt = cur.mem_total;
    let mfree = cur.mem_free_approx;
    let mused = mt.saturating_sub(mfree);
    let mpct = if mt > 0 { 100 * mused / mt } else { 0 };
    let mused_g = mused as f64 / 1_073_741_824.0;
    let mtotal_g = mt as f64 / 1_073_741_824.0;

    let ratio = cur.load[0] / cur.cores.max(1) as f64;
    let class = if ratio >= 2.0 {
        "critical"
    } else if ratio >= 1.0 {
        "warning"
    } else {
        "normal"
    };

    let ct = cur.cpu_temp / 1000;
    let cf = cur.cpu_freq as f64 / 1_000_000.0;
    let cfm = cur.cpu_fmax as f64 / 1_000_000.0;
    let prof = unsafe { std::str::from_utf8_unchecked(&cur.profile[..cur.profile_len as usize]) };

    // Build tooltip
    tt.clear();
    let _ = write!(
        tt,
        "Load: {:.2} {:.2} {:.2} ({} cores)",
        cur.load[0], cur.load[1], cur.load[2], cur.cores
    );

    match prev {
        Some(p) => {
            let dt_ms = (elapsed_s * 1000.0) as u64;
            if dt_ms > 0 {
                let d = cur.gpu_rc6_ms.saturating_sub(p.gpu_rc6_ms);
                let busy = (100.0 - d as f64 * 100.0 / dt_ms as f64).max(0.0);
                let _ = write!(
                    tt,
                    "\niGPU: {busy:.0}% @ {}/{} MHz",
                    cur.gpu_freq, cur.gpu_max
                );
            } else {
                let _ = write!(tt, "\niGPU: {}/{} MHz", cur.gpu_freq, cur.gpu_max);
            }
        }
        None => {
            let _ = write!(tt, "\niGPU: {}/{} MHz", cur.gpu_freq, cur.gpu_max);
        }
    }

    let _ = write!(tt, "\nProfile: {prof}");
    if cur.throttle.1 > 0 {
        let ts = unsafe { std::str::from_utf8_unchecked(&cur.throttle.0[..cur.throttle.1]) };
        let _ = write!(tt, "\n⚠ Throttled: {ts}");
    }

    tt.push_str("\n\n CPU    ");
    let _ = write!(tt, "{ct}°C    ");
    if prev.is_some() {
        let _ = write!(tt, "{:.0}", cur.cpu_pct);
    } else {
        tt.push('?');
    }
    let _ = write!(tt, "%    {cf:.1}/{cfm:.1} GHz");
    let blk = cur.blocked.sorted();
    for e in blk {
        let _ = write!(tt, "\n    {}  {}", e.state as char, comm_str(&e.comm, e.cl));
    }
    let entries = cur.top_cpu.sorted();
    if entries.is_empty() && blk.is_empty() {
        tt.push_str("\n  ---");
    }
    let total_ns = elapsed_s * cur.cores as f64 * 1_000_000_000.0;
    for e in entries {
        let pct = if total_ns > 0.0 {
            e.val as f64 * 100.0 / total_ns
        } else {
            0.0
        };
        let _ = write!(tt, "\n{pct:5.1}%  {}", comm_str(&e.comm, e.cl));
    }

    let _ = write!(
        tt,
        "\n\n Memory    {mused_g:.1}/{mtotal_g:.1} GiB ({mpct}%)"
    );
    let entries = cur.top_mem.sorted();
    if entries.is_empty() {
        tt.push_str("\n  ---");
    } else {
        for e in entries {
            let mb = e.val as f64 / 1_048_576.0;
            let _ = write!(tt, "\n{mb:5.0}M  {}", comm_str(&e.comm, e.cl));
        }
    }

    tt.push_str("\n\n IO/s");
    let entries = cur.top_io.sorted();
    if entries.is_empty() {
        tt.push_str("\n  ---");
    } else {
        for e in entries {
            let t = e.total as f64 / 1_048_576.0 / elapsed_s;
            let r = e.dr as f64 / 1_048_576.0 / elapsed_s;
            let w = e.dw as f64 / 1_048_576.0 / elapsed_s;
            let _ = write!(
                tt,
                "\n{t:5.1}M/s  {} (R:{r:.1} W:{w:.1})",
                comm_str(&e.comm, e.cl)
            );
        }
    }
    if cur.show_kthreads {
        tt.push_str("\n\n Kernel");
        let entries = cur.top_kthread.sorted();
        if entries.is_empty() {
            tt.push_str("\n  ---");
        } else {
            let total_ns = elapsed_s * cur.cores as f64 * 1_000_000_000.0;
            for e in entries {
                let pct = if total_ns > 0.0 {
                    e.val as f64 * 100.0 / total_ns
                } else {
                    0.0
                };
                let _ = write!(tt, "\n{pct:5.1}%  {}", comm_str(&e.comm, e.cl));
            }
        }
    }

    let ival = INTERVAL_MS.load(Ordering::Relaxed);
    let _ = write!(
        tt,
        "\n\nSampled in {:.1}ms (every {ival}ms)",
        dur.as_secs_f64() * 1000.0
    );

    // Build JSON directly
    json.clear();
    json.push_str("{\"text\":");
    text_buf.clear();
    let _ = write!(text_buf, "{:.2}", cur.load[0]);
    json_str(json, text_buf);
    json.push_str(",\"tooltip\":");
    json_str(json, tt);
    json.push_str(",\"class\":");
    json_str(json, class);
    json.push('}');

    let stdout = io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(json.as_bytes());
    let _ = lock.write_all(b"\n");
    let _ = lock.flush();
}

// --- Click-to-cycle interval control ---

extern "C" fn sig_cycle(_: libc::c_int) {
    let cur = INTERVAL_MS.load(Ordering::Relaxed);
    let next = INTERVALS
        .iter()
        .skip_while(|&&v| v != cur)
        .nth(1)
        .copied()
        .unwrap_or(INTERVALS[0]);
    INTERVAL_MS.store(next, Ordering::Relaxed);
}

extern "C" fn sig_kthreads(_: libc::c_int) {
    SHOW_KTHREADS.fetch_xor(true, Ordering::Relaxed);
}

fn sleep_or_signal(ms: u64) {
    let ts = libc::timespec {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_nsec: ((ms % 1000) * 1_000_000) as libc::c_long,
    };
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
}

fn print_histogram(fd: RawFd, secs: f64) {
    let mut bk = [0u64; 32];
    for i in 0..32u32 {
        let kb = i.to_ne_bytes();
        let mut vb = [0u8; 8];
        if bpf_map_lookup(fd, &kb, &mut vb) {
            bk[i as usize] = u64::from_ne_bytes(vb.try_into().unwrap());
        }
    }
    let first = bk.iter().position(|&v| v > 0).unwrap_or(0);
    let last = bk.iter().rposition(|&v| v > 0).unwrap_or(0);
    let mx = *bk.iter().max().unwrap_or(&1).max(&1);
    let total: u64 = bk.iter().sum();
    let mut sum_ns = 0u64;
    for (i, &c) in bk.iter().enumerate() {
        // midpoint of [2^i, 2^(i+1)) ≈ 1.5 * 2^i
        sum_ns += ((3u64 << i) >> 1) * c;
    }
    let avg = if total > 0 { sum_ns / total } else { 0 };
    let per_sec = total as f64 / secs;
    let overhead_pct = avg as f64 * per_sec / 1e9 * 100.0;
    eprintln!(
        "\nrstat BPF probe latency ({total} context switches, {per_sec:.0}/s over {secs:.1}s):\n"
    );
    eprintln!("    {:>13}    {:>8}  distribution", "ns", "count");
    for i in first..=last {
        let lo = 1u64 << i;
        let hi = (1u64 << (i + 1)) - 1;
        let c = bk[i];
        let w = (c * 40 / mx) as usize;
        let bar = "*".repeat(w);
        eprintln!("    {lo:>5}-{hi:<8} {c:>8}  |{bar:<40}|");
    }
    eprintln!(
        "\n  avg: ~{avg}ns  overhead: {overhead_pct:.4}% of one core ({:.3}ms/s)",
        avg as f64 * per_sec / 1e6
    );
}

/// One-time /proc scan to seed the BPF stats map with pre-existing D/Z processes.
/// The eBPF probes only see state transitions *after* they attach -- processes that
/// were already in D or Z state at startup would otherwise be invisible.
fn seed_existing_dz(stats_fd: RawFd) -> usize {
    let mut n = 0usize;
    let Ok(rd) = fs::read_dir("/proc") else {
        return 0;
    };
    let mut buf = [0u8; 512];
    for entry in rd.flatten() {
        let name = entry.file_name();
        let nb = name.as_encoded_bytes();
        if nb.is_empty() || nb[0] < b'0' || nb[0] > b'9' {
            continue;
        }
        let pid: u32 = match parse_u64_trim(nb) as u32 {
            0 => continue,
            v => v,
        };
        let path = format!("/proc/{}/stat", pid);
        let Some(len) = read_raw(&path, &mut buf) else {
            continue;
        };
        let b = &buf[..len];
        // Format: pid (comm) state ...
        // Find closing ')' then state is the next non-space char
        let Some(cp) = b.iter().rposition(|&c| c == b')') else {
            continue;
        };
        let rest = &b[cp + 1..];
        let state = match rest.iter().find(|&&c| c != b' ') {
            Some(&s) if s == b'D' || s == b'Z' => s,
            _ => continue,
        };
        // Extract comm from between '(' and ')'
        let op = match b.iter().position(|&c| c == b'(') {
            Some(i) => i + 1,
            None => continue,
        };
        let comm = &b[op..cp];
        let mut st = BpfPidStats::default();
        st.state = state;
        if state == b'Z' {
            st.seen = 1;
        } // pre-existing zombie: display immediately
        let cl = comm.len().min(16);
        st.comm[..cl].copy_from_slice(&comm[..cl]);
        let kb = pid.to_ne_bytes();
        let vb = unsafe {
            std::slice::from_raw_parts(
                &st as *const _ as *const u8,
                std::mem::size_of::<BpfPidStats>(),
            )
        };
        // BPF_NOEXIST (1): don't overwrite if probe already inserted this PID
        bpf_map_update(stats_fd, &kb, vb, 1);
        n += 1;
    }
    n
}

fn main() {
    let mut buf = [0u8; 64];
    let me = std::process::id();
    let parent = unsafe { libc::getppid() } as u32;
    let cores = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as u32;
    let mut fds = SysFds::open();

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_RESTART;
        sa.sa_sigaction = sig_cycle as usize;
        libc::sigaction(libc::SIGRTMIN(), &sa, std::ptr::null_mut());
        sa.sa_sigaction = sig_kthreads as usize;
        libc::sigaction(libc::SIGRTMIN() + 1, &sa, std::ptr::null_mut());
    }

    let args: Vec<String> = std::env::args().skip(1).collect();

    let probe_path = args
        .iter()
        .find(|a| a.ends_with(".bpf.o"))
        .cloned()
        .unwrap_or_else(|| {
            let exe = std::env::current_exe().unwrap_or_default();
            let dir = exe.parent().unwrap_or(std::path::Path::new("."));
            dir.join("probe.bpf.o").to_string_lossy().into_owned()
        });

    let mut bpf = BpfLoader::load(&probe_path).unwrap_or_else(|| {
        eprintln!("rstat: failed to load eBPF probe from {probe_path}");
        std::process::exit(1);
    });
    eprintln!("rstat: eBPF active ({probe_path})");

    let seeded = seed_existing_dz(bpf.stats_fd);
    if seeded > 0 {
        eprintln!("rstat: seeded {seeded} pre-existing D/Z processes from /proc");
    }

    let profile = args.iter().any(|a| a == "--profile");
    let profile_secs: u64 = if profile {
        args.iter()
            .skip_while(|a| *a != "--profile")
            .nth(1)
            .and_then(|a| a.parse().ok())
            .unwrap_or(5)
    } else {
        0
    };

    if profile {
        eprintln!("rstat: profiling BPF probe for {profile_secs}s...");
        thread::sleep(Duration::from_secs(profile_secs));
        print_histogram(bpf.latency_fd, profile_secs as f64);
        return;
    }

    let bench = args.iter().any(|a| a == "--bench");
    let bench_n: usize = if bench {
        args.iter()
            .skip_while(|a| *a != "--bench")
            .nth(1)
            .and_then(|a| a.parse().ok())
            .unwrap_or(100)
    } else {
        0
    };

    // Pre-allocated, reused every tick (zero-alloc steady state)
    let mut cur = PidStats::with_capacity(MAX_PIDS);
    let mut prev = PidStats::with_capacity(MAX_PIDS);
    let mut tt = String::with_capacity(1024);
    let mut json = String::with_capacity(1536);
    let mut text_buf = String::with_capacity(16);

    if bench {
        bpf.read_stats(&mut prev);
        let prev_ts = Instant::now();
        thread::sleep(Duration::from_millis(10));

        let mut times = Vec::with_capacity(bench_n);
        let mut last_ts = prev_ts;
        for _ in 0..bench_n {
            thread::sleep(Duration::from_millis(1));
            let t0 = Instant::now();
            let es = t0.duration_since(last_ts).as_secs_f64();
            bpf.read_stats(&mut cur);
            let _ = take_sample(me, parent, &mut buf, &mut fds, cores, es, &cur, &prev);
            times.push(t0.elapsed());
            last_ts = t0;
            std::mem::swap(&mut cur, &mut prev);
        }
        times.sort();
        let sum: Duration = times.iter().sum();
        let avg = sum / times.len() as u32;
        let p50 = times[times.len() / 2];
        let p95 = times[times.len() * 95 / 100];
        let p99 = times[times.len() * 99 / 100];
        eprintln!(
            "n={bench_n}  avg={:.2}ms  p50={:.2}ms  p95={:.2}ms  p99={:.2}ms  min={:.2}ms  max={:.2}ms",
            avg.as_secs_f64() * 1000.0,
            p50.as_secs_f64() * 1000.0,
            p95.as_secs_f64() * 1000.0,
            p99.as_secs_f64() * 1000.0,
            times[0].as_secs_f64() * 1000.0,
            times.last().unwrap().as_secs_f64() * 1000.0
        );
        return;
    }

    // First sample (no deltas)
    bpf.read_stats(&mut prev);
    let mut s = take_sample(me, parent, &mut buf, &mut fds, cores, 0.0, &prev, &cur);
    emit(
        None,
        &mut s,
        Duration::ZERO,
        &mut tt,
        &mut json,
        &mut text_buf,
    );
    let mut prev_sample = s;

    loop {
        sleep_or_signal(INTERVAL_MS.load(Ordering::Relaxed));
        let t0 = Instant::now();
        let es = t0.duration_since(prev_sample.ts).as_secs_f64();
        bpf.read_stats(&mut cur);
        bpf.ack_zombies(&cur);
        let mut s = take_sample(me, parent, &mut buf, &mut fds, cores, es, &cur, &prev);
        let dur = t0.elapsed();
        emit(
            Some(&prev_sample),
            &mut s,
            dur,
            &mut tt,
            &mut json,
            &mut text_buf,
        );
        prev_sample = s;
        std::mem::swap(&mut cur, &mut prev);
    }
}
