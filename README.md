# rstat

**A system monitor that runs inside the kernel. Sub-millisecond samples. Zero allocations. Faster than `top`.**

Most system monitors read `/proc` -- opening, reading, and closing thousands of files every refresh cycle. `top` does it. `btop` does it. They parse ASCII text the kernel formatted from data structures it already had in memory. It is a serialisation round-trip through the filesystem for numbers the kernel could hand you directly.

`rstat` skips all of that. It injects verified eBPF bytecode into the kernel's scheduler path. When the CPU switches between tasks, the probe reads CPU time, RSS, and IO counters directly from `task_struct` -- no files, no syscalls, no text parsing. Userspace reads the results from a BPF map in a single batch operation.

The result: a complete system health snapshot (CPU%, memory, load, temperature, frequency, GPU, power profile, top-5 processes by CPU/memory/IO with per-process breakdowns) in **under 1 millisecond** on a quiet desktop, with **zero heap allocations** in the steady-state hot path.

[![Read the full writeup](https://img.shields.io/badge/Read_the_writeup-over--yonder.tech-1a6e2e?style=for-the-badge)](https://over-yonder.tech/#articles/rstat)

## How it works

```
                    Ring 0 (Kernel)
    ┌─────────────────────────────────────────┐
    │  eBPF Sandbox          Kernel Structs   │
    │  ┌─────────────┐      ┌──────────────┐  │
    │  │ Verified     │◄─────│ task_struct   │  │
    │  │ bytecode     │◄─────│ mm_struct     │  │
    │  │              │◄─────│ task->ioac    │  │
    │  └──────┬───────┘      └──────────────┘  │
    │         │ writes to BPF map              │
    ├─────────┼────────────────────────────────┤
    │         ▼           Ring 3 (Userspace)   │
    │  ┌──────────────┐                        │
    │  │ rstat daemon  │──► Waybar (JSON)      │
    │  │ 1 batch read  │                       │
    │  └──────────────┘                        │
    └─────────────────────────────────────────┘
```

**Three BPF tracepoint probes:**
- `sched_switch` -- accounts CPU time, snapshots RSS and IO for the outgoing task
- `sched_process_exit` -- marks zombies (Z-state)
- `sched_process_free` -- cleans up reaped processes

**Userspace daemon (~795 lines of Rust):**
- Custom ELF loader (no aya, no libbpf-rs, no tokio, no C build step)
- Batch map reads with pre-allocated arrays
- Hand-written JSON emitter (no serde)
- All buffers pre-allocated and reused; zero `malloc` in the hot path

## Performance

| Stage | Time | Approach |
|-------|------|----------|
| Bash + coreutils | ~2,000 ms | Fork 10-15 subprocesses per sample |
| Rust + /proc | ~700 ms | Direct /proc parsing, one subprocess remained |
| Optimised /proc | ~15 ms | Sysfs, reusable buffers, byte-level parsing |
| **eBPF + zero-alloc** | **<1 ms** | BPF probes, batch map reads, hand-written JSON |

~200 KB RSS. <0.01% CPU. Two runtime dependencies (`libc`, `goblin`).

## Building

Rust, by the way. On NixOS, by the way.

Requires Nix with flakes:

```sh
nix build
```

Two-derivation build:
1. `rstat-probe` -- compiles `probe.bpf.c` with `clang -target bpf -O2 -g`
2. `rstat` -- builds the Rust binary, copies the probe alongside it

The binary requires `CAP_SYS_ADMIN` (or equivalent, e.g. NixOS `security.wrappers`) for `bpf()` and `perf_event_open()`.

## Waybar integration

```json
"custom/sysmon": {
    "exec": "rstat",
    "return-type": "json",
    "restart-interval": 0
}
```

## Writeup

The full story of how this went from a 2-second shell script to sub-millisecond eBPF:

[![Read the writeup on over-yonder.tech](https://img.shields.io/badge/Read_the_writeup-over--yonder.tech-1a6e2e?style=for-the-badge)](https://over-yonder.tech/#articles/rstat)
