# rstat

`rstat` is a Linux system monitor for Waybar. A small daemon samples the kernel's
own counters through file descriptors it keeps open, and serves five Waybar
modules (CPU, memory, disks, network and NVIDIA GPU), each with a headline and a
detailed tooltip. A section is sampled only while a Waybar module is watching
it, and a module redraws only when its output changes.

Headlines report saturation rather than utilization: how much work is waiting,
not how busy something is.

| Section | Headline | Tooltip |
| --- | --- | --- |
| `cpu` | 1-minute load · CPU pressure | load, pressure, interrupt pressure, utilization, context switches, frequency scaling, fans, CPU temperature, Intel thermal and ACPI throttling |
| `memory` | memory pressure (all tasks stalled) · available RAM | pressure, swap and paging, refaults, reclaim, compaction, OOM kills, RAM composition, zram, per-process proportional memory |
| `disks` | average requests queued on local disks | per-disk busy time, queue, latency and throughput, dirty pages, root filesystem, I/O pressure, tasks blocked in D state |
| `network` | average NAS (SMB) requests outstanding | NAS request rate and latency, TCP retransmissions and timeouts, listen and buffer errors, interfaces, link use |
| `gpu` | GPU utilization · VRAM | utilization, encoder and decoder, VRAM, time under each clock-limit policy, clocks, power, temperature headroom, PCIe, VRAM by process |

Each figure that can show strain is coloured green, amber or red against its
own threshold, and the module's CSS class (`ok`, `warning` or `critical`)
follows the worst of them.

### Why load and NAS wait are separated

Linux load average counts tasks in uninterruptible sleep, which includes tasks
waiting on a network filesystem. A machine with an idle local disk can show a
load of 30 while it waits on a NAS. Pressure stall information can't separate
the two either. `rstat` takes the local disk queue from `/sys/block/*/stat`
(time requests spent queued, per second of wall time) and the NAS queue from the
SMB client's `/proc/fs/cifs/Stats` (time spent on completed requests, per
second), so the disk and network headlines say which one is waiting.

## Design

- **Persistent descriptors.** Every procfs and sysfs file is opened once and
  re-read with `pread` at offset zero, which makes the kernel regenerate it.
  There is no per-sample `open`, `close` or process spawn.
- **NVML.** GPU figures come from the NVIDIA Management Library, which
  `nvidia-smi` itself uses, loaded once while the GPU section is watched.
- **Subscriptions.** The daemon listens on `$XDG_RUNTIME_DIR/rstat.sock`. A
  watcher sends a section name and receives a JSON line whenever that section's
  output changes. A section's sampler, with its descriptors and the driver
  library, is opened with the first watcher and closed with the last.
- **Expensive work only when needed.** Scanning every thread for D-state tasks
  costs about 100 ms, so it runs only while `/proc/stat` reports blocked tasks.
  Per-process proportional memory needs root and a few hundred milliseconds, so
  a system service writes it about once a minute with
  `rstat sample-process-memory`, and the memory section reads that report.

### Cost

Measured on a Ryzen 7 5800X3D (16 threads), Linux 6.18 and an RTX 5070 Ti, with the
daemon sampling once a second:

| Section | Daemon CPU time |
| --- | ---: |
| `cpu`, `memory`, `disks`, `network` | under 1 ms per sample each |
| `gpu` | about 8 ms per sample |
| all five | under 1% of one core |

Almost all of the cost is the NVIDIA driver. Its maximum clocks and fan count
are read once; its clock-limit violation counters, which cost about 6 ms to
read, are cumulative and read every 10 s; and PCIe throughput, which NVML
measures over a window of about 20 ms on each call, is re-measured every 10 s.
The shell and Python samplers `rstat` replaced cost about 430 ms of CPU for one
round of the same five sections.

## Version 1: the eBPF experiment

Version 1 (tag [`v1`](../../tree/v1)) asked whether a rich monitor could make
frequent refreshes cheaper by accounting for work when it happens. An eBPF
probe on the scheduler's `sched_switch` tracepoint kept per-task CPU, memory
and I/O counters, and userspace read them in a single batch lookup. Its
refresh path averaged 0.13–0.16 ms, about two orders of magnitude below a
procfs process walk.

The cost moved rather than disappeared. A poller pays per refresh; the probe
paid on every context switch:

```text
poller:  CPU per second ≈ refresh cost × refreshes per second
probe:   CPU per second ≈ handler cost × context switches per second
                        + refresh cost × refreshes per second
```

Measured on a Ryzen 5 3600, the switch handler cost 8 ms/s under ordinary load
(12,454 switches a second) and 1.8 CPU cores during a deliberate switch storm
(2.4 million a second). An always-on probe charges every context switch on the
machine for a status bar that refreshes once a second, and charges most when
the machine is busiest, which is exactly when a monitor should cost least. It
also needed root or `CAP_BPF` and `CAP_PERFMON`, compiled its probe with Clang
at startup, and covered only per-task figures; the saturation measures above
come from kernel counters that already exist.

eBPF remains the right tool for questions those counters can't answer, such as
attributing latency to individual tasks, run for the duration of an
investigation rather than continuously. Version 2 reads the counters the
kernel already keeps. The [case study](https://over-yonder.tech/work/rstat.html)
describes version 1 in detail.

## Building

```sh
nix build
```

The package wraps the binary so it finds the NVIDIA driver under
`/run/opengl-driver/lib` and `iw` for Wi-Fi details. Without an NVIDIA driver
the GPU section reports itself unavailable.

## Configuration

The daemon reads `$XDG_CONFIG_HOME/rstat/config.toml`, or the file given with
`rstat daemon --config PATH`. Every setting is optional. Each section has an
`enable` switch and a switch for each group of tooltip lines, all on by default.
A switched-off group isn't sampled, and a switched-off section sends an empty
line, which hides its Waybar module.

```toml
interval_ms = 1000          # how often watched sections are sampled, at least 100

[colors]                    # Pango colours
ok = "#a6e3a1"
warning = "#fab387"
critical = "#f38ba8"
label = "#7f849c"
value = "#cdd6f4"
heading = "#89b4fa"

[cpu]                       # load, pressure, interrupt_pressure, utilization, scheduler, frequency,
fans = false                # scaling, fans, temperature, thermal_throttling, acpi_throttling

[memory]                    # pressure, paging, reclaim, ram, zram, processes

[disks]                     # devices, dirty_pages, root_filesystem, pressure, blocked_tasks

[network]                   # nas, retransmissions, connections, listen_queue, udp_errors,
nas = false                 # kernel_backlog, interfaces

[gpu]                       # utilization, vram, clock_limits, clocks, power, temperature, fans,
devices = [0]               # pcie, pcie_traffic, processes; devices lists NVML indices, empty for all
processes = false
```

The memory section's process table comes from a root sampler, run about once a
minute:

```sh
rstat sample-process-memory /run/waybar-memory-processes.json
```

## NixOS and Home Manager

The flake provides a NixOS module for the root sampler and a Home Manager module
for the daemon, whose options mirror the configuration file
(`programs.rstat.cpu.fans`, `programs.rstat.gpu.devices` and so on, each
documented in `nix/sections.nix`):

```nix
# flake inputs
rstat.url = "github:overyonder/rstat";

# NixOS configuration
imports = [inputs.rstat.nixosModules.default];
services.rstat.processMemory.enable = true;

# Home Manager configuration
imports = [inputs.rstat.homeManagerModules.default];
programs.rstat = {
  enable = true;
  gpu.enable = false;
  network.nas = false;
};
programs.waybar.settings.main = {
  modules-right = ["custom/cpu" "custom/memory" "custom/disks" "custom/network"];
  "custom/cpu" = config.programs.rstat.waybarModules.cpu // {format = " {}";};
  "custom/memory" = config.programs.rstat.waybarModules.memory // {format = "󰍛 {}";};
  "custom/disks" = config.programs.rstat.waybarModules.disks // {format = "󰋊 {}";};
  "custom/network" = config.programs.rstat.waybarModules.network // {
    format = "{icon} {text}";
    format-icons = {ethernet = "󰈀"; wifi = "󰤨"; disconnected = "󰤭";};
  };
};
```

`waybarModules` holds a definition for each enabled section: the watcher
command, JSON output and restart interval.

## Other distributions

Run the daemon as a user service, `~/.config/systemd/user/rstat.service`,
enabled with `systemctl --user enable --now rstat`:

```ini
[Unit]
Description=rstat system monitor for Waybar
PartOf=graphical-session.target

[Service]
ExecStart=/usr/local/bin/rstat daemon
Restart=on-failure

[Install]
WantedBy=graphical-session.target
```

Add a Waybar module per section. Each watcher exits if the daemon goes away, so
Waybar restarts it:

```jsonc
"custom/cpu": {
    "exec": "rstat watch cpu",
    "return-type": "json",
    "restart-interval": 5,
    "format": " {}"
},
"custom/network": {
    "exec": "rstat watch network",
    "return-type": "json",
    "restart-interval": 5,
    "format": "{icon} {text}",
    "format-icons": { "ethernet": "󰈀", "wifi": "󰤨", "disconnected": "󰤭" }
}
```

The sections are `cpu`, `memory`, `disks`, `network` and `gpu`. The network
section sets `alt` to `ethernet`, `wifi` or `disconnected` for format icons.

For the process table, a root cron entry is enough:

```sh
* * * * * /usr/local/bin/rstat sample-process-memory /run/waybar-memory-processes.json
```
