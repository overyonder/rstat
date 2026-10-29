# The sections rstat serves and the tooltip groups each can switch off, with what each group shows.
# Both modules generate their options from this table; it mirrors src/config/mod.rs.
{
  cpu = {
    load = "Load averages, runnable tasks and I/O waiters.";
    pressure = "CPU pressure stall information.";
    interrupt_pressure = "Time lost to interrupts.";
    utilization = "Executing, user, system, interrupt, I/O wait and steal time.";
    scheduler = "Context switches and tasks created per second.";
    frequency = "Current frequencies across threads.";
    scaling = "Scaling driver, governor, energy preference, frequency limits and boost.";
    fans = "Fan speeds from hardware sensors.";
    temperature = "CPU temperature sensors (k10temp, zenpower or coretemp).";
    thermal_throttling = "Intel thermal throttling events.";
    acpi_throttling = "ACPI processor cooling devices with active cooling requests.";
  };
  memory = {
    pressure = "Memory pressure stall information.";
    paging = "Swap traffic, major page faults and refaults.";
    reclaim = "Direct and background reclaim, compaction stalls and OOM kills.";
    ram = "Available and free memory, swap use and RAM composition.";
    zswap = "Original size and physical RAM use of the compressed swap cache.";
    zram = "Compressed swap held in RAM.";
    processes = "Summed anonymous RSS and swap by program.";
  };
  disks = {
    devices = "Busy time, queue, throughput and latency for each disk.";
    dirty_pages = "Dirty pages and pages under writeback.";
    root_filesystem = "Use of the filesystem mounted at /.";
    pressure = "I/O pressure stall information.";
    blocked_tasks = "I/O waiters, with D-state thread counts during I/O waits.";
  };
  network = {
    nas = "SMB requests on the wire, active VFS operations, completed request rate and latency.";
    retransmissions = "TCP retransmissions and timeouts.";
    connections = "Established and new TCP connections.";
    listen_queue = "TCP listen queue overflows and drops.";
    udp_errors = "UDP buffer errors.";
    kernel_backlog = "Softnet drops and time squeezes.";
    interfaces = "Default route, addresses, link speed and traffic per interface.";
  };
  gpu = {
    utilization = "GPU activity, memory read/write activity, encoder and decoder utilization.";
    vram = "VRAM use and the driver's reservation.";
    clock_limits = "Time under each clock-limit policy and the active limit reasons.";
    clocks = "Graphics and memory clocks.";
    power = "Power draw against the limit.";
    temperature = "Temperature and headroom below the slowdown limit.";
    fans = "Fan speed targets.";
    pcie = "PCIe link generation and width, and replays.";
    pcie_traffic = "PCIe throughput, measured every 10 seconds.";
    processes = "VRAM by process.";
  };
}
