// rstat eBPF probe: per-PID CPU, RSS, IO via sched_switch tracepoint
// All per-process metrics collected in-kernel, no /proc walk needed.
// Compiled with: clang -target bpf -O2 -g -c probe.bpf.c -o probe.bpf.o
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_PIDS 8192

// Per-PID stats: cumulative cpu_ns, latest snapshots for rss/io
struct pid_stats {
    __u64 cpu_ns;       // cumulative on-CPU nanoseconds
    __u64 rss_pages;    // latest RSS snapshot (file+anon+shm pages)
    __u64 io_rb;        // cumulative read_bytes from task->ioac
    __u64 io_wb;        // cumulative write_bytes from task->ioac
    __u32 tgid;         // thread-group id (process id)
    char  comm[TASK_COMM_LEN];
    __u8  state;        // 'D' = uninterruptible, 'Z' = zombie, 0 = normal
    __u8  seen;         // client sets on first observation; cleared on exit/free
    __u16 _pad;
};

// System-wide counters
struct sys_stats {
    __u64 idle_ns;      // cumulative idle time (swapper/PID 0)
};

struct sched_in {
    __u64 ts;
};

// Per-PID stats map: userspace iterates this
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key, __u32);
    __type(value, struct pid_stats);
} stats SEC(".maps");

// System-wide stats: single-entry array
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sys_stats);
} sys SEC(".maps");

// Per-PID schedule-in timestamp (internal)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key, __u32);
    __type(value, struct sched_in);
} sched_start SEC(".maps");

// Self-timing histogram: 32 log2(ns) buckets
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} latency SEC(".maps");

static __always_inline __u32 log2_u64(__u64 v)
{
    __u32 r = 0;
    if (v > 0xFFFFFFFF) { v >>= 32; r += 32; }
    if (v > 0xFFFF) { v >>= 16; r += 16; }
    if (v > 0xFF) { v >>= 8; r += 8; }
    if (v > 0xF) { v >>= 4; r += 4; }
    if (v > 0x3) { v >>= 2; r += 2; }
    if (v > 0x1) { r += 1; }
    return r;
}

// sched_switch tracepoint context
struct sched_switch_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    char           prev_comm[16];
    int            prev_pid;
    int            prev_prio;
    long           prev_state;
    char           next_comm[16];
    int            next_pid;
    int            next_prio;
};

// 4-byte reads for tracepoint ctx (verifier rejects 8-byte ctx access)
static __always_inline void read_tp_comm(char *dst, const char *src)
{
    *(__u32 *)(dst + 0)  = *(__u32 *)(src + 0);
    *(__u32 *)(dst + 4)  = *(__u32 *)(src + 4);
    *(__u32 *)(dst + 8)  = *(__u32 *)(src + 8);
    *(__u32 *)(dst + 12) = *(__u32 *)(src + 12);
}

// Snapshot RSS and IO from task_struct into pid_stats
static __always_inline void snapshot_task(struct pid_stats *s)
{
    struct task_struct *task = (void *)bpf_get_current_task();

    // Process identity (aggregate per-process in userspace)
    __u32 tgid = 0;
    bpf_probe_read_kernel(&tgid, sizeof(tgid), &task->tgid);
    s->tgid = tgid;

    // RSS: mm->rss_stat[0..3].count (percpu_counter approx value)
    // indices: 0=file, 1=anon, 2=swap, 3=shmem; RSS = file+anon+shmem
    struct mm_struct *mm = 0;
    bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
    if (mm) {
        __s64 file = 0, anon = 0, shm = 0;
        bpf_probe_read_kernel(&file, sizeof(file), &mm->rss_stat[0].count);
        bpf_probe_read_kernel(&anon, sizeof(anon), &mm->rss_stat[1].count);
        bpf_probe_read_kernel(&shm,  sizeof(shm),  &mm->rss_stat[3].count);
        __s64 total = file + anon + shm;
        s->rss_pages = total > 0 ? (__u64)total : 0;
    }

    // IO: task->ioac.read_bytes, write_bytes (cumulative)
    __u64 rb = 0, wb = 0;
    bpf_probe_read_kernel(&rb, sizeof(rb), &task->ioac.read_bytes);
    bpf_probe_read_kernel(&wb, sizeof(wb), &task->ioac.write_bytes);
    s->io_rb = rb;
    s->io_wb = wb;
}

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct sched_switch_args *ctx)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 prev = ctx->prev_pid;
    __u32 next = ctx->next_pid;

    // Account time for prev (switching out)
    struct sched_in *si = bpf_map_lookup_elem(&sched_start, &prev);
    if (si && si->ts > 0) {
        __u64 delta = now - si->ts;

        if (prev == 0) {
            // Idle task: accumulate system idle time
            __u32 z = 0;
            struct sys_stats *ss = bpf_map_lookup_elem(&sys, &z);
            if (ss)
                __sync_fetch_and_add(&ss->idle_ns, delta);
        } else {
            // Per-PID: accumulate CPU, snapshot RSS + IO
            struct pid_stats *s = bpf_map_lookup_elem(&stats, &prev);
            if (s) {
                __sync_fetch_and_add(&s->cpu_ns, delta);
                snapshot_task(s);
                if (ctx->prev_state & 0x02)
                    s->state = 'D';
            } else {
                struct pid_stats ns = {};
                ns.cpu_ns = delta;
                if (ctx->prev_state & 0x02)
                    ns.state = 'D';
                read_tp_comm(ns.comm, ctx->prev_comm);
                snapshot_task(&ns);
                bpf_map_update_elem(&stats, &prev, &ns, BPF_NOEXIST);
            }
        }
    }
    bpf_map_delete_elem(&sched_start, &prev);

    // Record schedule-in time for next (including idle/PID 0)
    struct sched_in new_si = { .ts = now };
    bpf_map_update_elem(&sched_start, &next, &new_si, BPF_ANY);

    // Clear D-state for next (it's running now)
    if (next != 0) {
        struct pid_stats *ns = bpf_map_lookup_elem(&stats, &next);
        if (ns && ns->state == 'D')
            ns->state = 0;
    }

    // Self-timing: record probe latency in log2(ns) histogram
    __u64 _dt = bpf_ktime_get_ns() - now;
    __u32 _bk = log2_u64(_dt);
    if (_bk > 31) _bk = 31;
    __u64 *_bv = bpf_map_lookup_elem(&latency, &_bk);
    if (_bv) __sync_fetch_and_add(_bv, 1);

    return 0;
}

// Clean up on process exit
struct sched_process_exit_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    char           comm[16];
    int            pid;
    int            prio;
};

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_exit(struct sched_process_exit_args *ctx)
{
    __u32 pid = ctx->pid;
    bpf_map_delete_elem(&sched_start, &pid);
    struct pid_stats *s = bpf_map_lookup_elem(&stats, &pid);
    if (s) {
        s->state = 'Z';
        s->seen = 0;
    }
    return 0;
}

// Clean up on process reap (zombie -> freed)
struct sched_process_free_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    // tracepoint format is __data_loc char[] comm (u32 location/size descriptor)
    __u32          comm_loc;
    int            pid;
    int            prio;
};

SEC("tracepoint/sched/sched_process_free")
int handle_sched_free(struct sched_process_free_args *ctx)
{
    __u32 pid = ctx->pid;
    bpf_map_delete_elem(&sched_start, &pid);
    bpf_map_delete_elem(&stats, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
