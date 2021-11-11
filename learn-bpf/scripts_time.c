/*
 * monitoring execution time of the scripts
 * 1. monitor execve syscall, record starttime and pid
 * 2. monitor wait4 syscall, get pid and calculate endtime
 *
 */
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/string.h>


#define SEC(NAME) __attribute__((section(NAME), used))

#define COMMAND_LEN 128
#define MAP_HASH_MAX_ENTRIES 1024
#define MAP_ARRAY_MAX_ENTRIES 128

// copy from bpf_helpers.h
#define PT_REGS_RC(x) ((x)->rax)

#ifdef DEBUG
    #define __DEBUG__
#else
    #undef __DEBUG__
#endif


typedef unsigned long long u64;
typedef unsigned int u32;

/*
 * for script statistic
 */
typedef struct _script_stat {
    u32 pid;
    u64 time_ns;
    char parent_comm[COMMAND_LEN];
    char execve_comm[COMMAND_LEN];
} script_stat;

struct execve_args {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char *filename;
    const char *const *argv;
    const char *const *envp;
};


/*
 * bpf-map to output statistic info to userspace
 */
struct bpf_map_def SEC("maps") perf_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = MAP_ARRAY_MAX_ENTRIES
};

/*
 * bpf-map to store starttime and command for script
 * for sharing data between kernel bpf prog
 */
struct bpf_map_def SEC("maps") script_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(script_stat),
    .max_entries = MAP_HASH_MAX_ENTRIES
};


//SEC("kprobe/sys_execve")
SEC("tracepoint/syscalls/sys_enter_execve")
int enter_sys_execve(struct execve_args *args)
{
    // compare executable script name
    // and record starttime
    script_stat stat = {};

    stat.time_ns = bpf_ktime_get_ns();
    stat.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_str(stat.execve_comm, sizeof(stat.execve_comm), args->filename);
    bpf_get_current_comm(stat.parent_comm, sizeof(stat.parent_comm));

#ifdef __DEBUG__
    char fmt[] = "enter execve: %s, pid %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), stat.execve_comm, stat.pid);
#endif

    (void)bpf_map_update_elem(&script_table, &stat.pid, &stat, BPF_NOEXIST);
    return 0;
}


static int output_stat_event(void *ctx, script_stat *stat)
{
#ifdef __DEBUG__
    char fmt0[] = "execve parent: %s\n";
    bpf_trace_printk(fmt0, sizeof(fmt0), stat->parent_comm);

    char fmt1[] = "execve: %s, pid: %d, time_ns: %lu\n";
    bpf_trace_printk(fmt1, sizeof(fmt1), stat->execve_comm,
                     stat->pid, stat->time_ns);
#endif

    script_stat n_stat = {};
    n_stat.time_ns = stat->time_ns;
    n_stat.pid = stat->pid;
    memcpy(n_stat.parent_comm, stat->parent_comm, sizeof(n_stat.parent_comm));
    memcpy(n_stat.execve_comm, stat->execve_comm, sizeof(n_stat.execve_comm));
    int ret = bpf_perf_event_output(ctx, &perf_events, 0,
                                    &n_stat, sizeof(script_stat));
    if (ret)
    {
        char fmt_err[] = "perf event output failed, ret = %d\n";
        char fmt_err2[] = "execve: %s, pid: %d, time_ns: %lu\n";
        bpf_trace_printk(fmt_err, sizeof(fmt_err), ret);
        bpf_trace_printk(fmt_err2, sizeof(fmt_err2), n_stat.execve_comm,
                         n_stat.pid, n_stat.time_ns);
    }
    return ret;
}


SEC("tracepoint/syscalls/sys_enter_exit_group")
int exit_sys_exit(void *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

#ifdef __DEBUG__
    char fmt[] = "enter exit pid %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), pid);
#endif

    script_stat *stat = bpf_map_lookup_elem(&script_table, &pid);
    if (!stat)
    {
        return 0;
    }

    stat->time_ns = bpf_ktime_get_ns() - stat->time_ns;

    (void)output_stat_event(ctx, stat);
    
    // final delete elem in map
    (void)bpf_map_delete_elem(&script_table, &pid);
    return 0;
}


char _license[] SEC("license") = "GPL";

