/*
 * monitoring execution time of the scripts
 * 1. monitor execve syscall, record starttime and pid
 * 2. monitor wait4 syscall, get pid and calculate endtime
 *
 */
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf_helpers.h>
#include <string.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define COMMAND_LEN 128
#define MAP_HASH_MAX_ENTRIES 1024

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
 * struct for statistics
 */
typedef struct _script_stat {
    u64 time_ns;
    u32 pid;
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
 * bpf-map to store starttime and command for script
 */
struct bpf_map_def SEC("maps") script_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(script_stat),
    .max_entries = MAP_HASH_MAX_ENTRIES
};

/*
SEC("tracepoint/syscalls/sys_enter_execve")
int enter_sys_execve(struct execve_args *args)
{
    // compare executable script name
    // and record starttime
    char *filename_p = 0;

    script_stat stat = {};

    stat.time_ns = bpf_ktime_get_ns();
    stat.pid = bpf_get_current_pid_tgid() >> 32;
    //bpf_probe_read(&filename_p, sizeof(filename_p), args->filename);
    //bpf_probe_read_str(stat.execve_comm, sizeof(stat.execve_comm), filename_p);
    bpf_probe_read_str(stat.execve_comm, sizeof(stat.execve_comm), args->filename);
    bpf_get_current_comm(stat.parent_comm, sizeof(stat.parent_comm));

    
    char fmt[] = "execve enter: %s, %p\n";
    bpf_trace_printk(fmt, sizeof(fmt), stat.parent_comm, filename_p);

    char fmt2[] = "execve enter2: %d, %p, %s\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), stat.pid, stat.execve_comm, stat.execve_comm);
    return 0;
}
*/

//SEC("kprobe/sys_execve")
SEC("tracepoint/syscalls/sys_enter_execve")
int enter_sys_execve(struct execve_args *args)
{
    // compare executable script name
    // and record starttime
    script_stat stat = {};

    stat.time_ns = bpf_ktime_get_ns();
    stat.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_str(&stat.execve_comm, sizeof(stat.execve_comm), args->filename);
    bpf_get_current_comm(stat.parent_comm, sizeof(stat.parent_comm));

    (void)bpf_map_update_elem(&script_table, &stat.pid, &stat, BPF_NOEXIST);

#ifdef __DEBUG__
    char fmt[] = "execve enter: %s, %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), stat.execve_comm, stat.pid);
#endif
    return 0;
}


static int output_script_stat_event(script_stat *stat)
{
    char fmt[] = "execve: %s, pid: %d, time_ns: %lu";
    bpf_trace_printk(fmt, sizeof(fmt), stat->execve_comm,
                     stat->pid, stat->time_ns);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_exit_group")
int exit_sys_exit(void *res)
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

    (void)output_script_stat_event(stat);
    
    // final delete elem in map
    (void)bpf_map_delete_elem(&script_table, &pid);

    return 0;
}


/*
SEC("kretprobe/sys_wait4")
int exit_sys_wait4(struct pt_regs *regs)
{
    // findout specific script by pid
    // and calculate spendtime
    int ret = PT_REGS_RC(regs);
    u32 pid = 0;

    char fmt[] = "wait4 pid %d return, ret: %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), bpf_get_current_pid_tgid() >> 32, ret);

    if (ret < 0 && ret != -ECHILD)
    {
        return 0;
    }

    if (pid == -ECHILD)
    {
        // get current pid
        pid = bpf_get_current_pid_tgid() >> 32;
    }
    else
    {
        pid = ret;
    }
    script_stat *stat = bpf_map_lookup_elem(&script_table, &pid);
    if (!stat)
    {
        return 0;
    }

    stat->time_ns = bpf_ktime_get_ns() - stat->time_ns;

    (void)output_script_stat_event(stat);
    
    // final delete elem in map
    (void)bpf_map_delete_elem(&script_table, &pid);

    return 0;
}
*/

char _license[] SEC("license") = "GPL";

