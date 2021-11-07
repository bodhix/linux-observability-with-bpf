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
#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_PARM4(x) ((x)->rcx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->rsp)
#define PT_REGS_FP(x) ((x)->rbp)
#define PT_REGS_RC(x) ((x)->rax)
#define PT_REGS_SP(x) ((x)->rsp)
#define PT_REGS_IP(x) ((x)->rip)


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

/*
 * bpf-map to store starttime and command for script
 */
struct bpf_map_def SEC("maps") script_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(script_stat),
    .max_entries = MAP_HASH_MAX_ENTRIES
};


SEC("kprobe/sys_execve")
int enter_sys_execve(struct pt_regs *regs)
{
    // compare executable script name
    // and record starttime
    char *filename_p;
    script_stat stat = {};

    stat.time_ns = bpf_ktime_get_ns();
    stat.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read(&filename_p, sizeof(filename_p), (void *)PT_REGS_PARM1(regs));
    bpf_probe_read_str(stat.execve_comm, sizeof(stat.execve_comm), filename_p);
    bpf_get_current_comm(stat.parent_comm, sizeof(stat.parent_comm));

    (void)bpf_map_update_elem(&script_table, &stat.pid, &stat, BPF_NOEXIST);
    
    char fmt[] = "execve enter: %s, %p, %p\n";
    bpf_trace_printk(fmt, sizeof(fmt), stat.parent_comm, filename_p, PT_REGS_PARM1(regs));

    char fmt2[] = "execve enter2: %d, %s\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), stat.pid, stat.execve_comm);
    return 0;
}


static int output_script_stat_event(script_stat *stat)
{
    char fmt[] = "execve: %s, pid: %d, time_ns: %lu";
    bpf_trace_printk(fmt, sizeof(fmt), stat->execve_comm,
                     stat->pid, stat->time_ns);
    return 0;
}

SEC("kretprobe/sys_wait4")
int exit_sys_wait4(struct pt_regs *regs)
{
    // findout specific script by pid
    // and calculate spendtime
    int ret = PT_REGS_RC(regs);
    u32 pid = 0;
    //char fmt[] = "wait4 exit: %d, pid:%d";
    //u32 pid_c = bpf_get_current_pid_tgid() >> 32;
    //bpf_trace_printk(fmt, sizeof(fmt), pid, pid_c); 
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

    //(void)output_script_stat_event(stat);
    
    // final delete elem in map
    (void)bpf_map_delete_elem(&script_table, &pid);

    return 0;
}

char _license[] SEC("license") = "GPL";

