/*
 * monitoring execution time of the scripts
 * 1. monitor execve syscall, record starttime and pid
 * 2. monitor wait4 syscall, get pid and calculate endtime
 *
 */
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define COMMAND_LEN 64
#define MAP_HASH_MAX_ENTRIES 1024
/*
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
*/
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
    char fmt[] = "enter sys execve: %d";
    script_stat stat = {};

    stat.time_ns = bpf_ktime_get_ns();
    stat.pid = bpf_get_current_pid_tgid() >> 32;
    //(void)strncpy(stat.comm, (char *)PT_REGS_PARM1(regs), sizeof(stat.comm));
    bpf_get_current_comm(stat.parent_comm, sizeof(stat.parent_comm));
    (void)bpf_map_update_elem(&script_table, &stat.pid, &stat, BPF_NOEXIST);

    bpf_trace_printk(fmt, sizeof(fmt), stat.pid);

    return 0;
}


static int output_script_stat_event(script_stat *stat)
{
    char fmt[] = "%s execve: %s, pid: %d, time_ns: %lu";
    bpf_trace_printk(fmt, sizeof(fmt),
                     stat->parent_comm, stat->execve_comm,
                     stat->pid, stat->time_ns);
    return 0;
}


SEC("kretprobe/sys_wait4")
int exit_sys_wait4(struct pt_regs *regs)
{
    // findout specific script by pid
    // and calculate spendtime
    int pid = PT_REGS_RC(regs);
    if (pid < 0)
    {
        return 0;
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

char _license[] SEC("license") = "GPL";

