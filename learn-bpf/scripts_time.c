/*
 * monitoring execution time of the scripts
 * 1. monitor execve syscall, record starttime and pid
 * 2. monitor wait4 syscall, get pid and calculate endtime
 *
 */
#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define COMMAND_LEN 64
#define MAP_HASH_MAX_ENTRIES 1024

typedef unsigned long long u64;

/*
 * struct for statistics
 */
typedef struct _script_stat {
	u64 start_time_ns;
	u64 pid;
	char command[COMMAND_LEN];
} script_stat;

/*
 * bpf-map to store starttime and command for script
 */
struct bpf_map_def SEC("maps") script_table = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(script_stat),
	.max_entries = MAP_HASH_MAX_ENTRIES
};


SEC("kprobe/sys_execve")
int enter_sys_execve(struct pt_regs *regs, const char __user *filename, void *argv, void *envp)
{
	// compare executable script name
	// and record starttime
    char fmt[] = "enter sys execve: %s";
    script_stat stat = {};

    stat.start_time_ns = bpf_ktime_get_ns();
    stat.pid = bpf_get_current_pid_tgid();
    //(void)strncpy(stat.command, filename, sizeof(stat.command));
    //bpf_get_current_comm(stat.command, sizeof(stat.command));
    bpf_map_update_elem(&script_table, &stat.pid, &stat, BPF_ANY);

    bpf_trace_printk(fmt, sizeof(fmt), stat.command);

	return 0;
}


SEC("kretprobe/sys_wait4")
int exit_sys_wait4()
{
	// findout specific script by pid
	// and calculate spendtime
    char fmt[] = "exit sys wait4";
    bpf_trace_printk(fmt, sizeof(fmt));
	u64 end_time = bpf_ktime_get_ns();
	return 0;
}

char _license[] SEC("license") = "GPL";

