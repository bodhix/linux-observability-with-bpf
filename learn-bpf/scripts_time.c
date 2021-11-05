/*
 * monitoring execution time of the scripts
 * 1. monitor execve syscall, record starttime and pid
 * 2. monitor wait4 syscall, get pid and calculate endtime
 *
 */
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>

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
	char[COMMAND_LEN] command;
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
int enter_sys_execve(struct pt_regs *regs)
{
	// compare executable script name
	// and record starttime
	u64 start_time = bpf_ktime_get_ns();
	return 0;
}


SEC("kretprobe/sys_wait4")
int exit_sys_wait4()
{
	// findout specific script by pid
	// and calculate spendtime
	u64 end_time = bpf_ktime_get_ns();
	return 0;
}

char _license[] SEC("license") = "GPL";


