#include "bpf_load.h"
#include <bpf/libbpf.h>
#include <stdio.h>
#include <linux/types.h>

#define PERF_POLL_TIME_MS 1000
#define PERF_PAGE_CNT 8

#define COMMAND_LEN 128

typedef struct _script_stat {
    u32 pid;
    u64 time_ns;
    char parent_comm[COMMAND_LEN];
    char execve_comm[COMMAND_LEN];
} script_stat;


static void print_bpf_output(void *ctx, int cpu,
                             void *data, __u32 size)
{
    script_stat *stat = (script_stat *)data;
    float time_s = stat->time_ns / 1000000000;
    printf("%s execve: %s, pid: %d, time:%.3f\n",
           stat->parent_comm, stat->execve_comm, stat->pid, time_s);
}

static int receive_stat_event()
{
    struct perf_buffer_opts pb_opts = {};
    struct perf_buffer *pb = NULL;
    int ret = 0;

    pb_opts.sample_cb = print_bpf_output;
    pb = perf_buffer__new(map_fd[0], PERF_PAGE_CNT, &pb_opts);
    ret = libbpf_get_error(pb);
    if (ret) {
        printf("perf buffer new error: %d\n", ret);
        return -1;
    }

    while (true)
    {
        ret = perf_buffer__poll(pb, PERF_POLL_TIME_MS);
        if (ret < 0)
        {
            printf("perf buffer poll error: %d\n", ret);
        }
    }
}


int main(int argc, char **argv) {
    int ret = 0;
    ret = load_bpf_file("scripts_time.o");
    if (ret != 0) {
        printf("The kernel didn't load the BPF program\n");
        return -1;
    }

    // loop to receive stat event
    receive_stat_event();

    read_trace_pipe();

    return 0;
}
