#include "bpf_load.h"
#include <bpf/libbpf.h>
#include <linux/types.h>
#include <syslog.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>

#define PERF_POLL_TIME_MS 1000
#define PERF_PAGE_CNT 8

#define COMMAND_LEN 128

#define FILTER_MASK_PID (1>>1)
#define FILTER_MASK_PARENT_COMM (1>>2)
#define FILTER_MASK_EXECVE_COMM (1>>3)

#define LOG_MAX_LEN 2048

#ifdef CONSOLE
    #define __UDEBUG__
#else
    #undef __UDEBUG__
#endif


// structure of perf event
typedef struct _script_stat {
    u32 pid;
    u64 time_ns;
    char parent_comm[COMMAND_LEN];
    char execve_comm[COMMAND_LEN];
} script_stat;

// structure for event pid filter, not supported now
typedef struct _pid_filter {
    u32 pid;
    u32 nest_cnt;
} pid_filter;

typedef struct _comm_filter {
    int8_t exact;
    char comm[COMMAND_LEN];
} comm_filter;

// structure for event filter
// sub-filter has "and" relationship, not "or"
typedef struct _stat_filter {
    pid_filter pid;
    comm_filter parent_comm;
    comm_filter execve_comm;
    u32 mask;
} stat_filter;


static void get_timestamp(char *msg, int msg_size)
{
    struct timeval tv;
    struct tm tm_s;
    gettimeofday(&tv, NULL);

    uint32_t tv_usec = tv.tv_usec;
    localtime_r(&tv.tv_sec, &tm_s);

    snprintf(msg, msg_size, "%04d-%02d-%02d %02d:%02d:%02d.%04d",
             tm_s.tm_year + 1900, tm_s.tm_mon + 1, tm_s.tm_mday,
             tm_s.tm_hour, tm_s.tm_min, tm_s.tm_sec, tv_usec * 1000);
}

static void linfo(const char *fmt, ...)
{
    char log_msg[LOG_MAX_LEN] = {}; 

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(log_msg, LOG_MAX_LEN, fmt, ap);
    va_end(ap);

#ifdef __UDEBUG__
    char time_msg[25] = {};
    get_timestamp(time_msg, sizeof(time_msg));
    printf("[%s] %s\n", time_msg, log_msg);
#endif

    syslog(LOG_INFO, "%s", log_msg);
}

static void print_bpf_output(void *ctx, int cpu,
                             void *data, __u32 size)
{
    script_stat *stat = (script_stat *)data;
    double time_s = stat->time_ns / (double)1000000000;
    linfo("%s execve: %s, pid: %d, time:%.3f",
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
        linfo("perf buffer new failed, error: %d", ret);
        return -1;
    }

    while (true) {
        ret = perf_buffer__poll(pb, PERF_POLL_TIME_MS);
        if (ret < 0) {
            linfo("perf buffer poll failed, error: %d", ret);
        }
    }
}

static int parse_argv(stat_filter *filter, int argc, char **argv)
{
    return 0;
}

int main(int argc, char **argv)
{
    int ret = 0;
 
    openlog("calculate_script_time", LOG_CONS, LOG_USER);

    // add statistic filter
    stat_filter filter = {};
    ret = parse_argv(&filter, argc, argv);
    if (ret < 0) {
        linfo("parse argv failed, error: %d", ret);
        goto END;
    }

    ret = load_bpf_file("scripts_time_kern.o");
    if (ret != 0) {
        linfo("load bpf file failed, error: %d", ret);
        goto END;
    }

    // loop to receive stat event
    ret = receive_stat_event();
    if (ret < 0) {
        linfo("receive stat event failed, error: %d", ret);
        goto END;
    }
    // read_trace_pipe();
END:
    closelog();
    return ret;
}
