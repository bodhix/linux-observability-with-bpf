#include "bpf_load.h"
#include <bpf/libbpf.h>
#include <linux/types.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <regex.h>

#define PERF_POLL_TIME_MS 1000
#define PERF_PAGE_CNT 8

#define COMMAND_LEN 128
#define LOG_MAX_LEN 2048

#define FILTER_MASK_PID (1<<1)
#define FILTER_MASK_PARENT_COMM (1<<2)
#define FILTER_MASK_EXECVE_COMM (1<<3)


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
    char comm[COMMAND_LEN];
    int8_t regex;
    regex_t reg;
} comm_filter;

// structure for event filter
// sub-filter has "and" relationship, not "or"
typedef struct _stat_filter {
    pid_filter pid;
    comm_filter parent_comm;
    comm_filter execve_comm;
    u32 mask;
} stat_filter;


// store argv for filter
static stat_filter s_filter;


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

/* return 0 means pass filter
 * otherwise, did not pass filter
 */
static int filter_event(script_stat *stat)
{
    int ret = 0;
    if (s_filter.mask & FILTER_MASK_EXECVE_COMM) {
        if (s_filter.execve_comm.regex) {
            ret = regexec(&s_filter.execve_comm.reg, stat->execve_comm, 0, NULL, 0);
            if (ret != 0) {
                return -1;
            }
        }
        else {
            ret = strncmp(s_filter.execve_comm.comm, stat->execve_comm,
                          sizeof(stat->execve_comm));
            if (ret != 0) {
                return -1;
            }
        }
    }

    if (s_filter.mask & FILTER_MASK_PARENT_COMM) {
        if (s_filter.parent_comm.regex) {
            ret = regexec(&s_filter.parent_comm.reg, stat->parent_comm, 0, NULL, 0);
            if (ret != 0) {
                return -1;
            }
        }
        else {
            ret = strncmp(s_filter.parent_comm.comm, stat->parent_comm,
                          sizeof(stat->parent_comm));
            if (ret != 0) {
                return -1;
            }
        }
    }

    return 0;
}

static void print_bpf_output(void *ctx, int cpu,
                             void *data, __u32 size)
{
    script_stat *stat = (script_stat *)data;
    // we filter event here to provide precision of results
    int ret = filter_event(stat);
    if (ret != 0) {
        return;
    }

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


static void usage(void)
{
    printf("usage: {PROGRAMNAME} [-r] [-R] [-s PATTERN] [-p PATTERN]\n");
    printf("\t-r: use regex to match script, default 0\n");
    printf("\t-R: use regex to match parent script, default 0\n");
    printf("\t-s: script name to execution time\n");
    printf("\t-p: parent script name to execution time\n");
}

static int parse_argv(int argc, char **argv)
{
    int opt = 0;
    int ret = 0;
    char regex_err[1024] = {};

    s_filter.execve_comm.regex = 0;
    s_filter.parent_comm.regex = 0;
    while ((opt = getopt(argc,argv,"rRs:p:")) !=- 1) {
        switch(opt) {
            case 'r':
                s_filter.execve_comm.regex = 1;
                break;
            case 'R':
                s_filter.parent_comm.regex = 1;
                break;
            case 's':
                strncpy(s_filter.execve_comm.comm, optarg, sizeof(s_filter.execve_comm.comm));
                s_filter.mask |= FILTER_MASK_EXECVE_COMM;
                break;
            case 'p':
                strncpy(s_filter.parent_comm.comm, optarg, sizeof(s_filter.parent_comm.comm));
                s_filter.mask |= FILTER_MASK_PARENT_COMM;
                break;
            default:
                usage();
                exit(1);
        }
    }
 
    // compile regex if use it
    if ((s_filter.mask & FILTER_MASK_EXECVE_COMM) && s_filter.execve_comm.regex) {
        ret = regcomp(&s_filter.execve_comm.reg, s_filter.execve_comm.comm, REG_EXTENDED);
        if (ret != 0) {
            regerror(ret, &s_filter.execve_comm.reg, regex_err, sizeof(regex_err));
            return -1;
        }
    }
    if ((s_filter.mask & FILTER_MASK_PARENT_COMM) && s_filter.parent_comm.regex) {
        ret = regcomp(&s_filter.parent_comm.reg, s_filter.parent_comm.comm, REG_EXTENDED);
        if (ret != 0) {
            regerror(ret, &s_filter.parent_comm.reg, regex_err, sizeof(regex_err));
            return -1;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret = 0;
 
    openlog("calculate_script_time", LOG_CONS, LOG_USER);

    // add statistic filter, store result in static variable s_filter
    ret = parse_argv(argc, argv);
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
