#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>  
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <argp.h>
#include "netqtop.h"
#include "netqtop.skel.h"
#include "compat.h"
#include "trace_helpers.h"

static struct netqtop_bpf *obj = NULL; 
static char dev_name[IFNAMSIZ] = ""; 
//move these functions down
static void cleanup() {
    if (obj) {
        netqtop_bpf__destroy(obj); 
        obj = NULL;
    }
//    libbpf_cleanup(); // Clean up libbpf resources
}

static void signal_handler(int signo) {
    cleanup();
    exit(EXIT_FAILURE);
}

int get_queue_num(const char *dev_name) {
    DIR *dir;
    struct dirent *entry;
    int tx_queues = 0;
    int rx_queues = 0;

    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/queues", dev_name);

    dir = opendir(path);
    if (dir == NULL) {
        fprintf(stderr, "Failed to open %s\n", path);
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && strncmp(entry->d_name, ".", 1) != 0 && strncmp(entry->d_name, "..", 2) != 0) {
            if (strncmp(entry->d_name, "rx", 2) == 0) {
                rx_queues++;
            } else if (strncmp(entry->d_name, "tx", 2) == 0) {
                tx_queues++;
            }
        }
    }

    closedir(dir);
    return tx_queues > rx_queues ? tx_queues : rx_queues;
}

static struct env {
    bool verbose;
    bool throughput;
    int interval;
} env = {};

const char *argp_program_version = "netqtop 0.1";
const char *argp_program_bug_address =
    "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
    "Traces the kernel functions performing packet transmit (xmit_one)\n"
    "and packet receive (__netif_receive_skb_core) on data link layer.\n"
    "USAGE: netqtop [-n] [nic] [-t throughput] [-i interval]\n"
    "\n"
    "EXAMPLES:\n"
    "    netqtop -n lo                 #  1s\n"
    "    netqtop -n lo -i 3  # 1s traffic summaries on lo\n"
    "    netqtop -n lo -i 10 # 10s traffic summaries on lo with BPS and PPS info";

static const struct argp_option opts[] = {
    {"name", 'n', "NAME", 0, "Specify network interface"},
    {"interval", 'i', "INTERVAL", 0, "Summary interval in seconds"},
    {"throughput", 't', "THROUGHPUT", 0, "See PPS and BPS"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key)
    {
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case 'v':
        env.verbose = true;
        break;
    case 't':
        env.throughput = true;
        break;
    case 'i':
        errno = 0;
        int interval = strtol(arg, NULL, 10);
        if (errno || interval <= 0)
        {
            printf("Invalid interval: %s\n", arg);
            exit(1);
        }
        env.interval = interval;
        break;
    case 'n':
        strncpy(dev_name, arg, IFNAMSIZ - 1);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}
char *to_str(double num)
{
    static char buffer[20];
    if (num > 1000000)
    {
        sprintf(buffer, "%.2fM", num / (1024 * 1024.0));
    }
    else if (num > 1000)
    {
        sprintf(buffer, "%.2fK", num / 1024.0);
    }
    else
    {
        if ((int)num == num)
        {
            sprintf(buffer, "%d", (int)num);
        }
        else
        {
            sprintf(buffer, "%.2f", num);
        }
    }
    return buffer;
}

void print_table(int qnum)
{
    printf("%-11s%-11s%-11s%-11s%-11s%-11s%-11s\n",
           "QueueID", "avg_size", "[0, 64)", "[64, 512)", "[512, 2K)", "[2K, 16K)", "[16K, 64K)");

    if (env.throughput)
    {
        printf("%-11s %-11s", "BPS", "PPS");
    }

    printf("\n");


    for (int i = 0; i < qnum; ++i)
    {
    }
}

int main(int argc, char **argv)
{
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };

    int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    obj = netqtop_bpf__open_opts(&open_opts);
    if (!obj)
    {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    err = netqtop_bpf__load(obj);
    if (err)
    {
        fprintf(stderr, "failed to load and verify BPF programs\n");
        cleanup();
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    int queue_num = get_queue_num(dev_name);

   
    while (1)
    {
        if (env.throughput) {
            print_table(queue_num);
        } else {
            print_table(queue_num);
        }

        sleep(env.interval);
    }

    cleanup(); 
    return 0;
}

