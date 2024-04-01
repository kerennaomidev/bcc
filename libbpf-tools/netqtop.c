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
#include "btf_helpers.h"
#define MAX_QUEUES 1024

static char dev_name[IFNAMSIZ] = "";
static struct env {
    bool verbose;
    bool throughput;
    int interval;
} env = {};

const char *argp_program_version = "netqtop 0.1";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] = "Traces the kernel functions performing packet transmit (xmit_one)\n"
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

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
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
            if (errno || interval <= 0) {
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

char *to_str(double num) {
    static char buffer[20];
    if (num > 1000000) {
        sprintf(buffer, "%.2fM", num / (1024 * 1024.0));
    } else if (num > 1000) {
        sprintf(buffer, "%.2fK", num / 1024.0);
    } else {
        if ((int)num == num) {
            sprintf(buffer, "%d", (int)num);
        } else {
            sprintf(buffer, "%.2f", num);
        }
    }
    return buffer;
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

void print_table(struct queue_data *table, int qnum, int print_interval) {
    printf("%-11s%-11s%-11s%-11s%-11s%-11s%-11s",
           "QueueID", "avg_size", "[0, 64)", "[64, 512)", "[512, 2K)", "[2K, 16K)", "[16K, 64K)");

    if (env.throughput) {
        printf("%-11s%-11s", "BPS", "PPS");
    }
    printf("\n");

    int tBPS = 0, tPPS = 0, tAVG = 0;
    int tGroup[5] = {0};
    int tpkt = 0, tlen = 0;
    int qids[qnum];
    memset(qids, 0, sizeof(qids));

    for (int i = 0; i < qnum; ++i) {
        struct queue_data *item = &table[i];
        if (item->num_pkt > 0) {
            qids[i] = 1;
            tlen += item->total_pkt_len;
            tpkt += item->num_pkt;
            tGroup[0] += item->size_64B;
            tGroup[1] += item->size_512B;
            tGroup[2] += item->size_2K;
            tGroup[3] += item->size_16K;
            tGroup[4] += item->size_64K;
        }
    }

    tBPS = tlen / print_interval;
    tPPS = tpkt / print_interval;
    if (tpkt != 0) {
        tAVG = tlen / tpkt;
    }

    for (int k = 0; k < qnum; ++k) {
        struct queue_data *item = &table[k];
        int avg = 0;
        if (item->num_pkt != 0) {
            avg = item->total_pkt_len / item->num_pkt;
        }

        printf("%-11d%-11d%-11s%-11s%-11s%-11s%-11s%-11s", k,
               avg,
               to_str(avg),
               to_str(item->size_64B),
               to_str(item->size_512B),
               to_str(item->size_2K),
               to_str(item->size_16K),
               to_str(item->size_64K));

        if (env.throughput) {
            int BPS = item->total_pkt_len / print_interval;
            int PPS = item->num_pkt / print_interval;
            printf("%-11s%-11s\n", to_str(BPS), to_str(PPS));
        } else {
            printf("\n");
        }
    }

    printf("Total      %-11s%-11s%-11s%-11s%-11s%-11s",
           to_str(tAVG),
           to_str(tGroup[0]),
           to_str(tGroup[1]),
           to_str(tGroup[2]),
           to_str(tGroup[3]),
           to_str(tGroup[4]));

    if (env.throughput) {
        printf("%-11s%-11s\n", to_str(tBPS), to_str(tPPS));
    } else {
        printf("\n");
    }
}

void print_result(struct netqtop_bpf *obj) {
    int tx_fd, rx_fd;
    struct queue_data tx_data[MAX_QUEUES], rx_data[MAX_QUEUES];
    int tx_qnum, rx_qnum;
    __u16 key;

    tx_qnum = get_queue_num(dev_name);
    tx_fd = bpf_map__fd(obj->maps.txevent);
    for (int i = 0; i < tx_qnum; ++i) {
        key = i;
        bpf_map_lookup_elem(tx_fd, &key, &tx_data[i]);
    }

    printf("%s\n", asctime(localtime(&(time_t){time(NULL)})));
    printf("TX\n");
    print_table(tx_data, tx_qnum, env.interval);

    rx_qnum = get_queue_num(dev_name);
    rx_fd = bpf_map__fd(obj->maps.rxevent);
    for (int i = 0; i < rx_qnum; ++i) {
        key = i;
        bpf_map_lookup_elem(rx_fd, &key, &rx_data[i]);
    }

    printf("\n");
    printf("RX\n");
    print_table(rx_data, rx_qnum, env.interval);

    if (env.throughput) {
        printf("----------------------------------------------------------------------------------------------------------------------\n");
    } else {
        printf("-----------------------------------------------------------------------------\n");
    }
}


void sig_int(int signo) {
    exit(signo);
}

int main(int argc, char **argv) {
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };

    struct netqtop_bpf *obj;
    int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);

    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    err = ensure_core_btf(&open_opts);
    if (err) {
        fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
        return 1;
    }

    obj = netqtop_bpf__open_opts(&open_opts);
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    err = netqtop_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load and verify BPF programs\n");
        goto cleanup;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        perror("can't set signal handler");
        err = 1;
        goto cleanup;
    }
   // int queue_num = get_queue_num(dev_name);
    while (1) {
        print_result(obj);
        sleep(env.interval);
    }

cleanup:
    netqtop_bpf__destroy(obj);
    cleanup_core_btf(&open_opts);

    return err != 0;
}

