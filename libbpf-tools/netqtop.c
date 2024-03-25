#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "netqtop.h"
#include "netqtop.skel.h"
#include "compat.h"
#include "trace_helpers.h"

static struct env {
	bool verbose;
	bool throughput;
} env { };

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
"    netqtop -n lo -i 10 # 10s traffic summaries on lo with BPS and PPS info

static const struct argp_option opts[] = {
	{ "name", 'n', "NAME", 0, "Specify network interface" },
	{ "interval", 'i', "INTERVAL", 0, "Summary interval in seconds"},
	{ "throughput", 't', "THROUGHPUT", 0, "See PPS and BPS" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		verbose = true;
		break;
	case 't':
		throughput = true;
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
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

char* to_str(double num) {
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

void print_table(struct bpf_map *table, int qnum) {
    printf("%-11s%-11s%-11s%-11s%-11s%-11s%-11s\n",
           "QueueID", "avg_size", "[0, 64)", "[64, 512)", "[512, 2K)", "[2K, 16K)", "[16K, 64K)");

    if (throughput==true) {
        printf("%-11s %-11s", "BPS", "PPS");
    }

    printf("\n");

    double tBPS = 0, tPPS = 0, tAVG = 0;
    uint64_t tGroup[5] = {0}; 
    uint64_t tpkt = 0, tlen = 0;

    for (int i = 0; i < qnum; ++i) {
        uint16_t key = i;
        struct queue_data value;
        }

        double avg = (value.num_pkt != 0) ? value.total_pkt_len / value.num_pkt : 0;
        printf(" %-11d%-11s%-11s%-11s%-11s%-11s%-11s\n",
               key, to_str(avg), to_str(value.size_64B), to_str(value.size_512B),
               to_str(value.size_2K), to_str(value.size_16K), to_str(value.size_64K));

        if (throughput==true) {
            double BPS = value.total_pkt_len / print_interval;
            double PPS = value.num_pkt / print_interval;
            printf("%-11s%-11s", to_str(BPS), to_str(PPS));
        }

        printf("\n");

        tlen += value.total_pkt_len;
        tpkt += value.num_pkt;
        tGroup[0] += value.size_64B;
        tGroup[1] += value.size_512B;
        tGroup[2] += value.size_2K;
        tGroup[3] += value.size_16K;
        tGroup[4] += value.size_64K;
    }

    tBPS = tlen / print_interval;
    tPPS = tpkt / print_interval;
    if (tpkt != 0) {
        tAVG = tlen / tpkt;
    }

    printf(" Total      %-11s%-11s%-11s%-11s%-11s%-11s",
           to_str(tAVG), to_str(tGroup[0]), to_str(tGroup[1]), to_str(tGroup[2]),
           to_str(tGroup[3]), to_str(tGroup[4]));

    if () {
        printf("%-11s%-11s", to_str(tBPS), to_str(tPPS));
    }

    printf("\n");
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
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
