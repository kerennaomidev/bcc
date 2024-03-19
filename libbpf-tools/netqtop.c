#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "netqtop.h"
#include "netqtop.skel.h"
#include "compat.h"
#include "trace_helpers.h"

static struct env {
	bool verbose;
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

