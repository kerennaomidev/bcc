#ifndef __NETQTOP_H
#define __NETQTOP_H

#define STAT_STR_SZ	10
#define IFNAMSIZ	16
#define MAX_QUEUE_NUM 1024

struct ifname {
	char if_name[IFNAMSIZ];
};

struct queue_data {
	__u64 total_pkt_len;
	__u32 num_pkt;
	__u32 size_64B;
	__u32 size_512B;
	__u32 size_2K;
	__u32 size_16K;
	__u32 size_64K;
};

struct queue_stats_str {
	char avg_str[STAT_STR_SZ];
	char size_64B_str[STAT_STR_SZ];
	char size_512B_str[STAT_STR_SZ];
	char size_2K_str[STAT_STR_SZ];
	char size_16K_str[STAT_STR_SZ];
	char size_64K_str[STAT_STR_SZ];
	char size_bps_str[STAT_STR_SZ];
	char size_pps_str[STAT_STR_SZ];

};
#endif
