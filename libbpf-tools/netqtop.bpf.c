#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "netqtop.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct ifname);
} ifname_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_QUEUE_NUM);
	__type(key, u16);
	__type(value, struct queue_data);
} txevent SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_QUEUE_NUM);
	__type(key, u16);
	__type(value, struct queue_data);
} rxevent SEC(".maps");

static __always_inline int cmp_str(const char *src, const char *dst, int sz) {
		int len = 0;
		unsigned char c1, c2;
		for (len = 0; len < sz; len++) {
			c1 = *src++;
			c2 = *dst++;
			if (c1 != c2)
				return c1 < c2 ? -1 : 1;
			if (!c1)
				break;
		}
		return 0;
}

static int ifname_filter(struct sk_buff *skb) {
		int key = 0;
		char *usr_devname;
		char *real_devname;

		usr_devname = bpf_map_lookup_elem(&ifname_map, &key);
		real_devname = BPF_CORE_READ(skb, dev, name);

		if (!real_devname || !usr_devname)
			return 0;

		if (cmp_str(usr_devname, real_devname, IFNAMSIZ) != 0)
			return 0;

		return 1;
}

static void update_data(struct queue_data *data, u64 len) {
		data->total_pkt_len += len;
		data->num_pkt++;

		if (len / 64 == 0) {
			data->size_64B++;
		}
		else if (len / 512 == 0) {
			data->size_512B++;
		}
		else if (len / 2048 == 0) {
			data->size_2K++;
		}
		else if (len / 16384 == 0) {
			data->size_16K++;
		}
		else if (len / 65536 == 0) {	
			data->size_64K++;
		}
	}

SEC("tracepoint/net/net_dev_start_xmit")
int handle_net_dev_start_xmit(struct trace_event_raw_net_dev_start_xmit *ctx) {
		u16 qid;
		u16 skb_len;
		struct queue_data *data;
		struct queue_data zero_data = {0};
		struct sk_buff *skb_addr;

		skb_addr = (struct sk_buff*)BPF_CORE_READ(ctx, skbaddr);

		if (!ifname_filter(skb_addr))
			return 0;

		qid = BPF_CORE_READ(skb_addr, queue_mapping);
		skb_len = BPF_CORE_READ(skb_addr, len);

		data = bpf_map_lookup_elem(&txevent, &qid);
		if (!data)
			bpf_map_update_elem(&txevent, &qid, &zero_data, BPF_NOEXIST);

		data = bpf_map_lookup_elem(&txevent, &qid);
		if (!data || !skb_len)
			return 0;

		update_data(data, skb_len);
		bpf_map_update_elem(&txevent, &qid, data, BPF_ANY);
		return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int handle_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx)
{
		u16 qid;
		u16 skb_len;
		struct queue_data *data;
		struct queue_data zero_data = {0};
		struct sk_buff *skb_addr;

		skb_addr = (struct sk_buff*)BPF_CORE_READ(ctx, skbaddr);

		if (!ifname_filter(skb_addr))
			return 0;

		qid = BPF_CORE_READ(skb_addr, queue_mapping);
		skb_len = BPF_CORE_READ(skb_addr, len);

		data = bpf_map_lookup_elem(&rxevent, &qid);
		if (!data)
			bpf_map_update_elem(&rxevent, &qid, &zero_data, BPF_NOEXIST);

		data = bpf_map_lookup_elem(&rxevent, &qid);

		if (!data || !skb_len)
			return 0;

		update_data(data, skb_len);
		bpf_map_update_elem(&rxevent, &qid, data, BPF_ANY);
		return 0;
}

char LICENSE[] SEC("license") = "GPL";
