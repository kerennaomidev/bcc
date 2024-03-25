#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "netqtop.h"
#include <bpf/bpf_helpers.h>

// Define BPF map types
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, union name_buf);
} name_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u16);
    __type(value, struct queue_data);
} txevent SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u16);
    __type(value, struct queue_data);
} rxevent SEC(".maps");

static inline int name_filter(const char *dev_name) {
    union name_buf real_devname;
    bpf_probe_read_kernel(&real_devname, sizeof(real_devname), dev_name);

    int key = 0;
    union name_buf *leaf = bpf_map_lookup_elem(&name_map, &key);
    if (!leaf) {
        return 0;
    }
    if ((leaf->name_int).hi != real_devname.name_int.hi || (leaf->name_int).lo != real_devname.name_int.lo) {
        return 0;
    }

    return 1;
}

static void update_data(struct queue_data *data, u64 len) {
    data->total_pkt_len += len;
    data->num_pkt++;

    if (len < 64) {
        data->size_64B++;
    } else if (len < 512) {
        data->size_512B++;
    } else if (len < 2048) {
        data->size_2K++;
    } else if (len < 16384) {
        data->size_16K++;
    } else {
        data->size_64K++;
    }
}

SEC("tracepoint/net/net_dev_start_xmit")
int trace_net_dev_start_xmit(struct trace_event_raw_sys_enter *ctx) {
    struct sk_buff skb;
    bpf_probe_read_kernel(&skb, sizeof(skb), (void *)ctx->args[0]);

    if (!name_filter(skb.dev->name)) {
        return 0;
    }

    u16 qid = skb.queue_mapping;
    struct queue_data *data = bpf_map_lookup_elem(&txevent, &qid);
    if (!data) {
        struct queue_data newdata = {0};
        bpf_map_update_elem(&txevent, &qid, &newdata, BPF_NOEXIST);
        return 0;
    }

    update_data(data, skb.len);
    bpf_map_update_elem(&txevent, &qid, data, 0);

    return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int trace_netif_receive_skb(struct trace_event_raw_sys_enter *ctx) {
    struct sk_buff skb;
    bpf_probe_read_kernel(&skb, sizeof(skb), (void *)ctx->args[0]);

    if (!name_filter(skb.dev->name)) {
        return 0;
    }

    u16 qid = 0;
    // Since bpf_skb_rx_queue_recorded and bpf_skb_get_rx_queue are not available,
    // we'll omit the queue-related functionality here.

    struct queue_data *data = bpf_map_lookup_elem(&rxevent, &qid);
    if (!data) {
        struct queue_data newdata = {0};
        bpf_map_update_elem(&rxevent, &qid, &newdata, BPF_NOEXIST);
        return 0;
    }

    update_data(data, skb.len);
    bpf_map_update_elem(&rxevent, &qid, data, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

