#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "netqtop.h"
#include "core_fixes.bpf.h"

const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;

struct {
	__uint(type, BPF_ARRAY);
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

SEC("tracepoint/net/net_dev_start_xmit")
int trace_net_dev_start_xmit(struct trace_event_raw_sys_enter *ctx) {
    struct sk_buff *skb = (struct sk_buff*)ctx->args[0];
    if (!name_filter(skb)) {
        return 0;
    }
    u16 qid = skb->queue_mapping;
    struct queue_data *data = tx_q.lookup(&qid);
    if (!data) {
        struct queue_data newdata = {0};  
        bpf_map_update_elem(&txevent, &qid, &newdata, BPF_ANY);
        return 0;
    }

    update_data(data, skb->len);
    bpf_map_update_elem(&txevent, &qid, data, BPF_ANY);

    return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int trace_netif_receive_skb(struct trace_event_raw_sys_enter *ctx) {
    struct sk_buff skb;

    bpf_probe_read(&skb, sizeof(skb), ctx->args[0]);
    
    if (!name_filter(&skb)) {
        return 0;  
    }

    u16 qid = 0;
    if (skb_rx_queue_recorded(&skb)) {
        qid = skb_get_rx_queue(&skb);
    }

    struct queue_data newdata;
    __builtin_memset(&newdata, 0, sizeof(newdata));
    struct queue_data *data = rx_q.lookup_or_try_init(&qid, &newdata);
    if (!data) {
        struct queue_data newdata = {0};  
        bpf_map_update_elem(&txevent, &qid, &newdata, BPF_ANY);
        return 0;  
    }

    update_data(data, skb.len);
    bpf_map_update_elem(&rxevent, &qid, data, BPF_ANY);

    return 0; 
}


//cleanup:
//	bpf_map_delete_elem(&name_map);
//	return 0;
//}

char LICENSE[] SEC("license") = "GPL";
