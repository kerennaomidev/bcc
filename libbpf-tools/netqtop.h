#ifndef __NETQTOP_H
#define __NETQTOP_H

#define IFNAMSIZ	16
#define MAX_QUEUE_NUM 1024

union name_buf{
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    }name_int;
};
struct queue_data{
    u64 total_pkt_len;
    u32 num_pkt;
    u32 size_64B;
    u32 size_512B;
    u32 size_2K;
    u32 size_16K;
    u32 size_64K;
};




#endif
