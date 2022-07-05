// +build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "ingress_node_fw.h"

#define bpf_printk(fmt, ...) ({ \
    char ____fmt[] = fmt; \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif

#ifndef likely
#define likely(expr)   __builtin_expect(!!(expr), 1)
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, __u32);   // ruleId
	__type(value, struct ruleStatistics);
} ingress_node_firewall_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_TARGETS);
	__type(key_size, sizeof(struct bpf_lpm_ip_key));
	__type(value_size, sizeof(struct rulesValue) + (sizeof(struct ruleType)*MAX_RULES_PER_TARGET));
	__type(map_flags, BPF_F_NO_PREALLOC);
} ingress_node_firewall_table_map SEC(".maps");

__attribute__((__always_inline__))
static inline void sendEvent(struct xdp_md *ctx, __u16 interface_id, __u16 packet_len, __u8 action, __u16 ruleId) {
    __u64 flags = 0;//BPF_F_CURRENT_CPU;
    __u16 headerSize;
    struct event_hdr hdr;

    hdr.ifId = interface_id;
    hdr.ruleId = ruleId;
    hdr.action = action;
    hdr.fill = 0;
    headerSize = packet_len < MAX_EVENT_DATA ? packet_len : MAX_EVENT_DATA;

    flags |= (__u64)headerSize << 32;

    (void) bpf_perf_event_output(ctx, &eventTbl, flags, &hdr, sizeof(hdr));
}

__attribute__((__always_inline__))
static inline int ingress_node_firewall_main(struct xdp_md *ctx) {
    void * data = (void*)(long)ctx->data;
    void * dataEnd = (void*)(long)ctx->data_end;
    struct ethhdr *eth = data;
    void * ip = data + sizeof(struct ethhdr);

    if (unlikely(ip > dataEnd)) {
        return XDP_DROP;
    }
    __u16 proto = eth->h_proto;
    switch(proto) {
    case bpf_htons(ETH_P_IP):
        break;
    case bpf_htons(ETH_P_IPV6):
        break;
    default:
        return XDP_PASS;
    }
    return XDP_DROP;
}

SEC("xdp_ingress_node_firewall_process")
int ingres_node_firewall_process(struct xdp_md *ctx) {
    return ingress_node_firewall_main(ctx);
}