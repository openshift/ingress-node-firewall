// +build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "ingress_node_fw.h"

#define GET_ACTION(a) (__u8)((a) & 0xFF)
#define SET_ACTION(a) (__u32)(((__u32)a) & 0xFF)
#define GET_RULE_ID(r) (__u16)(((r) >> 8) & 0xFFFFFF)
#define SET_RULE_ID(r) (__u32)((((__u32)(r)) & 0xFFFFFF) << 8)
#define SET_ACTIONRULE_RESPONSE(a,r) (__u32)((((__u32)(r)) & 0xFFFFFF) << 8 | (a) & 0xFF)

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
static inline int ip_extract_l4Info()void *dataStart, void *dataEnd, __u16 *dstPort; __u8 *icmpType, __u8 *icmpCode) {
    struct iphdr *iph = dataStart;
    dataStart += sizeof(struct iphdr);
    if (unlikely(dataStart > dataEnd)) {
        return -1;
    }
    if (likely(IPPROTO_TCP == iph->protocol)) {
       struct tcphdr *tcph = (struct tcphdr *) dataStart;
       dataStart += sizeof(struct tcphdr);
       if (unlikely(dataStart > dataEnd)) {
            return -1;
       }
      *dstPort = tcph->dest;
    } else if (IPPROTO_UDP == iph->protocol) {
        struct udphdr *udph = (struct udphdr *) dataStart;
        dataStart += sizeof(struct udphdr);
        if (unlikely(dataStart > dataEnd)) {
            return -1;
        }
        *dstPort = udph->dest;
    } else if (IPPROTO_ICMP == iph->protocol) {
        struct icmphdr *icmph = (struct icmphdr *) dataStart;
        dataStart += sizeof(struct icmphdr);
        if (unlikely(dataStart > dataEnd)) {
            return -1;
        }
        *icmpType = imcph->type;
        *icmpCode = icmph->code;
    } else if (IPPROTO_ICMPV6 == iph->protocol) {
        struct icmp6hdr *icmp6h = (struct icmp6hdr *) dataStart;
        dataStart += sizeof(struct icmp6hdr);
        if (unlikely(dataStart > dataEnd)) {
            return -1;
        }
        *icmpType = imcp6h->icmp6_type;
        *icmpCode = icmp6h->icmp6_code;
    } else {
        return -1;
    }
    return 0
}

__attribute__((__always_inline__))
static inline __u32 ipv4_checkTuple(void *dataStart, void *dataEnd) {
    struct iphdr *iph = dataStart;
    struct bpf_lpm_ip_key key;
    __u8 *srcAddr = &iph->saddr;
    __u16 dstPort = 0;
    __u8 icmpCode = 0, icmpType = 0;
    int i;

    if (ip_extract_l4Info(dataStart, dataEnd, &dstPort, &icmpType, &icmpCode) < 0 ) {
        return SET_ACTION(UNDEF);
    }

    #pragma clang loop unroll(full)
    for (i = 0 ; i < 4; i++) {
        key.u.ip4_data[i] = srcAddr[i] & 0xFF;
    }

    struct rulesVal *rulesVal = (struct rulesVal *)bpf_map_lookup_elem(&ingress_node_firewall_table_map, &key);

    if (NULL != rulesVal) {
        #pragma clang loop unroll(full)
        for(i = 0; i < MAX_RULES_PER_TARGET; ++i) {
            if (unlikely(i >= rulesVal->numRules)) break;
            const struct ruleType *rule = &rulesVal->rules[i];
            if ((rule->protocol != 0) {
                if ((rule->protocol ==  IPPROTO_TCP) || (rule->protocol == IPPROTO_UDP))) {
                    if ((rule->srcAddrU.ip4_srcAddr == (*srcAddr & rule->srcMaskU.ip4_srcMask)) &&
                        (rule->dstPort == dstPort)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action,rule->ruleId);
                    }
                }
                if (rule->protocol == IPPROTO_ICMP) {
                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action,rule->ruleId);
                    }
                }
            }
        }
    }

    return SET_ACTION(UNDEF);
}

__attribute__((__always_inline__))
static inline __u32 ipv6_checkTuple(void *dataStart, void *dataEnd) {
    struct iphdr *iph = dataStart;
    struct bpf_lpm_ip_key key;
    __u8 *srcAddr = &iph->saddr;
    __u16 dstPort = 0;
    __u8 icmpCode = 0, icmpType = 0;
    int i;

    if (ip_extract_l4Info(dataStart, dataEnd, &dstPort, &icmpType, &icmpCode) < 0 ) {
        return SET_ACTION(UNDEF);
    }

    #pragma clang loop unroll(full)
    for (i = 0 ; i < 16; ++i) {
        key.u.ip6_data[i] = srcAddr[i] & 0xFF;
    }

    struct rulesVal *rulesVal = (struct rulesVal *)bpf_map_lookup_elem(&ingress_node_firewall_table_map, &key);

    if (NULL != rulesVal) {
        #pragma clang loop unroll(full)
        for(i = 0; i < MAX_RULES_PER_TARGET; ++i) {
            if (unlikely(i >= rulesVal->numRules)) break;
            const struct ruleType *rule = &rulesVal->rules[i];
            if ((rule->protocol != 0) {
                if ((rule->protocol ==  IPPROTO_TCP) || (rule->protocol == IPPROTO_UDP))) {
                    if (((rule->srcAddrU.ip6_srcAddr[0] == 0) || (rule->srcAddrU.ip6_srcAddr[0] == (srcAddr & rule->srcMaskU.ip6_srcMask[0]))) &&
                        ((rule->srcAddrU.ip6_srcAddr[1] == 0) || (rule->srcAddrU.ip6_srcAddr[1] == (srcAddr & rule->srcMaskU.ip6_srcMask[1]))) &&
                        ((rule->srcAddrU.ip6_srcAddr[2] == 0) || (rule->srcAddrU.ip6_srcAddr[2] == (srcAddr & rule->srcMaskU.ip6_srcMask[2]))) &&
                        ((rule->srcAddrU.ip6_srcAddr[3] == 0) || (rule->srcAddrU.ip6_srcAddr[3] == (srcAddr & rule->srcMaskU.ip6_srcMask[3]))) &&
                        (rule->dstPort == dstPort)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action,rule->ruleId);
                    }
                }
                if (rule->protocol == IPPROTO_ICMPV6) {
                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action,rule->ruleId);
                    }
                }
            }
        }
    }

    return SET_ACTION(UNDEF);
}

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

    (void) bpf_perf_event_output(ctx, &ingress_node_firewall_stats_map, flags, &hdr, sizeof(hdr));
}

__attribute__((__always_inline__))
static inline int ingress_node_firewall_main(struct xdp_md *ctx) {
    void * data = (void*)(long)ctx->data;
    void * dataEnd = (void*)(long)ctx->data_end;
    struct ethhdr *eth = data;
    void * dataStart = data + sizeof(struct ethhdr);
    __u32 result = UNDEF;

    if (unlikely(dataStart > dataEnd)) {
        return XDP_DROP;
    }

    switch(eth->h_proto) {
    case bpf_htons(ETH_P_IP):
        result = ipv4_checkTuple(dataStart, dataEnd);
        break;
    case bpf_htons(ETH_P_IPV6):
        result = ipv6_checkTuple(dataStart, dataEnd)
        break;
    default:
        return XDP_PASS;
    }

    ruleId = GET_RULE_ID(result);
    action = GET_ACTION(result);

    if (DENY == action) {
        sendEvent(ctx, ifId, (__u16)(dataEnd - data), DENY, ruleId);
        return XDP_DROP;
   }

   sendEvent(ctx, ifId, (__u16)(dataEnd - data), ALLOW, ruleId);
   return XDP_PASS;
}

SEC("xdp_ingress_node_firewall_process")
int ingres_node_firewall_process(struct xdp_md *ctx) {
    return ingress_node_firewall_main(ctx);
}