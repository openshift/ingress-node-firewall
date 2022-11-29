// +build ignore
#include <inttypes.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sctp.h>

#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "common.h"
#include "ingress_node_firewall.h"

#define MAX_CPUS		256

// FIXME: Hack this structure defined in linux/sctp.h however I am getting incomplete type when I reference it
struct sctphdr {
    __be16 source;
    __be16 dest;
    __be32 vtag;
    __le32 checksum;
};

/*
 * ingress_node_firewall_events_map: is perf event array map type
 * key is the rule id, packet header is captured and used to generate events.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_CPUS);
} ingress_node_firewall_events_map SEC(".maps");

/*
 * ingress_node_firewall_statistics_map: is per cpu array map type
 * key is the rule id
 * user space collects statistics per CPU and aggregate them.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32); // ruleId
    __type(value, struct ruleStatistics_st);
    __uint(max_entries, MAX_TARGETS);
} ingress_node_firewall_statistics_map SEC(".maps");

/*
 * ingress_node_firewall_table_map: is LPM trie map type
 * key is the ingress interface index and the sourceCIDR.
 * lookup returns an array of rules with actions for the XDP program
 * to process.
 * Note: this map is pinned to specific path in bpffs.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_ip_key_st);
    __type(value, struct rulesVal_st);
    __uint(max_entries, MAX_TARGETS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_node_firewall_table_map SEC(".maps");

/*
 * ingress_node_firewall_printk: macro used to generate prog traces for debugging only
 * to enable uncomment the following line
 */
//#define ENABLE_BPF_PRINTK
#ifdef ENABLE_BPF_PRINTK
#define ingress_node_firewall_printk(fmt, args...) bpf_printk(fmt, ##args)
#else
#define ingress_node_firewall_printk(fmt, args...)
#endif

/*
 * ip_extract_l4info(): extracts L4 info for the supported protocols from
 * the incoming packet's headers.
 * Input:
 * struct xdp_md *ctx: pointer to XDP context which contains packet pointer and input interface index.
 * bool is_v4: true for ipv4 and false for ipv6.
 * Output:
 * __u8 *proto: L4 protocol type supported types are TCP/UDP/SCTP/ICMP/ICMPv6.
 * __u16 *dstPort: pointer to L4 destination port for TCP/UDP/SCTP protocols.
 * __u8 *icmpType: pointer to ICMP or ICMPv6's type value.
 * __u8 *icmpCode: pointer to ICMP or ICMPv6's code value.
 * Return:
 * 0 for Success.
 * -1 for Failure.
 */
__attribute__((__always_inline__)) static inline int
ip_extract_l4info(struct xdp_md *ctx, __u8 *proto, __u16 *dstPort,
                  __u8 *icmpType, __u8 *icmpCode, __u8 is_v4) {
    void *data = (void *)(long)ctx->data;
    void *dataEnd = (void *)(long)ctx->data_end;
    void *dataStart = data + sizeof(struct ethhdr);

    if (likely(is_v4)) {
        struct iphdr *iph = dataStart;
        dataStart += sizeof(struct iphdr);
        if (unlikely(dataStart > dataEnd)) {
            return -1;
        }
        *proto = iph->protocol;
    } else {
        struct ipv6hdr *iph = dataStart;
        dataStart += sizeof(struct ipv6hdr);
        if (unlikely(dataStart > dataEnd)) {
            return -1;
        }
        *proto = iph->nexthdr;
    }
    switch (*proto) {
    case IPPROTO_TCP:
        {
            struct tcphdr *tcph = (struct tcphdr *)dataStart;
            dataStart += sizeof(struct tcphdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *dstPort = tcph->dest;
            break;
        }
    case IPPROTO_UDP:
        {
            struct udphdr *udph = (struct udphdr *)dataStart;
            dataStart += sizeof(struct udphdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *dstPort = udph->dest;
            break;
        }
    case IPPROTO_SCTP:
        {
            struct sctphdr *sctph = (struct sctphdr *)dataStart;
            dataStart += sizeof(struct sctphdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *dstPort = sctph->dest;
            break;
        }
    case IPPROTO_ICMP:
        {
            struct icmphdr *icmph = (struct icmphdr *)dataStart;
            dataStart += sizeof(struct icmphdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *icmpType = icmph->type;
            *icmpCode = icmph->code;
            break;
        }
    case IPPROTO_ICMPV6:
        {
            struct icmp6hdr *icmp6h = (struct icmp6hdr *)dataStart;
            dataStart += sizeof(struct icmp6hdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *icmpType = icmp6h->icmp6_type;
            *icmpCode = icmp6h->icmp6_code;
            break;
        }
    default:
        return -1;
    }
    return 0;
}

/*
 * ipv4_firewall_lookup(): matches ipv4 packet with LPM map's key,
 * match L4 headers with the result rules in order and return the action.
 * if there is no match it will return UNDEF action.
 * Input:
 * struct xdp_md *ctx: pointer to XDP context which contains packet pointer and input interface index.
 * __u32 ifID: ingress interface index where the packet is received from.
 * Output:
 * none.
 * Return:
 * __u32 action: returned action is the logical or of the rule id and action field
 * from the matching rule, in case of no match it returns UNDEF.
 */
__attribute__((__always_inline__)) static inline __u32
ipv4_firewall_lookup(struct xdp_md *ctx, __u32 ifId) {
    void *data = (void *)(long)ctx->data;
    struct iphdr *iph = data + sizeof(struct ethhdr);
    struct lpm_ip_key_st key;
    __u32 srcAddr = 0;
    __u16 dstPort = 0;
    __u8 icmpCode = 0, icmpType = 0, proto = 0;
    int i;

    if (unlikely(ip_extract_l4info(ctx, &proto, &dstPort, &icmpType, &icmpCode, 1) < 0)) {
        ingress_node_firewall_printk("failed to extract l4 info");
        return SET_ACTION(UNDEF);
    }

    srcAddr = iph->saddr;

    memset(&key, 0, sizeof(key));
    key.prefixLen = 64; // ipv4 address + ifId
    key.ip_data[0] = srcAddr & 0xFF;
    key.ip_data[1] = (srcAddr >> 8) & 0xFF;
    key.ip_data[2] = (srcAddr >> 16) & 0xFF;
    key.ip_data[3] = (srcAddr >> 24) & 0xFF;
    key.ingress_ifindex = ifId;

    struct rulesVal_st *rulesVal = (struct rulesVal_st *)bpf_map_lookup_elem(
        &ingress_node_firewall_table_map, &key);


    if (likely(NULL != rulesVal)) {
#pragma clang loop unroll(full)
        for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {
            struct ruleType_st *rule = &rulesVal->rules[i];
            if (rule->ruleId == INVALID_RULE_ID) {
                continue;
            }

            if (likely((rule->protocol != 0) && (rule->protocol == proto))) {
                ingress_node_firewall_printk("ruleInfo (protocol %d, Id %d, action %d)", rule->protocol, rule->ruleId, rule->action);
                if ((rule->protocol == IPPROTO_TCP) ||
                    (rule->protocol == IPPROTO_UDP) ||
                    (rule->protocol == IPPROTO_SCTP)) {
                    ingress_node_firewall_printk("TCP/UDP/SCTP packet rule_dstPortStart %d rule_dstPortEnd %d pkt_dstPort %d",
                    rule->dstPortStart, rule->dstPortEnd, bpf_ntohs(dstPort));
                    if (rule->dstPortEnd == 0 ) {
                        if (rule->dstPortStart == bpf_ntohs(dstPort)) {
                            return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                        }
                    } else {
                        if ((bpf_ntohs(dstPort) >= rule->dstPortStart) && (bpf_ntohs(dstPort) < rule->dstPortEnd)) {
                            return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                        }
                    }
                }

                if (rule->protocol == IPPROTO_ICMP) {
                    ingress_node_firewall_printk("ICMP packet rule(type:%d, code:%d) pkt(type:%d, code %d)", rule->icmpType, rule->icmpCode, icmpType, icmpCode);
                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                    }
                }
            }
            // Protocol is not set so just apply the action
            if (rule->protocol == 0) {
                return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
            }
        }
        ingress_node_firewall_printk("Packet didn't match any rule proto %d port %d", proto, bpf_ntohs(dstPort));
    }
    return SET_ACTION(UNDEF);
}

/*
 * ipv6_firewall_lookup(): matches ipv6 packet with LPM map's key,
 * match L4 headers with the result rules in order and return the action.
 * if there is no rule match it will return UNDEF action.
 * Input:
 * struct xdp_md *ctx: pointer to XDP context which contains packet pointer and input interface index.
 * __u32 ifID: ingress interface index where the packet is received from.
 * Output:
 * none.
 * Return:
 __u32 action: returned action is the logical or of the rule id and action field
 * from the matching rule, in case of no match it returns UNDEF.
 */
__attribute__((__always_inline__)) static inline __u32
ipv6_firewall_lookup(struct xdp_md *ctx, __u32 ifId) {
    void *data = (void *)(long)ctx->data;
    struct ipv6hdr *iph = data + sizeof(struct ethhdr);
    struct lpm_ip_key_st key;
    __u8 *srcAddr = NULL;
    __u16 dstPort = 0;
    __u8 icmpCode = 0, icmpType = 0, proto = 0;
    int i;

    if (unlikely(ip_extract_l4info(ctx, &proto, &dstPort, &icmpType, &icmpCode, 0) < 0)) {
        ingress_node_firewall_printk("failed to extract l4 info");
        return SET_ACTION(UNDEF);
    }
    srcAddr = iph->saddr.in6_u.u6_addr8;
    memset(&key, 0, sizeof(key));
    key.prefixLen = 160; // ipv6 address _ ifId
    memcpy(key.ip_data, srcAddr, 16);
    key.ingress_ifindex = ifId;

    struct rulesVal_st *rulesVal = (struct rulesVal_st *)bpf_map_lookup_elem(
        &ingress_node_firewall_table_map, &key);

    if (NULL != rulesVal) {
#pragma clang loop unroll(full)
        for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {
            struct ruleType_st *rule = &rulesVal->rules[i];
            if (rule->ruleId == INVALID_RULE_ID) {
                continue;
            }
            if (likely((rule->protocol != 0) && (rule->protocol == proto))) {
                ingress_node_firewall_printk("ruleInfo (protocol %d, Id %d, action %d)", rule->protocol, rule->ruleId, rule->action);
                if ((rule->protocol == IPPROTO_TCP) ||
                    (rule->protocol == IPPROTO_UDP) ||
                    (rule->protocol == IPPROTO_SCTP)) {
                    ingress_node_firewall_printk("TCP/UDP/SCTP packet rule_dstPortStart %d rule_dstPortEnd %d pkt_dstPort %d",
                        rule->dstPortStart, rule->dstPortEnd, bpf_ntohs(dstPort));
                    if (rule->dstPortEnd == 0) {
                        if (rule->dstPortStart == bpf_ntohs(dstPort)) {
                            return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                        }
                    } else {
                        if ((bpf_ntohs(dstPort) >= rule->dstPortStart) && (bpf_ntohs(dstPort) < rule->dstPortEnd)) {
                            return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                        }
                    }
                }

                if (rule->protocol == IPPROTO_ICMPV6) {
                    ingress_node_firewall_printk("ICMPV6 packet rule(type:%d, code:%d) pkt(type:%d, code %d)", rule->icmpType, rule->icmpCode, icmpType, icmpCode);
                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                    }
                }
            }
            // Protocol is not set so just apply the action
            if (rule->protocol == 0) {
                return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
            }
        }
        ingress_node_firewall_printk("Packet didn't match any rule proto %d port %d", proto, bpf_ntohs(dstPort));
    }
    return SET_ACTION(UNDEF);
}

/*
 * generate_event_and_update_statistics() : it will generate eBPF event including the packet header
 * and update statistics for the specificed rule id.
 * Input:
 * struct xdp_md *ctx: pointer to XDP context including input interface and packet pointer.
 * __u64 packet_len: packet length in bytes including layer2 header.
 * __u8 action: valid actions ALLOW/DENY/UNDEF.
 * __u16 ruleId: ruled id where the packet matches against (in case of match of course).
 * __u8 generateEvent: need to generate event for this packet or not.
 * __u32 ifID: input interface index where the packet is arrived from.
 * Output:
 * none.
 * Return:
 * none.
 */
__attribute__((__always_inline__)) static inline void
generate_event_and_update_statistics(struct xdp_md *ctx, __u64 packet_len, __u8 action, __u16 ruleId, __u8 generateEvent, __u32 ifId) {
    struct ruleStatistics_st *statistics, initialStats;
    struct event_hdr_st hdr;
    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 headerSize;
    __u32 key = ruleId;

    memset(&hdr, 0, sizeof(hdr));
    hdr.ruleId = ruleId;
    hdr.action = action;
    hdr.pktLength = (__u16)packet_len;
    hdr.ifId = (__u16)ifId;

    memset(&initialStats, 0, sizeof(initialStats));
    statistics = bpf_map_lookup_elem(&ingress_node_firewall_statistics_map, &key);
    if (likely(statistics)) {
        switch (action) {
        case ALLOW:
            __sync_fetch_and_add(&statistics->allow_stats.packets, 1);
            __sync_fetch_and_add(&statistics->allow_stats.bytes, packet_len);
            break;
        case DENY:
            __sync_fetch_and_add(&statistics->deny_stats.packets, 1);
            __sync_fetch_and_add(&statistics->deny_stats.bytes, packet_len);
            break;
        }
    } else {
        bpf_map_update_elem(&ingress_node_firewall_statistics_map, &key, &initialStats, BPF_ANY);
    }

    if (generateEvent) {
        headerSize = packet_len < MAX_EVENT_DATA ? packet_len : MAX_EVENT_DATA;
        // enable the following flag to dump packet header
        flags |= (__u64)headerSize << 32;

        (void)bpf_perf_event_output(ctx, &ingress_node_firewall_events_map, flags,
                                    &hdr, sizeof(hdr));
    }
}

/*
 * ingress_node_firewall_main(): is the entry point for the XDP program to do
 * ingress node firewall.
 * Input:
 * struct xdp_md *ctx: pointer to XDP context which contains packet pointer and input interface index.
 * Output:
 * none.
 * Return:
 * int XDP action: valid values XDP_DROP and XDP_PASS.
 */
__attribute__((__always_inline__)) static inline int
ingress_node_firewall_main(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *dataEnd = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    void *dataStart = data + sizeof(struct ethhdr);
    __u32 result = UNDEF;
    __u32 ifId = ctx->ingress_ifindex;

    ingress_node_firewall_printk("Ingress node firewall start processing a packet on %d", ifId);

    if (unlikely(dataStart > dataEnd)) {
        ingress_node_firewall_printk("Ingress node firewall bad packet XDP_DROP");
        return XDP_DROP;
    }
    switch (eth->h_proto) {
    case bpf_htons(ETH_P_IP):
        ingress_node_firewall_printk("Ingress node firewall process IPv4 packet");
        result = ipv4_firewall_lookup(ctx, ifId);
        break;
    case bpf_htons(ETH_P_IPV6):
        ingress_node_firewall_printk("Ingress node firewall process IPv6 packet");
        result = ipv6_firewall_lookup(ctx, ifId);
        break;
    default:
        ingress_node_firewall_printk("Ingress node firewall unknown L3 protocol XDP_PASS");
        return XDP_PASS;
    }

    __u16 ruleId = GET_RULE_ID(result);
    __u8 action = GET_ACTION(result);

    switch (action) {
    case DENY:
        generate_event_and_update_statistics(ctx, bpf_xdp_get_buff_len(ctx), DENY, ruleId, 1, ifId);
        ingress_node_firewall_printk("Ingress node firewall action DENY -> XDP_DROP");
        return XDP_DROP;
    case ALLOW:
        generate_event_and_update_statistics(ctx, bpf_xdp_get_buff_len(ctx), ALLOW, ruleId, 0, ifId);
        ingress_node_firewall_printk("Ingress node firewall action ALLOW -> XDP_PASS");
        return XDP_PASS;
    default:
        ingress_node_firewall_printk("Ingress node firewall action UNDEF");
        return XDP_PASS;
    }
}

SEC("xdp.frags")
int ingress_node_firewall_process(struct xdp_md *ctx) {
    return ingress_node_firewall_main(ctx);
}

char __license[] SEC("license") = "Dual BSD/GPL";
