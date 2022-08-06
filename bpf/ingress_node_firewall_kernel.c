// +build ignore
#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "common.h"
#include "ingress_node_firewall.h"
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

#define MAX_CPUS		256

// FIXME: Hack this structure defined in linux/sctp.h however I am getting incomplete type when I reference it
struct sctphdr {
	__be16 source;
	__be16 dest;
	__be32 vtag;
	__le32 checksum;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_CPUS);
} ingress_node_firewall_events_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32); // ruleId
    __type(value, struct ruleStatistics_st);
    __uint(max_entries, MAX_TARGETS);
} ingress_node_firewall_statistics_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_ip_key_st);
    __type(value, struct rulesVal_st);
    __uint(max_entries, MAX_TARGETS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_node_firewall_table_map SEC(".maps");

__attribute__((__always_inline__)) static inline int
ip_extract_l4Info(void *dataStart, void *dataEnd, __u8 *proto, __u16 *dstPort,
                  __u8 *icmpType, __u8 *icmpCode, __u8 is_v4) {

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

__attribute__((__always_inline__)) static inline __u32
ipv4_checkTuple(void *dataStart, void *dataEnd, __u32 ifId) {
    struct iphdr *iph = dataStart;
    struct lpm_ip_key_st key;
    __u32 srcAddr = iph->saddr;
    __u16 dstPort = 0;
    __u8 icmpCode = 0, icmpType = 0, proto = 0;
    int i;

    if (ip_extract_l4Info(dataStart, dataEnd, &proto, &dstPort, &icmpType, &icmpCode, 1) < 0) {
		bpf_printk("failed to extract l4 info");
        return SET_ACTION(UNDEF);
    }
    memset(&key, 0, sizeof(key));
    key.prefixLen = 32;
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
            if (likely((rule->protocol != 0) && (rule->protocol == proto))) {
				bpf_printk("ruleInfo (protocol %d, Id %d, action %d)", rule->protocol, rule->ruleId, rule->action);
                if ((rule->protocol == IPPROTO_TCP) ||
                    (rule->protocol == IPPROTO_UDP) ||
                    (rule->protocol == IPPROTO_SCTP)) {
                    bpf_printk("TCP/UDP/SCTP packet rule_dstPortStart %d rule_dstPortEnd %d pkt_dstPort %d",
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
					bpf_printk("ICMP packet rule(type:%d, code:%d) pkt(type:%d, code %d)", rule->icmpType, rule->icmpCode, icmpType, icmpCode);
                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                    }
                }
            }
        }
		bpf_printk("Packet didn't match any rule proto %d port %d", proto, bpf_ntohs(dstPort));
        // we matched CIDR but we have no rules matching so drop
        return SET_ACTIONRULE_RESPONSE(DENY, 0);
    }
    return SET_ACTION(UNDEF);
}

__attribute__((__always_inline__)) static inline __u32
ipv6_checkTuple(void *dataStart, void *dataEnd, __u32 ifId) {
    struct ipv6hdr *iph = dataStart;
    struct lpm_ip_key_st key;
    __u8 *srcAddr = iph->saddr.in6_u.u6_addr8;
    __u16 dstPort = 0;
    __u8 icmpCode = 0, icmpType = 0, proto = 0;
    int i;

    if (ip_extract_l4Info(dataStart, dataEnd, &proto, &dstPort, &icmpType, &icmpCode, 0) < 0) {
        return SET_ACTION(UNDEF);
    }
    memset(&key, 0, sizeof(key));
    key.prefixLen = 128;
    memcpy(key.ip_data, srcAddr, 16);
    key.ingress_ifindex = ifId;

    struct rulesVal_st *rulesVal = (struct rulesVal_st *)bpf_map_lookup_elem(
        &ingress_node_firewall_table_map, &key);

    if (NULL != rulesVal) {
#pragma clang loop unroll(full)
        for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {
            struct ruleType_st *rule = &rulesVal->rules[i];
            if (likely((rule->protocol != 0) && (rule->protocol == proto))) {
				bpf_printk("ruleInfo (protocol %d, Id %d, action %d)", rule->protocol, rule->ruleId, rule->action);
                if ((rule->protocol == IPPROTO_TCP) ||
                    (rule->protocol == IPPROTO_UDP) ||
                    (rule->protocol == IPPROTO_SCTP)) {
                    bpf_printk("TCP/UDP/SCTP packet rule_dstPortStart %d rule_dstPortEnd %d pkt_dstPort %d",
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
                	bpf_printk("ICMPV6 packet rule(type:%d, code:%d) pkt(type:%d, code %d)", rule->icmpType, rule->icmpCode, icmpType, icmpCode);
                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                    }
                }
            }
        }
		bpf_printk("Packet didn't match any rule proto %d port %d", proto, bpf_ntohs(dstPort));
        // we matched CIDR but we have no rules matching so drop
        return SET_ACTIONRULE_RESPONSE(DENY, 0);
    }
    return SET_ACTION(UNDEF);
}

__attribute__((__always_inline__)) static inline void
sendEvent(struct xdp_md *ctx, __u16 packet_len, __u8 action, __u16 ruleId, __u8 generateEvent, __u32 ifId) {
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

__attribute__((__always_inline__)) static inline int
ingress_node_firewall_main(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *dataEnd = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    void *dataStart = data + sizeof(struct ethhdr);
    __u32 result = UNDEF;
    __u32 ifId = ctx->ingress_ifindex;

    bpf_printk("Ingress node firewall start processing a packet on %d", ifId);
    if (unlikely(dataStart > dataEnd)) {
		bpf_printk("Ingress node firewall bad packet XDP_DROP");
        return XDP_DROP;
    }

    switch (eth->h_proto) {
    case bpf_htons(ETH_P_IP):
        bpf_printk("Ingress node firewall process IPv4 packet");
        result = ipv4_checkTuple(dataStart, dataEnd, ifId);
        break;
    case bpf_htons(ETH_P_IPV6):
        bpf_printk("Ingress node firewall process IPv6 packet");
        result = ipv6_checkTuple(dataStart, dataEnd, ifId);
        break;
    default:
        bpf_printk("Ingress node firewall unknown L3 protocol XDP_PASS");
        return XDP_PASS;
    }

    __u16 ruleId = GET_RULE_ID(result);
    __u8 action = GET_ACTION(result);

	switch (action) {
    case DENY:
        sendEvent(ctx, (__u16)(dataEnd - data), DENY, ruleId, 1, ifId);
        bpf_printk("Ingress node firewall action DENY -> XDP_DROP");
        return XDP_DROP;
    case ALLOW:
        sendEvent(ctx, (__u16)(dataEnd - data), ALLOW, ruleId, 0, ifId);
        bpf_printk("Ingress node firewall action ALLOW -> XDP_PASS");
        return XDP_PASS;
    default:
        bpf_printk("Ingress node firewall action UNDEF");
        return XDP_PASS;
    }
}

SEC("xdp_ingress_node_firewall_process")
int ingress_node_firewall_process(struct xdp_md *ctx) {
    return ingress_node_firewall_main(ctx);
}

char __license[] SEC("license") = "Dual BSD/GPL";
