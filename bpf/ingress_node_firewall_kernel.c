// +build ignore
#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "common.h"
#include "ingress_node_firewall.h"
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

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} ingress_node_firewall_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct bpf_lpm_ip_key_st);
    __type(value, struct rulesVal_st);
    __uint(max_entries, MAX_TARGETS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_node_firewall_table_map SEC(".maps");

__attribute__((__always_inline__)) static inline int
ip_extract_l4Info(void *dataStart, void *dataEnd, __u16 *dstPort,
                  __u8 *icmpType, __u8 *icmpCode) {
    struct iphdr *iph = dataStart;
    dataStart += sizeof(struct iphdr);
    if (unlikely(dataStart > dataEnd)) {
        return -1;
    }

    if (likely(IPPROTO_TCP == iph->protocol)) {
        struct tcphdr *tcph = (struct tcphdr *)dataStart;
        dataStart += sizeof(struct tcphdr);
        if (unlikely(dataStart > dataEnd)) {
            return -1;
        }
        *dstPort = tcph->dest;
		bpf_printk("Process TCP protocol dstPort %2x", *dstPort);
    } else if (IPPROTO_UDP == iph->protocol) {
        struct udphdr *udph = (struct udphdr *)dataStart;
        dataStart += sizeof(struct udphdr);
        if (unlikely(dataStart > dataEnd)) {
            return -1;
        }
        *dstPort = udph->dest;
    } else if (IPPROTO_ICMP == iph->protocol) {
        struct icmphdr *icmph = (struct icmphdr *)dataStart;
        dataStart += sizeof(struct icmphdr);
        if (unlikely(dataStart > dataEnd)) {
            return -1;
        }
        *icmpType = icmph->type;
        *icmpCode = icmph->code;
    } else if (IPPROTO_ICMPV6 == iph->protocol) {
        struct icmp6hdr *icmp6h = (struct icmp6hdr *)dataStart;
        dataStart += sizeof(struct icmp6hdr);
        if (unlikely(dataStart > dataEnd)) {
            return -1;
        }
        *icmpType = icmp6h->icmp6_type;
        *icmpCode = icmp6h->icmp6_code;
    } else {
        return -1;
    }

    return 0;
}

__attribute__((__always_inline__)) static inline __u32
ipv4_checkTuple(void *dataStart, void *dataEnd) {
    struct iphdr *iph = dataStart;
    struct bpf_lpm_ip_key_st key;
    __u32 srcAddr = iph->saddr;
    __u16 dstPort = 0;
    __u8 icmpCode = 0, icmpType = 0;
    int i;

    if (ip_extract_l4Info(dataStart, dataEnd, &dstPort, &icmpType, &icmpCode) <
      0) {
		bpf_printk("failed to extract l4 info");
        return SET_ACTION(UNDEF);
    }
    memset(&key, 0, sizeof(key));
    key.prefixLen = 32;
    key.ip_data[0] = srcAddr & 0xFF;
    key.ip_data[1] = (srcAddr >> 8) & 0xFF;
    key.ip_data[2] = (srcAddr >> 16) & 0xFF;
    key.ip_data[3] = (srcAddr >> 24) & 0xFF;

    struct rulesVal_st *rulesVal = (struct rulesVal_st *)bpf_map_lookup_elem(
        &ingress_node_firewall_table_map, &key);


    if (likely(NULL != rulesVal)) {
		bpf_printk("Hit bpf lpm match lookup");
#pragma clang loop unroll(full)
        for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {
            if (unlikely(i >= rulesVal->numRules))
                break;
            struct ruleType_st *rule = &rulesVal->rules[i];
			bpf_printk("ruleInfo (protocol %d, Id %d, action %d)", rule->protocol, rule->ruleId, rule->action);
            if (rule->protocol != 0) {
                if ((rule->protocol == IPPROTO_TCP) ||
                    (rule->protocol == IPPROTO_UDP)) {
					bpf_printk("TCP/UDP packet rule_dstPort %2x pkt_dstPort %2x", rule->dstPort, dstPort);
                    if (rule->dstPort == bpf_ntohs(dstPort)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
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
    }

    return SET_ACTION(UNDEF);
}

__attribute__((__always_inline__)) static inline __u32
ipv6_checkTuple(void *dataStart, void *dataEnd) {
    struct iphdr *iph = dataStart;
    struct bpf_lpm_ip_key_st key;
    __u32 *srcAddr = &iph->saddr;
    __u16 dstPort = 0;
    __u8 icmpCode = 0, icmpType = 0;
    int i;

    if (ip_extract_l4Info(dataStart, dataEnd, &dstPort, &icmpType, &icmpCode) <
      0) {
        return SET_ACTION(UNDEF);
    }
    memset(&key, 0, sizeof(key));
    key.prefixLen = 128;
#pragma clang loop unroll(full)
    for (i = 0; i < 16; ++i) {
        key.ip_data[i] = (srcAddr[i / 4] >> ((i % 4) * 8)) & 0xFF;
    }

    struct rulesVal_st *rulesVal = (struct rulesVal_st *)bpf_map_lookup_elem(
        &ingress_node_firewall_table_map, &key);

    if (NULL != rulesVal) {
#pragma clang loop unroll(full)
        for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {
            if (unlikely(i >= rulesVal->numRules))
                break;

            struct ruleType_st *rule = &rulesVal->rules[i];
            if (rule->protocol != 0) {
                if ((rule->protocol == IPPROTO_TCP) ||
                    (rule->protocol == IPPROTO_UDP)) {
                    if (rule->dstPort == bpf_ntohs(dstPort)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                    }
                }

                if (rule->protocol == IPPROTO_ICMPV6) {
                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                    }
                }
            }
        }
    }

    return SET_ACTION(UNDEF);
}

__attribute__((__always_inline__)) static inline void
sendEvent(struct xdp_md *ctx, __u16 packet_len, __u8 action, __u16 ruleId) {
	__u64 flags = 0; // BPF_F_CURRENT_CPU;
    __u16 headerSize;
    struct event_hdr_st hdr;

	memset(&hdr, 0, sizeof(hdr));
    hdr.ruleId = ruleId;
    hdr.action = action;
    hdr.fill = 0;
    headerSize = packet_len < MAX_EVENT_DATA ? packet_len : MAX_EVENT_DATA;

    flags |= (__u64)headerSize << 32;

    (void)bpf_perf_event_output(ctx, &ingress_node_firewall_stats_map, flags,
                                &hdr, sizeof(hdr));
}

__attribute__((__always_inline__)) static inline int
ingress_node_firewall_main(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *dataEnd = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    void *dataStart = data + sizeof(struct ethhdr);
    __u32 result = UNDEF;

	bpf_printk("Ingress node firewall start processing a packet");
    if (unlikely(dataStart > dataEnd)) {
		bpf_printk("Ingress node firewall bad packet XDP_DROP");
        return XDP_DROP;
    }

    switch (eth->h_proto) {
    case bpf_htons(ETH_P_IP):
		bpf_printk("Ingress node firewall process IPv4 packet");
        result = ipv4_checkTuple(dataStart, dataEnd);
        break;
    case bpf_htons(ETH_P_IPV6):
		bpf_printk("Ingress node firewall process IPv6 packet");
        result = ipv6_checkTuple(dataStart, dataEnd);
        break;
    default:
		bpf_printk("Ingress node firewall unknown L3 protocol XDP_PASS");
        return XDP_PASS;
    }

    __u16 ruleId = GET_RULE_ID(result);
    __u8 action = GET_ACTION(result);

    if (DENY == action) {
        sendEvent(ctx, (__u16)(dataEnd - data), DENY, ruleId);
		bpf_printk("Ingress node firewall action XDP_DROP");
        return XDP_DROP;
    }

    sendEvent(ctx, (__u16)(dataEnd - data), ALLOW, ruleId);
	bpf_printk("Ingress node firewall action XDP_PASS");
    return XDP_PASS;
}

SEC("xdp_ingress_node_firewall_process")
int ingres_node_firewall_process(struct xdp_md *ctx) {
    return ingress_node_firewall_main(ctx);
}

char __license[] SEC("license") = "Dual BSD/GPL";
