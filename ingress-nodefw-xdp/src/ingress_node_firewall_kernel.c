// +build ignore
#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "common.h"
#include "ingress_node_fw.h"
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

#define GET_ACTION(a) (__u8)((a)&0xFF)
#define SET_ACTION(a) (__u32)(((__u32)a) & 0xFF)
#define GET_RULE_ID(r) (__u16)(((r) >> 8) & 0xFFFFFF)
#define SET_RULE_ID(r) (__u32)((((__u32)(r)) & 0xFFFFFF) << 8)
#define SET_ACTIONRULE_RESPONSE(a, r)                                          \
  (__u32)((((__u32)(r)) & 0xFFFFFF) << 8 | (a)&0xFF)

#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif

#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif

struct bpf_map_def SEC("maps") ingress_node_firewall_stats_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1 << 24,
};

struct bpf_map_def SEC("maps") ingress_node_firewall_table_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct bpf_lpm_ip_key),
    .value_size = sizeof(struct rulesVal) +
                  (sizeof(struct ruleType) * MAX_RULES_PER_TARGET),
    .max_entries = MAX_TARGETS,
    .map_flags = BPF_F_NO_PREALLOC,
};

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

__attribute__((__always_inline__)) static inline int
dstPort_match(__u16 *dstPorts, __u16 dstPort) {
#pragma clang loop unroll(full)
  for (int i = 0; i < MAX_DST_PORTS; ++i) {
    if (dstPorts[i] == dstPort) {
      return 0;
    }
  }
  return -1;
}

__attribute__((__always_inline__)) static inline __u32
ipv4_checkTuple(void *dataStart, void *dataEnd) {
  struct iphdr *iph = dataStart;
  struct bpf_lpm_ip_key key;
  __u32 *srcAddr = &iph->saddr;
  __u16 dstPort = 0;
  __u8 icmpCode = 0, icmpType = 0;
  int i;

  if (ip_extract_l4Info(dataStart, dataEnd, &dstPort, &icmpType, &icmpCode) <
      0) {
    return SET_ACTION(UNDEF);
  }

#pragma clang loop unroll(full)
  for (i = 0; i < 4; i++) {
    key.u.ip4_data[i] = (*srcAddr >> (i * 4)) & 0xFF;
  }

  struct rulesVal *rulesVal = (struct rulesVal *)bpf_map_lookup_elem(
      &ingress_node_firewall_table_map, &key);

  if (NULL != rulesVal) {
#pragma clang loop unroll(full)
    for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {
      if (unlikely(i >= rulesVal->numRules))
        break;
      const struct ruleType *rule = &rulesVal->rules[i];
      if (rule->protocol != 0) {
        if ((rule->protocol == IPPROTO_TCP) ||
            (rule->protocol == IPPROTO_UDP)) {
          if ((rule->srcAddrU.ip4_srcAddr ==
               (*srcAddr & rule->srcMaskU.ip4_srcMask)) &&
              dstPort_match((__u16 *)rule->dstPorts, dstPort)) {
            return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
          }
        }

        if (rule->protocol == IPPROTO_ICMP) {
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
  struct bpf_lpm_ip_key key;
  __u32 *srcAddr = &iph->saddr;
  __u16 dstPort = 0;
  __u8 icmpCode = 0, icmpType = 0;
  int i;

  if (ip_extract_l4Info(dataStart, dataEnd, &dstPort, &icmpType, &icmpCode) <
      0) {
    return SET_ACTION(UNDEF);
  }

#pragma clang loop unroll(full)
  for (i = 0; i < 16; ++i) {
    key.u.ip6_data[i] = (srcAddr[i / 4] >> ((i % 4) * 4)) & 0xFF;
  }

  struct rulesVal *rulesVal = (struct rulesVal *)bpf_map_lookup_elem(
      &ingress_node_firewall_table_map, &key);

  if (NULL != rulesVal) {
#pragma clang loop unroll(full)
    for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {
      if (unlikely(i >= rulesVal->numRules))
        break;

      const struct ruleType *rule = &rulesVal->rules[i];
      if (rule->protocol != 0) {
        if ((rule->protocol == IPPROTO_TCP) ||
            (rule->protocol == IPPROTO_UDP)) {
          if (((rule->srcAddrU.ip6_srcAddr[0] == 0) ||
               (rule->srcAddrU.ip6_srcAddr[0] ==
                (srcAddr[0] & rule->srcMaskU.ip6_srcMask[0]))) &&
              ((rule->srcAddrU.ip6_srcAddr[1] == 0) ||
               (rule->srcAddrU.ip6_srcAddr[1] ==
                (srcAddr[1] & rule->srcMaskU.ip6_srcMask[1]))) &&
              ((rule->srcAddrU.ip6_srcAddr[2] == 0) ||
               (rule->srcAddrU.ip6_srcAddr[2] ==
                (srcAddr[2] & rule->srcMaskU.ip6_srcMask[2]))) &&
              ((rule->srcAddrU.ip6_srcAddr[3] == 0) ||
               (rule->srcAddrU.ip6_srcAddr[3] ==
                (srcAddr[3] & rule->srcMaskU.ip6_srcMask[3]))) &&
              dstPort_match((__u16 *)rule->dstPorts, dstPort)) {
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
  struct event_hdr hdr;

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

  if (unlikely(dataStart > dataEnd)) {
    return XDP_DROP;
  }

  switch (eth->h_proto) {
  case bpf_htons(ETH_P_IP):
    result = ipv4_checkTuple(dataStart, dataEnd);
    break;
  case bpf_htons(ETH_P_IPV6):
    result = ipv6_checkTuple(dataStart, dataEnd);
    break;
  default:
    return XDP_PASS;
  }

  __u16 ruleId = GET_RULE_ID(result);
  __u8 action = GET_ACTION(result);

  if (DENY == action) {
    sendEvent(ctx, (__u16)(dataEnd - data), DENY, ruleId);
    return XDP_DROP;
  }

  sendEvent(ctx, (__u16)(dataEnd - data), ALLOW, ruleId);
  return XDP_PASS;
}

SEC("xdp_ingress_node_firewall_process")
int ingres_node_firewall_process(struct xdp_md *ctx) {
  return ingress_node_firewall_main(ctx);
}

char __license[] SEC("license") = "Dual BSD/GPL";
