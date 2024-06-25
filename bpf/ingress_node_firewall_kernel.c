// +build ignore

// clang-format off
#include <vmlinux.h>
// clang-format on
#include "bpf_tracing.h"
#include "ingress_node_firewall.h"

#define MAX_CPUS 256

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) &&             \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) &&              \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_ntohs(x) (x)
#define bpf_htons(x) (x)
#else
#error "Endianness detection needs to be set up for your compiler?!"
#endif

/*
 * ingress_node_firewall_events_map: is perf event array map type
 * key is the rule id, packet header is captured and used to generate events.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_CPUS);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
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
  __uint(pinning, LIBBPF_PIN_BY_NAME);
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

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct lpm_ip_key_st);
  __type(value, struct lpm_ip_key_st);
  __uint(max_entries, 16384);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_node_firewall_dbg_map SEC(".maps");

/*
 * ingress_node_firewall_printk: macro used to generate prog traces for
 * debugging only to enable uncomment the following line
 */
// #define ENABLE_BPF_PRINTK
#ifdef ENABLE_BPF_PRINTK
#define ingress_node_firewall_printk(fmt, args...) bpf_printk(fmt, ##args)
#else
#define ingress_node_firewall_printk(fmt, args...)
#endif

// Global used to enable lookup debug hashmap
static volatile const __u32 debug_lookup = 0;

/*
 * ip_extract_l4info(): extracts L4 info for the supported protocols from
 * the incoming packet's headers.
 * Input:
 * void *data: pointer to the packet data.
 * void *data_end: pointer to the end of the packet data.
 * bool is_v4: true for ipv4 and false for ipv6.
 * Output:
 * __u16 *dstPort: pointer to L4 destination port for TCP/UDP/SCTP protocols.
 * __u8 *icmpType: pointer to ICMP or ICMPv6's type value.
 * __u8 *icmpCode: pointer to ICMP or ICMPv6's code value.
 * Return:
 * 0 for Success.
 * -1 for Failure.
 */
__attribute__((__always_inline__)) static inline int
ip_extract_l4info(void *data, void *dataEnd, __u8 *proto, __u16 *dstPort,
                  __u8 *icmpType, __u8 *icmpCode, __u8 is_v4) {
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
  case IPPROTO_TCP: {
    struct tcphdr *tcph = (struct tcphdr *)dataStart;
    dataStart += sizeof(struct tcphdr);
    if (unlikely(dataStart > dataEnd)) {
      return -1;
    }
    *dstPort = tcph->dest;
    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udph = (struct udphdr *)dataStart;
    dataStart += sizeof(struct udphdr);
    if (unlikely(dataStart > dataEnd)) {
      return -1;
    }
    *dstPort = udph->dest;
    break;
  }
  case IPPROTO_SCTP: {
    struct sctphdr *sctph = (struct sctphdr *)dataStart;
    dataStart += sizeof(struct sctphdr);
    if (unlikely(dataStart > dataEnd)) {
      return -1;
    }
    *dstPort = sctph->dest;
    break;
  }
  case IPPROTO_ICMP: {
    struct icmphdr *icmph = (struct icmphdr *)dataStart;
    dataStart += sizeof(struct icmphdr);
    if (unlikely(dataStart > dataEnd)) {
      return -1;
    }
    *icmpType = icmph->type;
    *icmpCode = icmph->code;
    break;
  }
  case IPPROTO_ICMPV6: {
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
 * void *data: pointer to the packet data.
 * void *data_end: pointer to the end of the packet data.
 * __u32 ifID: ingress interface index where the packet is received from.
 * Output:
 * none.
 * Return:
 * __u32 action: returned action is the logical or of the rule id and action
 * field from the matching rule, in case of no match it returns UNDEF.
 */
__attribute__((__always_inline__)) static inline __u32
ipv4_firewall_lookup(void *data, void *data_end, __u32 ifId) {
  struct iphdr *iph = data + sizeof(struct ethhdr);
  struct lpm_ip_key_st key;
  __u32 srcAddr = 0;
  __u16 dstPort = 0;
  __u8 icmpCode = 0, icmpType = 0, proto = 0;
  int i;

  if (unlikely(ip_extract_l4info(data, data_end, &proto, &dstPort, &icmpType,
                                 &icmpCode, 1) < 0)) {
    ingress_node_firewall_printk("failed to extract l4 info");
    return SET_ACTION(UNDEF);
  }

  srcAddr = iph->saddr;

  memset(&key, 0, sizeof(key));
  key.prefixLen = 64; // ipv4 address + ifId
  memcpy(key.ip_data, &srcAddr, sizeof(srcAddr));
  key.ingress_ifindex = ifId;

  if (unlikely(debug_lookup != 0)) {
    (void)bpf_map_update_elem(&ingress_node_firewall_dbg_map, &key, &key,
                              BPF_NOEXIST);
  }

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
        ingress_node_firewall_printk("ruleInfo (protocol %d, Id %d, action %d)",
                                     rule->protocol, rule->ruleId,
                                     rule->action);
        if ((rule->protocol == IPPROTO_TCP) ||
            (rule->protocol == IPPROTO_UDP) ||
            (rule->protocol == IPPROTO_SCTP)) {
          ingress_node_firewall_printk("TCP/UDP/SCTP packet rule_dstPortStart "
                                       "%d rule_dstPortEnd %d pkt_dstPort %d",
                                       rule->dstPortStart, rule->dstPortEnd,
                                       bpf_ntohs(dstPort));
          if (rule->dstPortEnd == 0) {
            if (rule->dstPortStart == bpf_ntohs(dstPort)) {
              return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
            }
          } else {
            if ((bpf_ntohs(dstPort) >= rule->dstPortStart) &&
                (bpf_ntohs(dstPort) < rule->dstPortEnd)) {
              return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
            }
          }
        }

        if (rule->protocol == IPPROTO_ICMP) {
          ingress_node_firewall_printk(
              "ICMP packet rule(type:%d, code:%d) pkt(type:%d, code %d)",
              rule->icmpType, rule->icmpCode, icmpType, icmpCode);
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
    ingress_node_firewall_printk(
        "Packet didn't match any rule proto %d port %d", proto,
        bpf_ntohs(dstPort));
  }
  return SET_ACTION(UNDEF);
}

/*
 * ipv6_firewall_lookup(): matches ipv6 packet with LPM map's key,
 * match L4 headers with the result rules in order and return the action.
 * if there is no rule match it will return UNDEF action.
 * Input:
 * void *data: pointer to the packet data.
 * void *data_end: pointer to the end of the packet data.
 * __u32 ifID: ingress interface index where the packet is received from.
 * Output:
 * none.
 * Return:
 __u32 action: returned action is the logical or of the rule id and action field
 * from the matching rule, in case of no match it returns UNDEF.
 */
__attribute__((__always_inline__)) static inline __u32
ipv6_firewall_lookup(void *data, void *data_end, __u32 ifId) {
  struct ipv6hdr *iph = data + sizeof(struct ethhdr);
  struct lpm_ip_key_st key;
  __u8 *srcAddr = NULL;
  __u16 dstPort = 0;
  __u8 icmpCode = 0, icmpType = 0, proto = 0;
  int i;

  if (unlikely(ip_extract_l4info(data, data_end, &proto, &dstPort, &icmpType,
                                 &icmpCode, 0) < 0)) {
    ingress_node_firewall_printk("failed to extract l4 info");
    return SET_ACTION(UNDEF);
  }
  srcAddr = iph->saddr.in6_u.u6_addr8;
  memset(&key, 0, sizeof(key));
  key.prefixLen = 160; // ipv6 address + ifId
  memcpy(key.ip_data, srcAddr, 16);
  key.ingress_ifindex = ifId;

  if (unlikely(debug_lookup != 0)) {
    (void)bpf_map_update_elem(&ingress_node_firewall_dbg_map, &key, &key,
                              BPF_NOEXIST);
  }

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
        ingress_node_firewall_printk("ruleInfo (protocol %d, Id %d, action %d)",
                                     rule->protocol, rule->ruleId,
                                     rule->action);
        if ((rule->protocol == IPPROTO_TCP) ||
            (rule->protocol == IPPROTO_UDP) ||
            (rule->protocol == IPPROTO_SCTP)) {
          ingress_node_firewall_printk("TCP/UDP/SCTP packet rule_dstPortStart "
                                       "%d rule_dstPortEnd %d pkt_dstPort %d",
                                       rule->dstPortStart, rule->dstPortEnd,
                                       bpf_ntohs(dstPort));
          if (rule->dstPortEnd == 0) {
            if (rule->dstPortStart == bpf_ntohs(dstPort)) {
              return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
            }
          } else {
            if ((bpf_ntohs(dstPort) >= rule->dstPortStart) &&
                (bpf_ntohs(dstPort) < rule->dstPortEnd)) {
              return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
            }
          }
        }

        if (rule->protocol == IPPROTO_ICMPV6) {
          ingress_node_firewall_printk(
              "ICMPV6 packet rule(type:%d, code:%d) pkt(type:%d, code %d)",
              rule->icmpType, rule->icmpCode, icmpType, icmpCode);
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
    ingress_node_firewall_printk(
        "Packet didn't match any rule proto %d port %d", proto,
        bpf_ntohs(dstPort));
  }
  return SET_ACTION(UNDEF);
}

/*
 * generate_event_and_update_statistics() : it will generate eBPF event
 * including the packet header and update statistics for the specificed rule id.
 * Input:
 * struct xdp_md *ctx: pointer to XDP context including input interface and
 * packet pointer.
 * __u64 packet_len: packet length in bytes including layer2 header.
 * __u8 action: valid actions ALLOW/DENY/UNDEF.
 * __u16 ruleId: ruled id where the packet matches against (in case of match of
 * course).
 * __u8 generateEvent: need to generate event for this packet or not.
 * __u32 ifID: input interface index where the packet is arrived from.
 * Output:
 * none.
 * Return:
 * none.
 */
__attribute__((__always_inline__)) static inline void
generate_event_and_update_statistics(void *ctx, __u64 packet_len, __u8 action,
                                     __u16 ruleId, __u8 generateEvent,
                                     __u32 ifId) {
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
    bpf_map_update_elem(&ingress_node_firewall_statistics_map, &key,
                        &initialStats, BPF_ANY);
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
 * xdp_ingress_node_firewall_main(): is the entry point for the XDP program to
 * do ingress node firewall. Input: struct xdp_md *ctx: pointer to XDP context
 * which contains packet pointer and input interface index. Output: none.
 * Return:
 * int XDP action: valid values XDP_DROP and XDP_PASS.
 */
__attribute__((__always_inline__)) static inline int
xdp_ingress_node_firewall_main(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *dataEnd = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  void *dataStart = data + sizeof(struct ethhdr);
  __u32 result = UNDEF;
  __u32 ifId = ctx->ingress_ifindex;

  ingress_node_firewall_printk(
      "XDP: Ingress node firewall start processing a packet on %d", ifId);

  if (unlikely(dataStart > dataEnd)) {
    ingress_node_firewall_printk(
        "XDP: Ingress node firewall bad packet XDP_DROP");
    return XDP_DROP;
  }
  switch (eth->h_proto) {
  case bpf_htons(ETH_P_IP):
    ingress_node_firewall_printk(
        "XDP: Ingress node firewall process IPv4 packet");
    result = ipv4_firewall_lookup(data, dataEnd, ifId);
    break;
  case bpf_htons(ETH_P_IPV6):
    ingress_node_firewall_printk(
        "XDP: Ingress node firewall process IPv6 packet");
    result = ipv6_firewall_lookup(data, dataEnd, ifId);
    break;
  default:
    ingress_node_firewall_printk(
        "XDP: Ingress node firewall unknown L3 protocol XDP_PASS");
    return XDP_PASS;
  }

  __u16 ruleId = GET_RULE_ID(result);
  __u8 action = GET_ACTION(result);

  switch (action) {
  case DENY:
    generate_event_and_update_statistics(ctx, bpf_xdp_get_buff_len(ctx), DENY,
                                         ruleId, 1, ifId);
    ingress_node_firewall_printk(
        "XDP: Ingress node firewall action DENY -> XDP_DROP");
    return XDP_DROP;
  case ALLOW:
    generate_event_and_update_statistics(ctx, bpf_xdp_get_buff_len(ctx), ALLOW,
                                         ruleId, 0, ifId);
    ingress_node_firewall_printk(
        "XDP: Ingress node firewall action ALLOW -> XDP_PASS");
    return XDP_PASS;
  default:
    ingress_node_firewall_printk("XDP: Ingress node firewall action UNDEF");
    return XDP_PASS;
  }
}

/*
 * tcx_ingress_node_firewall_main(): is the entry point for the TCX program to
 * do ingress node firewall. Input: struct __sk_buff *ctx: pointer to sk_buff
 * which contains packet pointer and input interface index. Output: none.
 * Return:
 * int TCX action: valid values TCX_DROP and TCX_NEXT.
 */
__attribute__((__always_inline__)) static inline int
tcx_ingress_node_firewall_main(struct __sk_buff *ctx) {
  void *data = (void *)(long)ctx->data;
  void *dataEnd = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  void *dataStart = data + sizeof(struct ethhdr);
  __u32 result = UNDEF;
  __u32 ifId = ctx->ifindex;

  ingress_node_firewall_printk(
      "TCX: Ingress node firewall start processing a packet on %d", ifId);

  if (unlikely(dataStart > dataEnd)) {
    ingress_node_firewall_printk(
        "TCX: Ingress node firewall bad packet TCX_DROP");
    return TCX_DROP;
  }
  switch (eth->h_proto) {
  case bpf_htons(ETH_P_IP):
    ingress_node_firewall_printk(
        "TCX: Ingress node firewall process IPv4 packet");
    result = ipv4_firewall_lookup(data, dataEnd, ifId);
    break;
  case bpf_htons(ETH_P_IPV6):
    ingress_node_firewall_printk(
        "TCX: Ingress node firewall process IPv6 packet");
    result = ipv6_firewall_lookup(data, dataEnd, ifId);
    break;
  default:
    ingress_node_firewall_printk(
        "TCX: Ingress node firewall unknown L3 protocol TCX_NEXT");
    return TCX_NEXT;
  }

  __u16 ruleId = GET_RULE_ID(result);
  __u8 action = GET_ACTION(result);

  switch (action) {
  case DENY:
    generate_event_and_update_statistics(ctx, ctx->len, DENY, ruleId, 1, ifId);
    ingress_node_firewall_printk(
        "TCX: Ingress node firewall action DENY -> TCX_DROP");
    return TCX_DROP;
  case ALLOW:
    generate_event_and_update_statistics(ctx, ctx->len, ALLOW, ruleId, 0, ifId);
    ingress_node_firewall_printk(
        "TCX: Ingress node firewall action ALLOW -> TCX_NEXT");
    return TCX_NEXT;
  default:
    ingress_node_firewall_printk("TCX: Ingress node firewall action UNDEF");
    return TCX_NEXT;
  }
}

SEC("xdp.frags")
int xdp_ingress_node_firewall_process(struct xdp_md *ctx) {
  return xdp_ingress_node_firewall_main(ctx);
}

SEC("tcx_ingress_node_fw")
int tcx_ingress_node_firewall_process(struct __sk_buff *skb) {
  return tcx_ingress_node_firewall_main(skb);
}

char __license[] SEC("license") = "Dual BSD/GPL";
