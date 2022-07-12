#ifndef __INGRESS_NODE_FIREWALL__
#define __INGRESS_NODE_FIREWALL__

#define UNDEF 0
#define DENY XDP_DROP
#define ALLOW XDP_PASS
#define MAX_DST_PORTS 100
#define MAX_TARGETS (1024)
#define MAX_RULES_PER_TARGET (100)
#define MAX_EVENT_DATA 512ul

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

struct event_hdr_st {
  __u16 ifId;
  __u16 ruleId;
  __u8 action;
  __u8 fill;
} __attribute__((packed));

// Force emitting struct event_hdr_st into the ELF.
const struct event_hdr_st *unused __attribute__((unused));

struct ruleType_st {
  __u32 ruleId;
  __u8 protocol;
  __u16 dstPorts[MAX_DST_PORTS];
  __u8 icmpType;
  __u8 icmpCode;
  __u8 action;
} __attribute__((packed));

// using Longest prefix match in case of overlapping CIDRs we need to match to
// the more specific CIDR.
struct bpf_lpm_ip_key_st {
  __u32 prefixLen;
  union {
    __u8 ip4_data[4];
    __u8 ip6_data[16];
  } u;
} __attribute__((packed));

struct rulesVal_st {
  __u32 numRules;
  struct ruleType_st rules[MAX_RULES_PER_TARGET];
} __attribute__((packed));

struct ruleStatistics_st {
  __u64 packets;
  __u64 bytes;
} __attribute__((packed));

#endif
