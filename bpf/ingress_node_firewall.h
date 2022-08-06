#ifndef __INGRESS_NODE_FIREWALL__
#define __INGRESS_NODE_FIREWALL__

#define UNDEF XDP_ABORTED
#define DENY XDP_DROP
#define ALLOW XDP_PASS
#define MAX_TARGETS (1024)
#define MAX_RULES_PER_TARGET (100)
#define MAX_EVENT_DATA 256

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

#ifndef memset
# define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
# define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif

struct ruleStatistics_st {
	struct allow_stats_st {
        __u64 packets;
        __u64 bytes;
    } allow_stats;
    struct deny_stats_st {
        __u64 packets;
        __u64 bytes;
    } deny_stats;
};
// Force emitting struct ruleStatistics_st into the ELF.
const struct ruleStatistics_st *unused3 __attribute__((unused));

struct event_hdr_st {
    __u16 ifId;
    __u16 ruleId;
    __u8 action;
    __u8 pad;
    __u16 pktLength;
} __attribute__((packed));

// Force emitting struct event_hdr_st into the ELF.
const struct event_hdr_st *unused1 __attribute__((unused));

struct ruleType_st {
    __u32 ruleId;
    __u8 protocol;
    __u16 dstPortStart;
    __u16 dstPortEnd;
    __u8 icmpType;
    __u8 icmpCode;
    __u8 action;
} __attribute__((packed));
// Force emitting struct ruleType_st into the ELF.
const struct ruleType_st *unused2 __attribute__((unused));

// using Longest prefix match in case of overlapping CIDRs we need to match to
// the more specific CIDR.
struct lpm_ip_key_st {
    __u32 prefixLen;
    __u8 ip_data[16];
    __u32 ingress_ifindex;
} __attribute__((packed));

struct rulesVal_st {
    struct ruleType_st rules[MAX_RULES_PER_TARGET];
} __attribute__((packed));


#endif
