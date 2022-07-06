#ifndef __INGRESS_NODE_FW_H
#define __INGRESS_NODE_FW_H

#define UNDEF 0
#define DENY XDP_DROP
#define ALLOW XDP_PASS
#define MAX_DST_PORTS 100
#define MAX_TARGETS   (1024)
#define MAX_RULES_PER_TARGET (100)
#define MAX_EVENT_DATA 512ul

struct event_hdr {
    __u16 ifId;
    __u16 ruleId;
    __u8  action;
    __u8  fill;
};

struct ruleType {
    __u32 ruleId;
    __u8 protocol;
    union {
        __u32 ip4_srcAddr;
        __u32 ip6_srcAddr[4];
    } srcAddrU;
    union {
        __u32 ip4_srcMask;
        __u32 ip6_srcMask[4];
    } srcMaskU;
    __u16 dstPorts[MAX_DST_PORTS];
    __u8 icmpType;
    __u8 icmpCode;
    __u8 action;
};


// using Longest prefix match in case of overlapping CIDRs we need to match to the more specific CIDR.
struct bpf_lpm_ip_key {
    __u32 prefixLen;
    union {
        __u8 ip4_data[4];
        __u8 ip6_data[16];
    } u;
};

struct rulesVal {
    __u32 numRules;
    struct ruleType rules[0];
};

struct ruleStatistics {
    __u64 packets;
    __u64 bytes;
};

#endif