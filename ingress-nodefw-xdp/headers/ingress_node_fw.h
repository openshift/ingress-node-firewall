#ifndef __INGRESS_NODE_FW_H
#define __INGRESS_NODE_FW_H

#define DENY XDP_DROP
#define ALLOW XDP_PASS
#define MAX_DST_PORTS 100
#define MAX_TARGETS   (1024)
#define MAX_RULES_PER_TARGET (100)
#define MAX_EVENT_DATA 512ul

struct ruleType {
    __u32 ruleId;
    __u8 protocol;
    union {
        __u8 srcAddr[4];
        __u8 srcAddr[16];
    } srcAddr;
    union {
        __u8 srcMask[4];
        __u8 srcMask[16];
    } srcMask;
     __u16 dstPort[MAX_DST_PORTS];
    __u8 icmpType;
    __u8 icmpCode;
    __u8 action;
} __packed;


// using Longest prefix match in case of overlapping CIDRs we need to match to the more specific CIDR.
struct bpf_lpm_ip_key {
    __u32 prefixLen;
    union {
        __u8 data[4];
        __u8 data[16];
    } u;
} __packed;

struct rulesVal {
    __u32 numRules;
    struct ruleType rules[0];
} __packed;

struct ruleStatistics {
    __u64 packets;
    __u64 bytes;
} __packed;

#endif