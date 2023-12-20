# Troubleshooting Ingress Node Firewall

![logo](./infw_debug.png)

By: Mohamed S. Mahmoud

## Install dependencies

```shell
toolbox
yum install -y bpftool xdp-tools
```

You might have to use custom toolbox image to do so please refer to
https://docs.openshift.com/container-platform/4.14/support/gathering-cluster-data.html#about-toolbox_gathering-cluster-data

## Inspecting Ingress Node Firewall Tables with `bpftool`

Retrieve the details of the Ingress Node Firewall object:

```yaml
 oc get ingressnodefirewalls.ingressnodefirewall.openshift.io ingressnodefirewall-demo2 -o yaml
apiVersion: ingressnodefirewall.openshift.io/v1alpha1
kind: IngressNodeFirewall
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"ingressnodefirewall.openshift.io/v1alpha1","kind":"IngressNodeFirewall","metadata":{"annotations":{},"name":"ingressnodefirewall-demo2"},"spec":{"ingress":[{"rules":[{"action":"Deny","order":10,"protocolConfig":{"icmp":{"icmpType":8},"protocol":"ICMP"}},{"action":"Deny","order":20,"protocolConfig":{"protocol":"TCP","tcp":{"ports":"8000-9000"}}}],"sourceCIDRs":["172.16.0.0/12"]},{"rules":[{"action":"Deny","order":10,"protocolConfig":{"icmpv6":{"icmpType":128},"protocol":"ICMPv6"}}],"sourceCIDRs":["fc00:f853:ccd:e793::0/64"]}],"interfaces":["eth0"],"nodeSelector":{"matchLabels":{"do-node-ingress-firewall":"true"}}}}
  creationTimestamp: "2023-12-18T16:49:52Z"
  generation: 1
  name: ingressnodefirewall-demo2
  resourceVersion: "1476"
  uid: 70e10b9c-4aee-4490-a1bc-07930fa71563
spec:
  ingress:
  - rules:
    - action: Deny
      order: 10
      protocolConfig:
        icmp:
          icmpType: 8
        protocol: ICMP
    - action: Deny
      order: 20
      protocolConfig:
        protocol: TCP
        tcp:
          ports: 8000-9000
    sourceCIDRs:
    - 172.16.0.0/12
  - rules:
    - action: Deny
      order: 10
      protocolConfig:
        icmpv6:
          icmpType: 128
        protocol: ICMPv6
    sourceCIDRs:
    - fc00:f853:ccd:e793::0/64
  interfaces:
  - eth0
  nodeSelector:
    matchLabels:
      do-node-ingress-firewall: "true"
status:
  syncStatus: Synchronized

```

Check if the Ingress Node Firewall is attached to the interface:

```shell
[root@kind-worker /]# ip link show eth0
97: eth0@if98: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc noqueue state UP mode DEFAULT group default
    link/ether 02:42:ac:14:00:04 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    prog/xdp id 504 name ingress_node_fi tag 29d9ba3daeaf54b2 jited
```

View the Ingress Node Firewall maps using `bpftool`:

```shell
bpftool map list
....
 431: lpm_trie  name ingress_node_fi  flags 0x1
	key 24B  value 1200B  max_entries 1024  memlock 2520B
	btf_id 721
	pids daemon(1089355)
432: percpu_array  name ingress_node_fi  flags 0x0
	key 4B  value 32B  max_entries 1024  memlock 401728B
	btf_id 722
	pids daemon(1089355)
433: perf_event_array  name ingress_node_fi  flags 0x0
	key 4B  value 4B  max_entries 12  memlock 416B
	pids daemon(1089355)

```

Now, inspect the rules inside the Longest Prefix Match (LPM) table:

```shell
bpftool map dump id 431 -p
 "formatted": {
            "key": {
                "prefixLen": 44,
                "ingress_ifindex": 97,
                "ip_data": [172,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0
                ]
            },
            "value": {
                "rules": [{
                        "ruleId": 0,
                        "protocol": 0,
                        "dstPortStart": 0,
                        "dstPortEnd": 0,
                        "icmpType": 0,
                        "icmpCode": 0,
                        "action": 0
                  },{
                        "ruleId": 10,
                        "protocol": 1,
                        "dstPortStart": 0,
                        "dstPortEnd": 0,
                        "icmpType": 8,
                        "icmpCode": 0,
                        "action": 1
                    },{
                        "ruleId": 20,
                        "protocol": 6,
                        "dstPortStart": 8000,
                        "dstPortEnd": 9000,
                        "icmpType": 0,
                        "icmpCode": 0,
                        "action": 1
                    },{
                        "ruleId": 0,
                        "protocol": 0,
                        "dstPortStart": 0,
                        "dstPortEnd": 0,
                        "icmpType": 0,
                        "icmpCode": 0,
                        "action": 0
                    }
                ]
            }
        }
```

For clarity, note that action field values are defined as follows:

- `XDP_DROP` = 1
- `XDP_PASS` = 2

If uncertain about the Longest Prefix Match (LPM) key, enable `debug`
in node firewall config object and redeploy.
Update the Ingress Node Firewall Config:

```yaml
apiVersion: ingressnodefirewall.openshift.io/v1alpha1
kind: IngressNodeFirewallConfig
metadata:
  name: ingressnodefirewallconfig
  namespace: ingress-node-firewall-system
spec:
  nodeSelector:
    node-role.kubernetes.io/worker: ""
  debug: true
```

Inspect the precise Longest Prefix Match (LPM) key build by Ingress Node Firewall code:

```bash
[root@kind-worker /]# bpftool map list
501: hash  name ingress_node_fi  flags 0x0
	key 24B  value 24B  max_entries 16384  memlock 1837472B
	btf_id 844
	pids daemon(1135584)
502: lpm_trie  name ingress_node_fi  flags 0x1
	key 24B  value 1200B  max_entries 1024  memlock 2520B
	btf_id 845
	pids daemon(1135584)
503: percpu_array  name ingress_node_fi  flags 0x0
	key 4B  value 32B  max_entries 1024  memlock 401728B
	btf_id 846
	pids daemon(1135584)
504: perf_event_array  name ingress_node_fi  flags 0x0
	key 4B  value 4B  max_entries 12  memlock 416B
	pids daemon(1135584)

[root@kind-worker /]# ip link show eth0
103: eth0@if104: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc noqueue state UP mode DEFAULT group default
    link/ether 02:42:ac:14:00:03 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    prog/xdp id 626 name ingress_node_fi tag 29d9ba3daeaf54b2 jited
```

```shell

[root@kind-worker /]# bpftool map dump id 501
[{
    {
        "key": {
            "prefixLen": 64,
            "ingress_ifindex": 103,
            "ip_data": [172,64,150,109,0,0,0,0,0,0,0,0,0,0,0,0
            ]
        },
        "value": {
            "prefixLen": 64,
            "ingress_ifindex": 103,
            "ip_data": [172,64,150,109,0,0,0,0,0,0,0,0,0,0,0,0
            ]
        }
    }
}]

```

The lookup key sent to the Longest Prefix Match (LPM) matching is also employed as
both the key and the value in the hashmap mentioned above,
providing a means to verify that the key is constructed accurately.

Note: Ingress Node Firewall daemon's daemon container logs shows the key
values associated with ingress node firewall.

Lastly, there is perCPU array containing statistics index by `ruleId` and it also
can be read by `bpftool`

```shell
[root@kind-worker /]# bpftool map dump id 503 -p
....
 "formatted": {
            "key": 10,
            "values": [{
                    "cpu": 0,
                    "value": {
                        "allow_stats": {
                            "packets": 0,
                            "bytes": 0
                        },
                        "deny_stats": {
                            "packets": 0,
                            "bytes": 0
                        }
                    }
                },{
                    "cpu": 1,
                    "value": {
                        "allow_stats": {
                            "packets": 0,
                            "bytes": 0
                        },
                        "deny_stats": {
                            "packets": 0,
                            "bytes": 0
                        }
                    }
                },{
                    "cpu": 2,
                    "value": {
                        "allow_stats": {
                            "packets": 0,
                            "bytes": 0
                        },
                        "deny_stats": {
                            "packets": 6,
                            "bytes": 588
                        }
                    }
                },{
                    "cpu": 3,
                    "value": {
                        "allow_stats": {
                            "packets": 0,
                            "bytes": 0
                        },
                        "deny_stats": {
                            "packets": 7,
                            "bytes": 686
                        }
                    }
                },{
                    "cpu": 4,
                    "value": {
                        "allow_stats": {
                            "packets": 0,
                            "bytes": 0
                        },
                        "deny_stats": {
                            "packets": 21,
                            "bytes": 2058
                        }
                    }
                },{

```

For more details about `bpftool` please refer to
https://github.com/libbpf/bpftool/blob/main/docs/bpftool.rst

## Using `xdp-loader` to force removing Ingress Node Firewall eBPF XDP program from an interface

Check the loaded XDP programs:

```shell
[root@kind-worker /]# xdp-loader status
CURRENT XDP PROGRAM STATUS:

Interface        Prio  Program name      Mode     ID   Tag               Chain actions
--------------------------------------------------------------------------------------
lo                     <No XDP program loaded!>
vethcdb1588a           <No XDP program loaded!>
vetheecac75e           <No XDP program loaded!>
eth0                   ingress_node_firewall_process native   504  29d9ba3daeaf54b2

```

To remove Ingress Node Firewall from `eth0`:

```shell
[root@kind-worker /]# xdp-loader unload -a eth0
[root@kind-worker /]# xdp-loader status
CURRENT XDP PROGRAM STATUS:

Interface        Prio  Program name      Mode     ID   Tag               Chain actions
--------------------------------------------------------------------------------------
lo                     <No XDP program loaded!>
vethcdb1588a           <No XDP program loaded!>
vetheecac75e           <No XDP program loaded!>
eth0                   <No XDP program loaded!>

```

For more details about `xdp-loader` please refer to
https://github.com/xdp-project/xdp-tools/tree/master/xdp-loader

## Using `xdpdump` to Identify Issues After Applying Node Firewall

Send ping traffic and detect dropped packets `xdpdump`:

```shell
[root@kind-worker /]# xdpdump -i eth0 -x --rx-capture entry,exit | grep -i drop -A10 -B10
listening on eth0, ingress XDP program ID 521 func ingress_node_firewall_process, capture mode entry/exit, capture size 262144 bytes
1702921403.926847279: ingress_node_firewall_process()@exit[DROP]: packet size 98 bytes, captured 98 bytes on if_index 97, rx queue 0, id 1
  0x0000:  02 42 ac 14 00 04 02 42 38 0f 70 1c 08 00 45 00  .B.....B8.p...E.
  0x0010:  00 54 57 bb 40 00 40 01 8a c0 ac 14 00 01 ac 14  .TW.@.@.........
  0x0020:  00 04 08 00 5a f4 00 0a 00 0a c5 84 80 65 00 00  ....Z........e..
  0x0030:  00 00 8e 3a 0a 00 00 00 00 00 10 11 12 13 14 15  ...:............
  0x0040:  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25  .......... !"#$%
  0x0050:  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35  &'()*+,-./012345
  0x0060:  36 37                                            67

```

Note: You can also check the Ingress Node Firewall daemonset's events container for equivalent information:

```shell
oc logs -n ingress-node-firewall-system ingress-node-firewall-daemon-nmmps -c events -f
2023-12-18 17:26:52 +0000 UTC kind-worker ruleId 10 action Drop len 98 if eth0
2023-12-18 17:26:52 +0000 UTC kind-worker 	ipv4 src addr 172.20.0.1 dst addr 172.20.0.4
2023-12-18 17:26:52 +0000 UTC kind-worker 	icmpv4 type 8 code 0
2023-12-18 17:26:53 +0000 UTC kind-worker ruleId 10 action Drop len 98 if eth0
2023-12-18 17:26:53 +0000 UTC kind-worker 	ipv4 src addr 172.20.0.1 dst addr 172.20.0.4
2023-12-18 17:26:53 +0000 UTC kind-worker 	icmpv4 type 8 code 0

```

For more details about `xdpdump` please refer to
https://www.redhat.com/en/blog/capturing-network-traffic-express-data-path-xdp-environment
