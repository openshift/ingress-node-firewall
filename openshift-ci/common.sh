#!/usr/bin/bash

ingress_node_firewall_dir="$(dirname $(readlink -f $0))"
source ${ingress_node_firewall_dir}/../../common.sh
source ${ingress_node_firewall_dir}/../../network.sh
