#!/usr/bin/bash

ingress_node_firewall_dir="$(dirname $(readlink -f $0))"
pushd ${ingress_node_firewall_dir}/../../
source common.sh
source network.sh
popd