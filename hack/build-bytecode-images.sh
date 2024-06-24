#!/bin/bash

# Set default value for IMAGE_INFW_BC tag if not already set
IMAGE_INFW_BC=${IMAGE_INFW_BC:-quay.io/bpfman-bytecode/ingress-node-firewall}

# PROGRAMS is a list of <program name>:<program type> tuples
PROGRAMS="{\
\"xdp_ingress_node_firewall_process\":\"xdp\",\
\"tcx_ingress_node_firewall_process\":\"tc\"\
}"

# MAPS is a list of <map name>:<map type> tuples
MAPS="{\
\"ingress_node_firewall_dbg_map\":\"hash\",\
\"ingress_node_firewall_events_map\":\"perf_event_array\",\
\"ingress_node_firewall_statistics_map\":\"per_cpu_array\",\
\"ingress_node_firewall_table_map\":\"lpm_trie\"\
}"

docker buildx create --use
docker buildx inspect --bootstrap

DOCKER_BUILDKIT=1 docker build \
 --build-arg PROGRAMS="$PROGRAMS" \
 --build-arg MAPS="$MAPS" \
 --build-arg BYTECODE_FILE=bpf_x86_bpfel.o \
 -f ./Containerfile.bytecode \
 --push \
 ./pkg/ebpf -t $IMAGE_INFW_BC
