#!/bin/bash

# Set default value for IMAGE_INFW_BC tag if not already set
IMAGE_INFW_BC=${IMAGE_INFW_BC:-quay.io/bpfman-bytecode/ingress-node-firewall-multi}

# PROGRAMS is a list of <program name>:<program type> tuples
PROGRAMS='{
"xdp_ingress_node_firewall_process":"xdp",
"tcx_ingress_node_firewall_process":"tcx"
}'

echo "$PROGRAMS" | jq empty || { echo "Invalid JSON in PROGRAMS"; exit 1; }

# MAPS is a list of <map name>:<map type> tuples
MAPS='{
"ingress_node_firewall_dbg_map":"hash",
"ingress_node_firewall_events_map":"perf_event_array",
"ingress_node_firewall_statistics_map":"per_cpu_array",
"ingress_node_firewall_table_map":"lpm_trie"
}'

echo "$MAPS" | jq empty || { echo "Invalid JSON in MAPS"; exit 1; }

docker buildx create --use
docker buildx inspect --bootstrap

DOCKER_BUILDKIT=1 docker buildx build \
 --platform linux/amd64,linux/arm64,linux/s390x,linux/ppc64le \
 --build-arg PROGRAMS="$PROGRAMS" \
 --build-arg MAPS="$MAPS" \
 --build-arg BC_AMD64_EL=bpf_x86_bpfel.o \
 --build-arg BC_ARM64_EL=bpf_arm64_bpfel.o \
 --build-arg BC_S390X_EB=bpf_s390_bpfeb.o \
 --build-arg BC_PPC64LE_EL=bpf_powerpc_bpfel.o \
 -f ./Containerfile.bytecode.multi.arch \
 --push \
 ./pkg/ebpf -t $IMAGE_INFW_BC
