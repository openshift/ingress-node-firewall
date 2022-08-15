#!/usr/bin/env bash
set -o errexit

# create registry container unless it already exists
reg_name='kind-registry'
reg_port='5001'
if [ "$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)" != 'true' ]; then
  docker run \
    -d --restart=always -p "127.0.0.1:${reg_port}:5000" --name "${reg_name}" \
    registry:2
fi

DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# desired cluster name; default is "kind"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kind}"
IP_FAMILY=${IP_FAMILY:-dual}
NET_CIDR_IPV4=${NET_CIDR_IPV4:-10.244.0.0/16}
SVC_CIDR_IPV4=${SVC_CIDR_IPV4:-10.96.0.0/16}
NET_CIDR_IPV6=${NET_CIDR_IPV6:-fd00:10:244::/48}
SVC_CIDR_IPV6=${SVC_CIDR_IPV6:-fd00:10:96::/112}
cat <<EOF | kind create cluster --image kindest/node:v1.24.0 --config=- --kubeconfig=${DIR}/kubeconfig
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${reg_port}"]
    endpoint = ["http://${reg_name}:5000"]
networking:
    podSubnet: $NET_CIDR_IPV4,$NET_CIDR_IPV6
    serviceSubnet: $SVC_CIDR_IPV4,$SVC_CIDR_IPV6
    ipFamily: $IP_FAMILY
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
        extraArgs:
            v: "5"
    controllerManager:
        extraArgs:
            v: "5"
    scheduler:
        extraArgs:
            v: "5"
- role: worker
- role: worker
EOF
export KUBECONFIG=${DIR}/kubeconfig
oc label node kind-worker node-role.kubernetes.io/worker=
oc label node kind-worker2 node-role.kubernetes.io/worker=
