#!/usr/bin/env bash
set -o errexit

DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# desired cluster name; default is "kind"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kind}"

cat <<EOF | kind create cluster --image kindest/node:v1.24.0 --config=- --kubeconfig=${DIR}/kubeconfig
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
    ipFamily: "dual"
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
        kubeletExtraArgs:
        container-log-max-size: "100Mi"
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
EOF
export KUBECONFIG=${DIR}/kubeconfig
oc label node kind-control-plane node-role.kubernetes.io/worker=
