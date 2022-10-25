#!/usr/bin/env bash
set -eux

DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# parse_args parses the provided command line arguments
parse_args() {
  set +u
  while [ "$1" != "" ]; do
    case $1 in
      -d | --deploy-operator )  DEPLOY_OPERATOR=true
                                ;;
    esac
    shift
  done
  set -u
}

# deploy_kind installs the kind cluster
deploy_kind() {
  cat <<EOF | kind create cluster --image kindest/node:v1.25.2 --config=- --kubeconfig=${DIR}/kubeconfig
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
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
  extraMounts:
      - hostPath: /sys/fs/bpf
        containerPath: /sys/fs/bpf
        propagation: Bidirectional
- role: worker
  extraMounts:
      - hostPath: /sys/fs/bpf
        containerPath: /sys/fs/bpf
        propagation: Bidirectional
EOF
}

# install_operator installs the operator on top of the kind cluster
install_operator() {
  pushd ${DIR}/../
  make install
  make docker-build IMG=localhost/ingress-node-firewall-controller:local
  kind load docker-image localhost/ingress-node-firewall-controller:local
  make docker-build-daemon DAEMON_IMG=localhost/ingress-node-firewall-daemon:local
  kind load docker-image localhost/ingress-node-firewall-daemon:local
  set +x
  hack/set-daemon-image.sh localhost/ingress-node-firewall-daemon:local || then_hit_any_key
  set -x
  make deploy-kind IMG=localhost/ingress-node-firewall-controller:local
  popd
}

# then_hit_any_key is used to stop script execution if manual user intervention is needed
then_hit_any_key() {
  echo "Then, hit any key"
  read
}

# print_success prints a little success message at the end of the script
print_success() {
  set +x
  echo "Your kind cluster was created successfully"
  echo "Run the following to load the kubeconfig:"
  echo "export KUBECONFIG=${DIR}/kubeconfig"
  set -x
}

# Parse all arguments to this script and set defaults
parse_args "$@"
DEPLOY_OPERATOR=${DEPLOY_OPERATOR:-false}
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kind}"
IP_FAMILY=${IP_FAMILY:-dual}
NET_CIDR_IPV4=${NET_CIDR_IPV4:-10.244.0.0/16}
SVC_CIDR_IPV4=${SVC_CIDR_IPV4:-10.96.0.0/16}
NET_CIDR_IPV6=${NET_CIDR_IPV6:-fd00:10:244::/48}
SVC_CIDR_IPV6=${SVC_CIDR_IPV6:-fd00:10:96::/112}

# At the minimum, deploy the kind cluster
deploy_kind
export KUBECONFIG=${DIR}/kubeconfig
oc label node kind-worker node-role.kubernetes.io/worker=
oc label node kind-worker2 node-role.kubernetes.io/worker=

# If the -d flag is set, install the operator as well
if $DEPLOY_OPERATOR; then
  install_operator
fi

# Print success at the end of this script
print_success
