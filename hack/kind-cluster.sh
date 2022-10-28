#!/usr/bin/env bash
set -eux

DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

KIND_IMAGE="kindest/node:v1.25.2"
# Direct push from alpines offical docker repository to quay in order not to hit dockers rate limiting.
BPF_MOUNTER_IMAGE="quay.io/ingressnodefirewall/alpine:3.14"

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
  cat <<EOF | kind create cluster --image ${KIND_IMAGE} --config=- --kubeconfig=${DIR}/kubeconfig
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
- role: worker
EOF
}

# install_bpf_daemonset will install the daemonset that mounts the bpf file system
# into each kind docker container
install_bpf_daemonset() {
  cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: bpf-mounter
  namespace: default
spec:
  selector:
    matchLabels:
      app: bpf-mounter
  template:
    metadata:
      labels:
        app: bpf-mounter
    spec:
      hostNetwork: true
      hostPID: true
      tolerations:
        - operator: Exists
      initContainers:
        - name: mount-bpffs
          image: ${BPF_MOUNTER_IMAGE}
          command:
          - /bin/sh
          - -xc
          - |
            #!/bin/sh
            if ! /bin/mount | /bin/grep -q 'bpffs on /sys/fs/bpf'; then
              /bin/mount bpffs /sys/fs/bpf -t bpf
            fi
          securityContext:
            privileged: true
            runAsUser: 0
            capabilities:
              add:
                - CAP_BPF
                - CAP_NET_ADMIN
          terminationMessagePolicy: FallbackToLogsOnError
          volumeMounts:
            - name: bpf-maps
              mountPath: /sys/fs/bpf
              mountPropagation: Bidirectional
      containers:
        - name: sleep
          image: ${BPF_MOUNTER_IMAGE}
          command: ['sleep', 'infinity']
      volumes:
        - name: bpf-maps
          hostPath:
            path: /sys/fs/bpf
            type: DirectoryOrCreate
EOF
  kubectl rollout status daemonset -n default bpf-mounter --timeout 300s
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

# DaemonSet to mount /sys/fs/bpf on each docker container
install_bpf_daemonset

# If the -d flag is set, install the operator as well
if $DEPLOY_OPERATOR; then
  install_operator
fi

# Print success at the end of this script
print_success
