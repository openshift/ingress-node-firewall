#!/usr/bin/bash

ingress_node_firewall_dir="$(dirname $(readlink -f $0))"
source ${ingress_node_firewall_dir}/common.sh

TESTS_REPORTS_PATH=${TESTS_REPORTS_PATH:-/logs/artifacts/}
export OO_INSTALL_NAMESPACE=${OO_INSTALL_NAMESPACE:-"openshift-ingress-node-firewall"}

worker_node=$(oc get node | grep worker | head -n 1 | awk '{print $1}')
ovnkube_node_pod=$(oc get pod -n openshift-ovn-kubernetes -owide | grep ovnkube-node | grep "${worker_node}" | awk '{print $1}')
# E2E tests test allowing / denying Pod IPs. This is not the typical use case for INF but it gives us flexibility and
# control over the test cases that we would not enjoy if we attached to any other interface.
# Pod IPs are visibly by the XDP program after they have been de-encapsulated and for OVN-Kubernetes as the CNI - this is a GENEVE interface.
# Since OVN-Kubernetes is the default CNI for OCP, we set the interface to test against as the GENEVE interface.
export NODE_INTERFACE=genev_sys_6081
# CoreOS nodes, by default, have SCTP kernel module unloaded.
export ENABLE_SCTP=false

yum install -y go

mkdir -p "${TESTS_REPORTS_PATH}"
go test --tags=validationtests -v ../test/e2e/validation -ginkgo.v -junit "${TESTS_REPORTS_PATH}" -report "${TESTS_REPORTS_PATH}"
go test --tags=e2etests -v ../test/e2e/functional -ginkgo.v -junit "${TESTS_REPORTS_PATH}" -report "${TESTS_REPORTS_PATH}"
