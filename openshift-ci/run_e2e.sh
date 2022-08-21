#!/usr/bin/bash

ingress_node_firewall_dir="$(dirname $(readlink -f $0))"
source ${ingress_node_firewall_dir}/common.sh

TESTS_REPORTS_PATH=${TESTS_REPORTS_PATH:-/logs/artifacts/}
export OO_INSTALL_NAMESPACE=${OO_INSTALL_NAMESPACE:-"openshift-ingress-node-firewall"}
export IS_OPENSHIFT="true"

worker_node=$(oc get node | grep worker | head -n 1 | awk '{print $1}')
ovnkube_node_pod=$(oc get pod -n openshift-ovn-kubernetes -owide | grep ovnkube-node | grep "${worker_node}" | awk '{print $1}')
export NODE_INTERFACE=$(oc exec -n openshift-ovn-kubernetes "${ovnkube_node_pod}" ovs-vsctl list-ports br-ex | grep -v br-ex)

yum install -y go

mkdir -p "${TESTS_REPORTS_PATH}"
go test --tags=validationtests -v ../test/e2e/validation -ginkgo.v -junit "${TESTS_REPORTS_PATH}" -report "${TESTS_REPORTS_PATH}"
go test --tags=e2etests -v ../test/e2e/functional -ginkgo.v -junit "${TESTS_REPORTS_PATH}" -report "${TESTS_REPORTS_PATH}"
