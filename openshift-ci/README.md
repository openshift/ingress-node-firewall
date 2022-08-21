# ingress-node-firewall test env

This scripts installs ingress-node-firewall into OCP, for test environment.

## Prerequisites

- Succeed to deploy OCP by dev-scripts (https://github.com/openshift-metal3/dev-scripts)
- IPv4v6 is enabled

## Quickstart

Make sure that OCP is deployed by dev-scripts.

To configure ingress-node-firewall clone this repo to dev-scripts and run:

```
$ cd <dev-scripts>/ingress-node-firewall/openshift-ci/
$ ./deploy_ingress_node_firewall.sh
```

### Check ingress-node-firewall pod status

```
$ export KUBECONIFG=<dev-scripts>/ocp/<cluster name>/auth/kubeconfig
$ oc get pod -n openshift-ingress-node-firewall
```

### Run E2E tests against development cluster

The test suite will run the appropriate tests against the cluster.

To run the E2E tests:

```
$ cd <dev-scripts>/ingress-node-firewall/openshift-ci/
$ ./run_e2e.sh
```
