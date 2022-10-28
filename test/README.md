# Tests

## E2E mode

The ingress-node-firewall e2e tests are divided into 2 suites:
- validation - verify if the ingress-node-firewall operator has been installed correctly
- functional - verify that the installation of ingress-node-firewall by the operator is working correctly

To run the tests use the following make targets:
- make test-validation - run the validation tests
    - Enable running e2e tests in a non-default namespace by setting environment variable `OO_INSTALL_NAMESPACE` value to the namespace name.
- make test-functional - run the functional tests
    - Enable running e2e tests in a non-default namespace by setting environment variable `OO_INSTALL_NAMESPACE` value to the namespace name.
    - Override the default test interface (currently "eth0") for installing the XDP program by setting environment variable `NODE_INTERFACE` value to the interface name. Overriding is required when testing on OCP and must be set to `genev_sys_6081` when OVN-Kubernetes is the CNI.
    - SCTP tests are enabled by default. Your test target kubernetes cluster nodes must have have SCTP kernel modules loaded.
      Enable the kernel module on RHEL 8 / CoreOS:
      ```shell
      modprobe sctp
      ```
      Enable SCTP tests by setting environment variable `ENABLE_SCTP=true`
    - Force single stack by setting environment variable `IS_SINGLESTACK=true`. When set to true and if the test target is a dual stack cluster, only IPV4 tests will execute.

- make test-e2e - run all tests

# Known issues
- Executing IPV6 tests against a KinD cluster may not function if your KinD host has firewalld enabled.
For fedora:
```shell
sudo systemctl stop firewalld
sudo systemctl stop docker
sudo systemctl start docker
# create your cluster
```
