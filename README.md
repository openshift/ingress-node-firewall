<p align="center">
  <img src="logo.jpg" alt="logo" width="25%"/>
</p>

# Ingress Node Firewall
This is the Ingress node Firewall Operator, implementing [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/) for deploying Ingress node firewall daemon on kubernetes cluster.
It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/)
which provides a reconcile function responsible for synchronizing resources until the desired state is reached on the cluster

[![Project maturity: alpha](https://img.shields.io/badge/maturity-alpha-orange.svg)]() [![license](https://img.shields.io/github/license/openshift/ingress-node-firewall.svg?maxAge=2592000)](https://github.com/openshift/ingress-node-firewall/blob/master/LICENSE) [![Containers](https://img.shields.io/badge/containers-ready-green.svg)](https://quay.io/openshift/ingress-node-firewall-operator:4.13) [![Go report card](https://goreportcard.com/badge/github.com/openshift/ingress-node-firewall)](https://goreportcard.com/report/github.com/openshift/ingress-node-firewall) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/6726/badge)](https://bestpractices.coreinfrastructure.org/projects/6726)


## Usage

Once the Ingress Node Firewall Operator is installed, you have to create an `IngressNodeFirewallConfig` custom resource to deploy the Operator's DaemonSet.
The `IngressNodeFirewallConfig` custom resource needs to be created inside the `ingress-node-firewall-system` namespace and be named `ingressnodefirewallconfig`. Only one `IngressNodeFirewallConfig` resource can exist in a cluster.
The operator will consume this resource and create ingress node firewall daemonset `daemon` which runs on all nodes that match the `nodeSelector`.

Following is example of `IngressNodeFirewallConfig` resource:
```yaml
apiVersion: ingressnodefirewall.openshift.io/v1alpha1
kind: IngressNodeFirewallConfig
metadata:
  name: ingressnodefirewallconfig
  namespace: ingress-node-firewall-system
spec:
  nodeSelector:
    node-role.kubernetes.io/worker: ""
```

After that, deploy one or multiple `IngressNodeFirewall` resources to apply firewall rules to your nodes. Make sure that the `nodeSelector` matches a set of nodes. The Ingress Node Firewall Operator will create objects of kind `IngressNodeFirewallNodeState` for each node that is matches by at least one `IngressNodeFirewall` resource:
```yaml
apiVersion: ingressnodefirewall.openshift.io/v1alpha1
kind: IngressNodeFirewall
metadata:
  name: ingressnodefirewall-demo-1
spec:
  interfaces:
  - eth0
  nodeSelector:
    node-role.kubernetes.io/worker: ""
  ingress:
  - sourceCIDRs:
       - 1.1.1.1/24
       - 100:1::1/64
    rules:
    - order: 10
      protocolConfig:
        protocol: TCP
        tcp:
          ports: "100-200"
      action: Allow
```

You can use the following shortcut to deploy samples, including `IngressNodeFirewallConfig` and `IngressNodeFirewall` resources:
```
make deploy-samples
```

And in order to uninstall them:
```
make undeploy-samples
```

## Deploying the operator

### Prerequisites

You need to install the following packages:

operator-sdk 1.22.0

controller-gen v0.9.0+

For fedora, you will need the following packages
```sh
sudo dnf install glibc-devel glibc-devel.i686
```

### Running on a KinD cluster

#### Creating a kind cluster with the operator installed

##### In a single step

1. Download latest [KinD](https://kind.sigs.k8s.io/docs/user/quick-start) stable version
2. Install KinD and the operator and export KUBECONFIG
```sh
make create-and-deploy-kind-cluster
export KUBECONFIG=$(pwd)/hack/kubeconfig
```
**Note:** If prompted to do so, manually edit file `config/manager/env.yaml` and set the value of environment variable
`DAEMONSET_IMAGE`. This should only happen if `yq` cannot be found.

##### Deploying kind and the operator manually

1. Download latest [KinD](https://kind.sigs.k8s.io/docs/user/quick-start) stable version
2. Install KinD and export KUBECONFIG
```sh
make create-kind-cluster
export KUBECONFIG=$(pwd)/hack/kubeconfig
```
3. Install custom resource definitions
```sh
make install
```
4. Build controller container image
```sh
make docker-build IMG=<some-registry>/ingress-node-firewall-controller:latest
```
5. Load controller container image to KinD container(s)
```sh
kind load docker-image <some-registry>/ingress-node-firewall-controller:latest
```
6. Build daemon container image
```sh
make docker-build-daemon DAEMON_IMG=<some-registry>/ingress-node-firewall-daemon:latest
```
7. Load daemon container image to KinD container(s)
```sh
kind load docker-image <some-registry>/ingress-node-firewall-daemon:latest
```
8. Set the daemon image name
```sh
hack/set-daemon-image.sh <some-registry>/ingress-node-firewall-daemon:latest
```
9. Deploy resources to KinD cluster
```sh
make deploy-kind IMG=<some-registry>/ingress-node-firewall-controller:latest
```

#### Removing the operator from the kind cluster

In order to remove the operator:
1. Undeploy resources from KinD cluster
```sh
make undeploy-kind
```
2. Uninstall custom resource definitions:
```sh
make uninstall
```

#### Deleting the kind cluster

In order to delete the kind cluster:
```sh
make destroy-kind-cluster
```

### Running on an OCP cluster

In order to run this operator on OpenShift, one can either deploy from manifests or from the OLM.
In both cases, follow the [Common steps](README.md#common-steps) first and then follow either [Deploy from manifests](README.md#deploy-from-manifests) or [Deploy with OLM](README.md#deploy-with-olm).

#### Common steps

1. Create OCP cluster
2. Build controller container image
```sh
make docker-build IMG=<some-registry>/ingress-node-firewall-controller:latest
# or make podman-build IMG=<some-registry>/ingress-node-firewall-controller:latest
```
3. Push controller container image to an image registry
```sh
make docker-push IMG=<some-registry>/ingress-node-firewall-controller:latest
# or make podman-push IMG=<some-registry>/ingress-node-firewall-controller:latest
```
4. Build daemon container image
```sh
make docker-build-daemon DAEMON_IMG=<some-registry>/ingress-node-firewall-daemon:latest
# or make podman-build-daemon DAEMON_IMG=<some-registry>/ingress-node-firewall-daemon:latest
```
5. Push controller container image to an image registry
```sh
make docker-push-daemon DAEMON_IMG=<some-registry>/ingress-node-firewall-daemon:latest
# or make podman-push-daemon DAEMON_IMG=<some-registry>/ingress-node-firewall-daemon:latest
```
6. Set the daemon image name
```sh
hack/set-daemon-image.sh <some-registry>/ingress-node-firewall-daemon:latest
```

#### Deploy from manifests

7. Install custom resource definitions
```sh
make install
```
8. Deploy resources to OpenShift cluster
```sh
make deploy IMG=<some-registry>/ingress-node-firewall-controller:latest
```

##### To uninstall

Undeploy resources from OCP cluster
```sh
make undeploy
```
Uninstall custom resource definitions
```sh
make uninstall
```

#### Deploy with OLM

7. Build and push bundle and index images to an image registry. 
```sh
make build-and-push-bundle-images \
  IMG=<some-registry>/ingress-node-firewall-controller:latest \
  BUNDLE_IMG=<some-registry>/ingress-node-firewall-bundle:latest \
  BUNDLE_INDEX_IMG=<some-registry>/ingress-node-firewall-index:latest
# or make podman-build-and-push-bundle-images \
#      IMG=<some-registry>/ingress-node-firewall-controller:latest \
#      BUNDLE_IMG=<some-registry>/ingress-node-firewall-bundle:latest \
#      BUNDLE_INDEX_IMG=<some-registry>/ingress-node-firewall-index:latest
```

8. Deploy with OLM
```sh
make deploy-with-olm \
  NAMESPACE=openshift-ingress-node-firewall \
  BUNDLE_INDEX_IMG=<some-registry>/ingress-node-firewall-index:latest
```

##### To uninstall

Undeploy resources from OCP cluster
```sh
oc delete ns openshift-ingress-node-firewall
```
Uninstall custom resource definitions
```sh
make uninstall
```

## Testing

### Running test

To run ingress-node-firewall-operator unit tests (no cluster required), execute the following:
```shell
make test
```
> NOTE: Some tests (e.g. `ebpfsyncer_test.go`) will only be triggered if `make test` is run as the root user. 

To test for race conditions, run:
```sh
make test-race
```

### Running E2E test

1. Bring up KinD cluster and deploy ingress node firewall operator from the steps outlined previously.
2. Run full E2E test
```shell
make test-e2e
```
Note: See test README.md for test options and known issues.

## Statistics

Statistics are generated by the BPF program when a packet is allowed or denied outputting the total packets allowed and
denied plus also the number of bytes handled. This statistics are captured in user space by the node daemons and exposed
as prometheus format metrics which are then scraped by prometheus on OCP. We do not deploy Prometheus with our KinD setup scripts
but the metrics will still be available to query from a service named `ingress-node-firewall-daemon-metrics` or from
within the node daemons themselves:
1. Exec into one of the node daemons
```sh
kubectl exec -n ${OPERATOR_NAMESPACE} -it ${NODE_DAEMON_NAME} sh
```
2. Retrieve the Prometheus formatted metrics
```sh
Curl 127.0.0.1:39301/metrics
```

Within OCP, you may use the OCP console to access the promql console to search for the following metrics:
- ingressnodefirewall_node_packet_allow_total
- ingressnodefirewall_node_packet_allow_bytes
- ingressnodefirewall_node_packet_deny_total
- ingressnodefirewall_node_packet_deny_bytes

## Useful commands and tricks

### Generating operator bundle

In order to generate an operator bundle, run the following:
```shell
make bundle
make manifests
```

### Building the DaemonSet image

This operator depends on the DaemonSet image. You can build this image and push it to your registry with:
```
make docker-build-daemon DAEMON_IMG=<registry>/<image>:<tag>
# or make podman-build-daemon DAEMON_IMG=<registry>/<image>:<tag>
make docker-push-daemon DAEMON_IMG=<registry>/<image>:<tag>
# or make podman-push-daemon DAEMON_IMG=<registry>/<image>:<tag>
```

### Running the operator locally

> NOTE: Running the operator like this shall be used for development purposes only.
> It may be helpful when making changes to and testing the main controller.
> However, there may be obstacles getting this to work with the DaemonSet.
> See [Running on a KinD cluster](README.md#running-on-a-kind-cluster) and
> [Running on an OCP cluster](README.md#running-on-an-ocp-cluster) for more reliable instructions.

1. Export your kubernetes credentials
2. Create the project and service account
```sh
oc new-project ingress-node-firewall-system
oc create sa ingress-node-firewall-daemon
oc adm policy add-scc-to-user privileged -z ingress-node-firewall-daemon
```

3. Run this operator locally with the following commands:
```sh
export DAEMONSET_IMAGE=<registry>/<image>:<tag>
export DAEMONSET_NAMESPACE=ingress-node-firewall-system
export KUBE_RBAC_PROXY_IMAGE=quay.io/openshift/origin-kube-rbac-proxy:latest
make install run
```

4. Create `IngressNodeFirewallConfig` CR.
