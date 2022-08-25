# ingress-node-firewall
This is Ingress node Firewall Operator, implementing [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/) for deploying Ingress node firewall daemon on kubernetes cluster.
It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/)
which provides a reconcile function responsible for synchronizing resources untile the desired state is reached on the cluster

## Prerequisites
Need to install the following packages:

operator-sdk 1.22.0

controller-gen v0.9.0+

For fedora, you will need the following packages
```sh
sudo dnf install glibc-devel glibc-devel.i686
```

## Building the DaemonSet image

This operator depends on the DaemonSet image. You can build this image and push it to your registry with:
```
make podman-build-daemon DAEMON_IMG=<registry>/<image>:<tag>
make podman-push-daemon DAEMON_IMG=<registry>/<image>:<tag>
```
> If you are using docker, replace `podman-build-daemon` with `docker-build-daemon` and `podman-push-daemon` with `docker-push-daemon`.

## Running the operator locally

First, export your kubernetes credentials. Then, you can run this cluster locally with the following command:
```
export DAEMONSET_IMAGE=<registry>/<image>:<tag>
export DAEMONSET_NAMESPACE=ingress-node-firewall-system
make install run
```

## Usage

Once the Ingress Node Firewall Operator is installed, you have to create a `IngressNodeFirewallConfig` custom resource to deploy the Operator's DaemonSet.
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
  tolerations:
  - key: "Example"
    operator: "Exists"
    effect: "NoExecute"
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

## Running test

to run ingress-node-firewall-operator unit tests (no cluster required), execute the following :
```shell
make test
```
## Generating operator bundle

In order to generate an operator bundle, run the following:
```shell
make bundle
```
## Running on a KinD cluster
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
8. Manually edit "config/manager/env.yaml" and add the daemon image to value of environment variable "DAEMONSET_IMAGE"
9. Deploy resources to KinD cluster
```sh
make deploy-kind IMG=<some-registry>/ingress-node-firewall-controller:latest
```
7. Undeploy resources from KinD cluster
```sh
make undeploy-kind
```
8. Uninstall custom resource definitions
```sh
make uninstall
```

## Running on an OCP cluster
1. Create OCP cluster
2. Install custom resource definitions
```sh
make install
```
3. Build controller container image
```sh
make docker-build IMG=<some-registry>/ingress-node-firewall-controller:latest
```
4. Push controller container image to an image registry
```sh
make docker-push IMG=<some-registry>/ingress-node-firewall-controller:latest
```
5. Build daemon container image
```sh
make docker-build-daemon DAEMON_IMG=<some-registry>/ingress-node-firewall-daemom:latest
```
6. Push controller container image to an image registry
```sh
make docker-push-daemon DAEMON_IMG=<some-registry>/ingress-node-firewall-daemom:latest
```
7. Manually edit "config/manager/env.yaml" and add the daemon image name to value of environment variable "DAEMONSET_IMAGE"
8. make deploy IMG=<some-registry>/ingress-node-firewall-controller:latest
9. Undeploy resources from OCP cluster
```sh
make undeploy
```
10. Uninstall custom resource definitions
```sh
make uninstall
```

## Disable webhook
Remove manager binary flag `--enable-webhook` from the containers command in file config/manager/manager.yaml

## Running E2E test
1. Bring up KinD cluster and deploy ingress node firewall operator from the steps outlined previous
2. Run full E2E test
```shell
make test-e2e
```

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
2. Retrieve the prometheus formatted metrics
```sh
Curl 127.0.0.1:39301/metrics
```

Within OCP, you may use the OCP console to access the promql console to search for the following metrics:
- ingressnodefirewall_node_packet_allow_total
- ingressnodefirewall_node_packet_allow_bytes
- ingressnodefirewall_node_packet_deny_total
- ingressnodefirewall_node_packet_deny_bytes