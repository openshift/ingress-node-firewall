# ingress-node-firewall
This is Ingress node Firewall Operator, implementing [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/) for deploying Ingress node firewall daemon on kubernetes cluster.
It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/) 
which provides a reconcile function responsible for synchronizing resources untile the desired state is reached on the cluster 

## Prerequisites
Need to install the following packages:

operator-sdk 1.22.0

controller-gen v0.9.0+

## Usage
Once the Ingress node firewall Operator is installed, you have to create a `IngrNodeFwConfig` custom resource to deploy an instance. The operator will consume this resource and create ingress node firewall daemonset `daemon` based on it. The `IngrNodeFwConfig` custom resource needs to be created inside the `ingress-node-firewall-system` namespace and be named `ingressnodefirewallconfig`. Only one `IngrNodeFwConfig` resource can exist in a cluster.

Following is example of `IngrNodeFwConfig` resource:
```yaml
apiVersion: ingress-nodefw.ingress-nodefw/v1alpha1
kind: IngrNodeFwConfig
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
## Running test
to run ingress-node-firewall-operator unit tests (no cluster required), execute the following :
```shell
make test
```