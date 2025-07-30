#!/usr/bin/bash

set -eu
set -o pipefail

ingress_node_firewall_dir="$(dirname "$(readlink -f "$0")")"
source "${ingress_node_firewall_dir}"/common.sh

INGRESS_NODE_FIREWALL_IMAGE_BASE=${INGRESS_NODE_FIREWALL_IMAGE_BASE:-$(echo "${OPENSHIFT_RELEASE_IMAGE}" | sed -e 's/release/stable/g' | sed -e 's/@.*$//g')}
INGRESS_NODE_FIREWALL_IMAGE_TAG=${INGRESS_NODE_FIREWALL_IMAGE_TAG:-"ingress-node-firewall"}
INGRESS_NODE_FIREWALL_DAEMON_IMAGE_TAG=${INGRESS_NODE_FIREWALL_DAEMON_IMAGE_TAG:-"ingress-node-firewall-daemon"}
export NAMESPACE=${NAMESPACE:-"openshift-ingress-node-firewall"}

rm -f ingress-node-firewall-operator-deploy/bundle.Dockerfile
rm -rf ingress-node-firewall-operator-deploy/bundle

cp ../bundle.Dockerfile ingress-node-firewall-operator-deploy 
cp -r ../bundle/ ingress-node-firewall-operator-deploy/bundle 

cd ingress-node-firewall-operator-deploy || exit

ESCAPED_OPERATOR_IMAGE=$(printf '%s\n' "${INGRESS_NODE_FIREWALL_IMAGE_BASE}:${INGRESS_NODE_FIREWALL_IMAGE_TAG}" | sed -e 's/[]\/$*.^[]/\\&/g');
find . -type f -name "*clusterserviceversion*.yaml" -exec sed -i 's/quay.io\/openshift\/origin-ingress-node-firewall:.*$/'"$ESCAPED_OPERATOR_IMAGE"'/g' {} +
ESCAPED_DAEMON_IMAGE=$(printf '%s\n' "${INGRESS_NODE_FIREWALL_IMAGE_BASE}:${INGRESS_NODE_FIREWALL_DAEMON_IMAGE_TAG}" | sed -e 's/[]\/$*.^[]/\\&/g');
find . -type f -name "*clusterserviceversion*.yaml" -exec sed -i 's/quay.io\/openshift\/origin-ingress-node-firewall-daemon:.*$/'"$ESCAPED_DAEMON_IMAGE"'/g' {} +

cd - || exit

oc label ns openshift-marketplace --overwrite pod-security.kubernetes.io/enforce=privileged
oc patch OperatorHub cluster --type json \
    -p '[{"op": "add", "path": "/spec/disableAllDefaultSources", "value": true}]'
secret=$(oc -n openshift-marketplace get sa builder -oyaml | grep imagePullSecrets -A 1 | grep -o "builder-.*")

buildindexpod="apiVersion: v1
kind: Pod
metadata:
  name: buildindex
  namespace: openshift-marketplace
spec:
  restartPolicy: Never
  serviceAccountName: builder
  containers:
    - name: priv
      image: quay.io/podman/stable
      command:
        - /bin/bash
        - -c
        - |
          set -xe
          sleep INF
      securityContext:
        privileged: true
      volumeMounts:
        - mountPath: /var/run/secrets/openshift.io/push
          name: dockercfg
          readOnly: true
  volumes:
    - name: dockercfg
      defaultMode: 384
      secret:
        secretName: $secret
"

echo "$buildindexpod" | oc apply -f -

success=0
iterations=0
sleep_time=10
max_iterations=72 # results in 12 minutes timeout
until [[ $success -eq 1 ]] || [[ $iterations -eq $max_iterations ]]
do
  run_status=$(oc -n openshift-marketplace get pod buildindex -o json | jq '.status.phase' | tr -d '"')
  if [ "$run_status" == "Running" ]; then
    success=1
    break
  fi
  iterations=$((iterations+1))
  sleep $sleep_time
done

oc cp ingress-node-firewall-operator-deploy openshift-marketplace/buildindex:/tmp
oc exec -n openshift-marketplace buildindex /tmp/ingress-node-firewall-operator-deploy/build_and_push_index.sh

oc apply -f ingress-node-firewall-operator-deploy/install-resources.yaml

# there is a race in the creation of the pod and the service account that prevents
# the index image to be pulled. Here we check if the pod is not running and we kill it. 
success=0
iterations=0
sleep_time=10
max_iterations=72 # results in 12 minutes timeout
until [[ $success -eq 1 ]] || [[ $iterations -eq $max_iterations ]]
do
  run_status=$(oc -n openshift-marketplace get pod | grep ingress-node-firewall-operator-index | awk '{print $3}')
  if [ "$run_status" == "Running" ]; then
    success=1
    break
  elif [[ "$run_status" == *"Image"*  ]]; then
    echo "pod in bad status try to recreate the image again status: $run_status"
    pod_name=$(oc -n openshift-marketplace get pod | grep ingress-node-firewall-operator-index | awk '{print $1}')
    oc -n openshift-marketplace delete po "$pod_name"
  fi
  iterations=$((iterations+1))
  sleep $sleep_time
done

if [[ $success -eq 1 ]]; then
  echo "[INFO] index image pod running"
else
  echo "[ERROR] index image pod failed to run"
  exit 1
fi

./wait_for_csv.sh

oc label ns openshift-marketplace --overwrite pod-security.kubernetes.io/enforce=baseline

oc apply -f - <<EOF
apiVersion: ingressnodefirewall.openshift.io/v1alpha1
kind: IngressNodeFirewallConfig
metadata:
  name: ingressnodefirewallconfig
  namespace: "${NAMESPACE}"
spec:
  nodeSelector:
    node-role.kubernetes.io/worker: ""
  tolerations:
  - key: "Example"
    operator: "Exists"
    effect: "NoExecute"
EOF

ds_ready=false
iterations=0
sleep_time=10
max_iterations=72 # results in 12 minutes timeout
until $ds_ready
do
  desired_ds_num=$(oc get ds -n "$NAMESPACE" ingress-node-firewall-daemon -o jsonpath="{.status.desiredNumberScheduled}")
  ready_ds_num=$(oc get ds -n "$NAMESPACE" ingress-node-firewall-daemon -o jsonpath="{.status.numberReady}")
  if [ "${desired_ds_num}" -gt 1 ] && [ "${ready_ds_num}" -eq "${desired_ds_num}" ]; then
    echo "daemonset ready"
    ds_ready=true
  else    
    echo "still waiting for daemonset"
    sleep $sleep_time
    iterations=$((iterations+1))
    if [ "$iterations" -eq "$max_iterations" ]; then
      echo "failed waiting for daemonset"
      exit 1
    fi
  fi
done
