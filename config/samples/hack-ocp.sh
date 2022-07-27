#!/bin/bash

NAMESPACE=ingress-node-firewall-system

oc new-project ${NAMESPACE} || oc project ${NAMESPACE}
oc adm policy add-scc-to-user privileged -z daemon

cat <<EOF | oc apply -f -
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  creationTimestamp: null
  name: daemon
  namespace: ${NAMESPACE}
rules:
- apiGroups:
  - ingress-nodefw.ingress-nodefw
  resources:
  - ingressnodefirewallnodestates
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - ingress-nodefw.ingress-nodefw
  resources:
  - ingressnodefirewallnodestates/finalizers
  verbs:
  - update
- apiGroups:
  - ingress-nodefw.ingress-nodefw
  resources:
  - ingressnodefirewallnodestates/status
  verbs:
  - get
  - patch
  - update
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: daemon
  namespace: ${NAMESPACE}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: daemon
subjects:
- kind: ServiceAccount
  name: daemon
  namespace: ${NAMESPACE}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: daemon
  namespace: ${NAMESPACE}
EOF
