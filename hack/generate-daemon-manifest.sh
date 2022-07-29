#!/bin/bash
MANIFEST_FILE="daemonset.yaml"
MANIFEST_PATH="bindata/manifests/daemon"

if ! command -v yq &> /dev/null
then
    echo "yq binary not found, installing... "
    go install -mod='' github.com/mikefarah/yq/v4@v4.13.3
fi

yq e --inplace '. | (select(.kind == "DaemonSet" and .metadata.name == "ingress-node-firewall-daemon") | .spec.template.spec.containers[] | select(.name == "daemon").image)|="{{.Image}}"' ${MANIFEST_PATH}/${MANIFEST_FILE}
