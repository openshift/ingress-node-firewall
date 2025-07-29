#!/bin/bash

yum install jq git wget -y
cd /tmp/ingress-node-firewall-operator-deploy

wget https://github.com/operator-framework/operator-registry/releases/download/v1.23.0/linux-amd64-opm
mv linux-amd64-opm opm
chmod +x ./opm
pass=$( jq .\"image-registry.openshift-image-registry.svc:5000\".auth /var/run/secrets/openshift.io/push/.dockercfg )
pass=`echo ${pass:1:-1} | base64 -d`
podman login -u serviceaccount -p ${pass:8} image-registry.openshift-image-registry.svc:5000 --tls-verify=false

podman build -f bundle.Dockerfile --tag image-registry.openshift-image-registry.svc:5000/openshift-marketplace/ingress-node-firewall-operator-bundle:latest .
podman push image-registry.openshift-image-registry.svc:5000/openshift-marketplace/ingress-node-firewall-operator-bundle:latest --tls-verify=false

./opm index --skip-tls add --bundles image-registry.openshift-image-registry.svc:5000/openshift-marketplace/ingress-node-firewall-operator-bundle:latest --tag image-registry.openshift-image-registry.svc:5000/openshift-marketplace/ingress-node-firewall-operator-index:latest -p podman --mode semver
podman push image-registry.openshift-image-registry.svc:5000/openshift-marketplace/ingress-node-firewall-operator-index:latest --tls-verify=false
