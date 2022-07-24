#!/bin/bash

# todo: how to scaffold best?

oc project ingress-node-firewall
oc adm policy add-scc-to-user privileged -z daemon
