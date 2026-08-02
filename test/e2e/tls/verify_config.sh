#!/bin/bash
# Verify TLS configuration after EnableTLSAdherence()

set -euo pipefail

echo "=== Verifying TLS Configuration ==="
echo ""

# 1. Check FeatureGate
echo "1. Checking FeatureGate 'cluster':"
echo "   Spec.FeatureSet:"
oc get featuregate cluster -o jsonpath='{.spec.featureSet}' && echo ""
echo "   Spec.CustomNoUpgrade.Enabled:"
oc get featuregate cluster -o jsonpath='{.spec.customNoUpgrade.enabled}' && echo ""
echo ""

# 2. Check APIServer
echo "2. Checking APIServer 'cluster':"
echo "   Spec.TLSSecurityProfile.Type:"
oc get apiserver cluster -o jsonpath='{.spec.tlsSecurityProfile.type}' && echo ""
echo "   Spec.TLSAdherence:"
oc get apiserver cluster -o jsonpath='{.spec.tlsAdherence}' && echo ""
echo ""

# 3. Check FeatureGate Status
echo "3. Checking FeatureGate Status (TLSAdherence active):"
VERSION=$(oc get clusterversion version -o jsonpath='{.status.desired.version}')
echo "   Cluster version: ${VERSION}"
echo "   TLSAdherence in status:"
oc get featuregate cluster -o json | \
  jq -r --arg v "${VERSION}" '.status.featureGates[] | select(.version == $v) | .enabled[] | select(.name == "TLSAdherence") | "   ✓ " + .name' || echo "   ✗ Not found"
echo ""

# 4. Check MCP Status
echo "4. Checking Machine Config Pools:"
oc get mcp -o custom-columns=\
NAME:.metadata.name,\
UPDATED:.status.conditions[?\(@.type==\"Updated\"\)].status,\
UPDATING:.status.conditions[?\(@.type==\"Updating\"\)].status,\
DEGRADED:.status.conditions[?\(@.type==\"Degraded\"\)].status,\
MACHINES:.status.machineCount,\
READY:.status.readyMachineCount,\
UPDATED_COUNT:.status.updatedMachineCount
echo ""

# 5. Check Cluster Operators
echo "5. Checking Cluster Operators (should all be Available, Not Degraded, Not Progressing):"
oc get co -o custom-columns=\
NAME:.metadata.name,\
AVAILABLE:.status.conditions[?\(@.type==\"Available\"\)].status,\
PROGRESSING:.status.conditions[?\(@.type==\"Progressing\"\)].status,\
DEGRADED:.status.conditions[?\(@.type==\"Degraded\"\)].status | \
  head -20
echo ""

# 6. Check Nodes
echo "6. Checking Nodes:"
oc get nodes -o custom-columns=\
NAME:.metadata.name,\
STATUS:.status.conditions[?\(@.type==\"Ready\"\)].status,\
ROLES:.metadata.labels.node-role\\.kubernetes\\.io/*
echo ""

echo "=== Configuration Verification Complete ==="
