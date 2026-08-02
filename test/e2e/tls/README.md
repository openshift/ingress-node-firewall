# Feature Gate Helper Package

This package provides helper functions for enabling and managing OpenShift FeatureGates in e2e tests.

## Overview

The `tls` package provides a comprehensive helper function `EnableTLSAdherence()` that handles the complete workflow of enabling the TLSAdherence feature gate and waiting for cluster stability.

## Usage

### In Your Tests

```go
import (
    "github.com/openshift/ingress-node-firewall/test/e2e/client"
    "github.com/openshift/ingress-node-firewall/test/e2e/tls"
)

Context("TLS Compliance Tests", func() {
    BeforeEach(func() {
        // Enable TLSAdherence feature gate and wait for complete cluster stability
        err := tls.EnableTLSAdherence(testclient.Client)
        Expect(err).NotTo(HaveOccurred())
    })

    It("should test TLS compliance", func() {
        // Your test code here
        // Cluster is now fully stable with TLSAdherence enabled
    })
})
```

## What `EnableTLSAdherence()` Does

The function performs the following steps automatically:

### Step 1: Patch FeatureGate
- Checks if TLSAdherence is already enabled
- If not, patches the FeatureGate resource to enable CustomNoUpgrade with TLSAdherence
- Handles both fresh clusters and clusters with existing CustomNoUpgrade settings

### Step 2: Wait for MCP Rollout to Start
- Polls Machine Config Pools (MCPs) until at least one enters "Updating" state
- Timeout: 5 minutes
- Ensures the feature gate change has triggered node configuration updates

### Step 3: Wait for MCP Rollout to Complete
- Waits for ALL Machine Config Pools to complete their rollout
- Checks: `Updated=True` AND `UpdatedMachineCount == MachineCount`
- Timeout: 30 minutes per MCP
- Skips MCPs with 0 machines

### Step 4: Wait for Cluster Operators to Settle
- Waits for ALL cluster operators to be healthy
- Checks for each operator:
  - `Available = True`
  - `Degraded = False`
  - `Progressing = False`
- Timeout: 30 minutes
- Logs unsettled operators during polling

### Step 5: Wait for Nodes to be Ready
- Waits for ALL nodes to report `Ready=True`
- Timeout: 10 minutes
- Ensures all nodes have successfully applied the new configuration

### Step 6: Verify TLSAdherence is Active
- Verifies TLSAdherence appears in `.status.featureGates[].enabled[]`
- Checks against the current cluster version
- Timeout: 15 minutes
- Ensures the feature gate is not just enabled in spec, but active in status

## Function Signature

```go
func EnableTLSAdherence(client *testclient.ClientSet) error
```

### Parameters
- `client`: The test client set containing the cluster configuration

### Returns
- `error`: Returns an error if any step fails, nil on success

## Error Handling

The function provides detailed error messages at each step:

```go
err := tls.EnableTLSAdherence(testclient.Client)
if err != nil {
    // Error message will indicate which step failed:
    // - "failed to get tls"
    // - "failed to update tls"
    // - "MCP <name> did not complete"
    // - "cluster operators not settled"
    // - "nodes not stable"
    // - "TLSAdherence not active"
}
```

## Logging

The function logs progress at each step using `log.Printf()`:

```
=== Starting TLSAdherence feature gate enablement ===
Step 1: Patching FeatureGate to enable TLSAdherence
✓ Feature gate patched successfully
Step 2: Waiting for MCP rollout to start
MCP master has started updating
✓ MCP rollout started
Step 3: Waiting for MCP rollout to complete
Waiting for MCP master (3 machines) to complete
MCP master: 1/3 machines updated, Updated=false (waiting...)
MCP master: 2/3 machines updated, Updated=false (waiting...)
MCP master: 3/3 machines updated, Updated=true (waiting...)
✓ MCP master: 3/3 machines updated
Waiting for MCP worker (2 machines) to complete
✓ MCP worker: 2/2 machines updated
✓ All MCPs updated successfully
Step 4: Waiting for all cluster operators to settle
✓ All cluster operators settled
Step 5: Waiting for all nodes to be ready and stable
All 5 nodes are ready
✓ All nodes are ready and stable
Step 6: Verifying TLSAdherence is active in feature gate status
✓ TLSAdherence is active in feature gate status
=== TLSAdherence feature gate successfully enabled and cluster is stable ===
```

## Helper Functions

### `IsTLSAdherenceEnabled()`

Check if TLSAdherence is enabled without waiting:

```go
func IsTLSAdherenceEnabled(configClient configv1client.Interface) (bool, error)
```

**Usage:**
```go
configClient, _ := configv1client.NewForConfig(client.Config)
enabled, err := tls.IsTLSAdherence Enabled(configClient)
if err != nil {
    // Handle error
}
if enabled {
    // TLSAdherence is enabled
}
```

## Implementation Details

### Internal Functions

- `isAlreadyEnabled()`: Checks spec for TLSAdherence
- `patchFeatureGate()`: Patches the FeatureGate resource
- `waitForMCPRolloutStart()`: Polls for MCP Updating condition
- `waitForAllMCPsComplete()`: Waits for all MCPs
- `waitForMCPComplete()`: Waits for a specific MCP
- `waitForOperatorsToSettle()`: Polls cluster operators
- `getOperatorConditions()`: Extracts operator conditions
- `waitForNodesStability()`: Polls node Ready conditions
- `isNodeReady()`: Checks if a node is Ready
- `verifyTLSAdherenceActive()`: Verifies in feature gate status
- `verifyClusterStability()`: Re-verifies when already enabled

## Why This Is Important

Feature gate changes are **disruptive operations** that affect the entire cluster:

1. **MCP Rollout** - Nodes restart with new machine configuration
2. **Operator Reconciliation** - Many operators reconcile due to new feature gate
3. **API Server Changes** - New APIs may become available
4. **Network Configuration** - TLS settings affect network components

**Without proper health checks**, tests may:
- ❌ Run against an unstable cluster
- ❌ Get false positives/negatives
- ❌ Experience flaky test results
- ❌ Miss actual bugs due to cluster instability

**With this helper**, tests:
- ✅ Run only when cluster is fully stable
- ✅ Have reliable, reproducible results
- ✅ Properly test TLS compliance
- ✅ Catch real issues

## Timeouts Summary

| Step | Timeout | Interval |
|------|---------|----------|
| MCP Rollout Start | 5 minutes | 10 seconds |
| MCP Rollout Complete | 30 minutes per MCP | 30 seconds |
| Operators Settle | 30 minutes | 10 seconds |
| Nodes Ready | 10 minutes | 30 seconds |
| TLSAdherence Active | 15 minutes | 15 seconds |

**Total Maximum Time**: ~75 minutes (worst case, all timeouts exhausted)  
**Typical Time**: 10-20 minutes (depending on cluster size and performance)

## Testing

The helper has been modeled after production-tested code from:
- `origin/test/extended/util/operator/settle.go`
- `origin/test/extended/machine_config/helpers.go`
- `release/ci-operator/step-registry/tls-13/tls-13-commands.sh`

## Dependencies

```go
import (
    configv1 "github.com/openshift/api/config/v1"
    mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
    configv1client "github.com/openshift/client-go/config/clientset/versioned"
    machineconfigclient "github.com/openshift/client-go/machineconfiguration/clientset/versioned"
    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/util/wait"
)
```

These dependencies should already be available in the ingress-node-firewall test suite.
