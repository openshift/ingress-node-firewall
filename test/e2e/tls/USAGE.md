# Feature Gate Helper - Usage Guide

## Public Functions

### 1. `EnableTLSAdherence()` - Complete TLS Feature Gate Enablement

Enable TLSAdherence feature gate and wait for complete cluster stability.

```go
func EnableTLSAdherence(client *testclient.ClientSet) error
```

**Usage:**
```go
import (
    "github.com/openshift/ingress-node-firewall/test/e2e/tls"
)

BeforeEach(func() {
    err := tls.EnableTLSAdherence(testclient.Client)
    Expect(err).NotTo(HaveOccurred())
})
```

**What it does:**
1. ✅ Patches FeatureGate to enable TLSAdherence
2. ✅ Waits for MCP rollout (start + complete)
3. ✅ Waits for all cluster operators to settle
4. ✅ Waits for all nodes to be ready
5. ✅ Verifies TLSAdherence is active in status

---

### 2. `WaitForClusterStability()` - ⭐ REUSABLE Cluster Stability Wait

**This is the MOST REUSABLE function** - use it after ANY disruptive cluster operation!

```go
func WaitForClusterStability(client *testclient.ClientSet) error
```

**Use cases:**
- ✅ After changing TLS profiles
- ✅ After enabling/disabling ANY feature gate
- ✅ After modifying cluster configuration
- ✅ After ANY operation that triggers MCP updates

**What it does:**
1. Waits for MCP rollout to start (5 min timeout)
2. Waits for all MCPs to complete (30 min timeout)
3. Waits for all cluster operators to settle (30 min timeout)
4. Waits for all nodes to be ready (10 min timeout)

#### Example 1: After Changing TLS Profile

```go
It("should apply Modern TLS profile", func() {
    // Change TLS profile
    err := oc.Run("patch").Args("apiserver", "cluster", "--type=merge",
        "-p", `{"spec":{"tlsSecurityProfile":{"type":"Modern","modern":{}}}}`).Execute()
    Expect(err).NotTo(HaveOccurred())

    // Wait for cluster stability
    err = tls.WaitForClusterStability(testclient.Client)
    Expect(err).NotTo(HaveOccurred())

    // Now cluster is stable and ready for TLS compliance tests
    // ... your test logic here ...
})
```

#### Example 2: After Enabling TechPreviewNoUpgrade

```go
It("should enable TechPreview features", func() {
    // Enable TechPreviewNoUpgrade
    err := oc.Run("patch").Args("tls", "cluster", "--type=merge",
        "-p", `{"spec":{"featureSet":"TechPreviewNoUpgrade"}}`).Execute()
    Expect(err).NotTo(HaveOccurred())

    // Wait for cluster stability
    err = tls.WaitForClusterStability(testclient.Client)
    Expect(err).NotTo(HaveOccurred())

    // Cluster is now stable with TechPreview features enabled
})
```

#### Example 3: In Your TLS Tests

```go
Context("TLS Profile Compliance", func() {
    BeforeEach(func() {
        // Enable TLSAdherence feature gate
        err := tls.EnableTLSAdherence(testclient.Client)
        Expect(err).NotTo(HaveOccurred())
    })

    Context("Modern TLS Profile", func() {
        BeforeEach(func() {
            // Apply Modern TLS profile
            err := oc.Run("patch").Args("apiserver", "cluster", "--type=merge",
                "-p", `{"spec":{"tlsSecurityProfile":{"type":"Modern"}}}`).Execute()
            Expect(err).NotTo(HaveOccurred())

            // Wait for cluster stability after TLS profile change
            err = tls.WaitForClusterStability(testclient.Client)
            Expect(err).NotTo(HaveOccurred())
        })

        It("should verify ingress-node-firewall TLS compliance", func() {
            // Test TLS compliance
        })
    })

    Context("Custom TLS Profile", func() {
        BeforeEach(func() {
            // Apply Custom TLS profile
            err := oc.Run("patch").Args("apiserver", "cluster", "--type=merge",
                "-p", `{"spec":{"tlsSecurityProfile":{"type":"Custom","custom":{"minTLSVersion":"VersionTLS12"}}}}`).Execute()
            Expect(err).NotTo(HaveOccurred())

            // Wait for cluster stability after TLS profile change
            err = tls.WaitForClusterStability(testclient.Client)
            Expect(err).NotTo(HaveOccurred())
        })

        It("should verify ingress-node-firewall TLS compliance", func() {
            // Test TLS compliance
        })
    })
})
```

---

### 3. `IsTLSAdherenceEnabled()` - Quick Check

Check if TLSAdherence is enabled without waiting.

```go
func IsTLSAdherenceEnabled(configClient configv1client.Interface) (bool, error)
```

**Usage:**
```go
configClient, _ := configv1client.NewForConfig(client.Config)
enabled, err := tls.IsTLSAdherenceEnabled(configClient)
if err != nil {
    log.Fatalf("Failed to check TLSAdherence: %v", err)
}

if enabled {
    log.Println("TLSAdherence is enabled")
} else {
    log.Println("TLSAdherence is NOT enabled")
}
```

---

## Comparison: When to Use Which Function

| Function | Use Case | Enables Feature Gate? | Waits for Stability? |
|----------|----------|----------------------|---------------------|
| `EnableTLSAdherence()` | Enable TLSAdherence feature gate | ✅ Yes | ✅ Yes |
| `WaitForClusterStability()` | After ANY cluster config change | ❌ No | ✅ Yes |
| `IsTLSAdherenceEnabled()` | Quick check without waiting | ❌ No | ❌ No |

---

## Why `WaitForClusterStability()` is Reusable

### Problem It Solves:

Many cluster configuration changes are **disruptive** and trigger:
1. MCP rollouts (nodes restart)
2. Operator reconciliation
3. Pod restarts
4. Configuration propagation

**Without waiting for stability**, tests will:
- ❌ Run against unstable cluster
- ❌ Get flaky results
- ❌ Experience false positives/negatives

### Solution:

`WaitForClusterStability()` provides a **single, reusable** function that properly waits for:
- ✅ All MCPs to complete rollout
- ✅ All operators to be healthy
- ✅ All nodes to be ready

### When to Use It:

**After ANY of these operations:**
- Changing feature gates
- Changing TLS profiles
- Modifying APIServer configuration
- Updating cluster-wide settings
- Any `oc patch` on cluster-scoped resources that triggers MCO

### When NOT to Use It:

**Do NOT use after:**
- Creating pods/deployments (not cluster-wide)
- Namespaced resource changes
- Operations that don't affect nodes/operators

---

## Logging Output

### `EnableTLSAdherence()`

```
=== Starting TLSAdherence feature gate enablement ===
Step 1: Patching FeatureGate to enable TLSAdherence
✓ Feature gate patched successfully
=== Waiting for cluster stability ===
Step 1: Waiting for MCP rollout to start
✓ MCP rollout started
Step 2: Waiting for MCP rollout to complete
✓ MCP master: 3/3 machines updated
✓ MCP worker: 2/2 machines updated
✓ All MCPs updated successfully
Step 3: Waiting for all cluster operators to settle
✓ All cluster operators settled
Step 4: Waiting for all nodes to be ready and stable
✓ All nodes are ready and stable
=== Cluster is stable ===
Step 6: Verifying TLSAdherence is active in feature gate status
✓ TLSAdherence is active in feature gate status
=== TLSAdherence feature gate successfully enabled and cluster is stable ===
```

### `WaitForClusterStability()`

```
=== Waiting for cluster stability ===
Step 1: Waiting for MCP rollout to start
✓ MCP rollout started
Step 2: Waiting for MCP rollout to complete
✓ MCP master: 3/3 machines updated
✓ MCP worker: 2/2 machines updated
✓ All MCPs updated successfully
Step 3: Waiting for all cluster operators to settle
✓ All cluster operators settled
Step 4: Waiting for all nodes to be ready and stable
✓ All nodes are ready and stable
=== Cluster is stable ===
```

---

## Timeouts

| Step | Timeout | Interval |
|------|---------|----------|
| MCP Rollout Start | 5 minutes | 10 seconds |
| MCP Rollout Complete | 30 minutes per MCP | 30 seconds |
| Operators Settle | 30 minutes | 10 seconds |
| Nodes Ready | 10 minutes | 30 seconds |
| TLSAdherence Active | 15 minutes | 15 seconds |

**Typical execution time:** 10-20 minutes  
**Maximum time:** ~75 minutes (all timeouts exhausted)

---

## Error Handling

All functions return detailed errors:

```go
err := tls.WaitForClusterStability(testclient.Client)
if err != nil {
    // Error messages indicate which step failed:
    // - "failed to create config client"
    // - "MCP master did not complete"
    // - "cluster operators not settled: network is Degraded"
    // - "nodes not stable: node-1 is NotReady"
}
```

---

## Best Practices

### ✅ DO:

```go
// Use WaitForClusterStability after cluster config changes
oc.Run("patch").Args(...).Execute()
err := tls.WaitForClusterStability(testclient.Client)
Expect(err).NotTo(HaveOccurred())
```

### ❌ DON'T:

```go
// Don't assume cluster is stable immediately after config change
oc.Run("patch").Args(...).Execute()
// Run tests immediately ← BAD! Cluster is not stable yet
```

### ✅ DO:

```go
// Use EnableTLSAdherence ONCE in parent BeforeEach
Context("TLS Tests", func() {
    BeforeEach(func() {
        err := tls.EnableTLSAdherence(testclient.Client)
        Expect(err).NotTo(HaveOccurred())
    })
    // ... child contexts ...
})
```

### ❌ DON'T:

```go
// Don't enable TLSAdherence multiple times
Context("Test 1", func() {
    BeforeEach(func() {
        tls.EnableTLSAdherence(testclient.Client) // ← First time
    })
})
Context("Test 2", func() {
    BeforeEach(func() {
        tls.EnableTLSAdherence(testclient.Client) // ← Wasteful! Already enabled
    })
})
```

---

## Summary

✅ **`EnableTLSAdherence()`** - Use when you need to enable TLSAdherence feature gate  
✅ **`WaitForClusterStability()`** - ⭐ REUSABLE - Use after ANY disruptive cluster operation  
✅ **`IsTLSAdherenceEnabled()`** - Use for quick checks without waiting  

The **most important** takeaway: **`WaitForClusterStability()` is your friend** for ANY test that modifies cluster-wide configuration!
