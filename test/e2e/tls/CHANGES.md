# TLS Adherence Configuration - Complete Implementation

## Summary

The `EnableTLSAdherence()` function now configures **BOTH** required components:

1. **FeatureGate CR**: Enables `TLSAdherence` feature via `CustomNoUpgrade`
2. **APIServer CR**: Sets TLS profile and adherence policy

## What Gets Configured

### 1. FeatureGate Configuration
```bash
oc patch featuregate cluster --type=merge \
  -p '{"spec":{"featureSet":"CustomNoUpgrade","customNoUpgrade":{"enabled":["TLSAdherence"]}}}'
```

**Effect**: Enables the `TLSAdherence` feature gate cluster-wide

### 2. APIServer Configuration (NEW!)
```bash
oc patch apiserver cluster --type=merge \
  -p '{"spec":{"tlsSecurityProfile":{"type":"Modern","modern":{}},"tlsAdherence":"StrictAllComponents"}}'
```

**Effect**: 
- Sets TLS profile to `Modern` (most secure)
- Sets adherence policy to `StrictAllComponents` (all components must comply)

## Code Changes

### Updated Functions

#### `EnableTLSAdherence(client *testclient.ClientSet) error`
- **Default behavior**: Calls `EnableTLSAdherenceWithProfile()` with:
  - TLS Profile: `"Modern"`
  - Adherence Policy: `"StrictAllComponents"`

#### `EnableTLSAdherenceWithProfile(client, tlsProfileType, tlsAdherencePolicy) error` (NEW!)
- **Flexible function** for custom configurations
- Supports TLS profile types:
  - `"Modern"` - Most secure (default)
  - `"Intermediate"` - Balanced security/compatibility
  - `"Old"` - Maximum compatibility
  - `"Custom"` - User-defined settings

## Execution Flow

```
Step 1: Patch FeatureGate to enable TLSAdherence feature
        ↓
Step 2: Patch APIServer with TLS profile and tlsAdherence policy  ← NEW STEP
        ↓
Step 3: Wait for MCP rollout to start (5 min timeout)
        ↓
Step 4: Wait for all MCPs to complete (30 min timeout)
        ↓
Step 5: Wait for cluster operators to settle (30 min timeout)
        ↓
Step 6: Wait for nodes to be ready (10 min timeout)
        ↓
Step 7: Verify TLSAdherence active in FeatureGate status (15 min timeout)
        ↓
Success ✓
```

## Usage Examples

### Example 1: Default Modern Profile (Recommended)
```go
Context("TLS Profile Compliance", func() {
    BeforeEach(func() {
        // Uses Modern profile + StrictAllComponents
        err := tls.EnableTLSAdherence(testclient.Client)
        Expect(err).NotTo(HaveOccurred())
    })
    
    It("should verify TLS compliance", func() {
        // Test code here
    })
})
```

### Example 2: Custom Profile Configuration
```go
Context("Custom TLS Profile", func() {
    BeforeEach(func() {
        // Use Intermediate profile instead
        err := tls.EnableTLSAdherenceWithProfile(
            testclient.Client,
            "Intermediate",  // TLS profile type
            "StrictAllComponents",  // Adherence policy
        )
        Expect(err).NotTo(HaveOccurred())
    })
})
```

## Verification

After running `EnableTLSAdherence()`, verify with:

```bash
# Run verification script
./test/e2e/tls/verify_config.sh
```

### Expected Output:

```
=== Verifying TLS Configuration ===

1. Checking FeatureGate 'cluster':
   Spec.FeatureSet: CustomNoUpgrade
   Spec.CustomNoUpgrade.Enabled: ["TLSAdherence"]

2. Checking APIServer 'cluster':
   Spec.TLSSecurityProfile.Type: Modern
   Spec.TLSAdherence: StrictAllComponents

3. Checking FeatureGate Status (TLSAdherence active):
   Cluster version: 4.21.x
   TLSAdherence in status:
   ✓ TLSAdherence

4. Checking Machine Config Pools:
   NAME     UPDATED  UPDATING  DEGRADED  MACHINES  READY  UPDATED_COUNT
   master   True     False     False     3         3      3
   worker   True     False     False     2         2      2

5. Checking Cluster Operators:
   All operators: Available=True, Progressing=False, Degraded=False

6. Checking Nodes:
   All nodes: Ready=True
```

## TLS Profile Types

| Profile | Security Level | Use Case |
|---------|---------------|----------|
| **Modern** | Highest | OCP 4.21+ (TLS 1.3 only) |
| **Intermediate** | Balanced | Mixed environment compatibility |
| **Old** | Lowest | Legacy system support |
| **Custom** | User-defined | Specific requirements |

## TLS Adherence Policies

| Policy | Description | Components Affected |
|--------|-------------|---------------------|
| **StrictAllComponents** | All components must comply | All cluster components |
| **LegacyAdheringComponentsOnly** | Only legacy components | Components that already honored profile |

## Implementation Details

### New Function: `patchAPIServerTLSProfile()`

**Location**: `test/e2e/tls/tls.go:157-207`

**Purpose**: Patches the APIServer CR to configure TLS profile and adherence policy

**Parameters**:
- `ctx`: Context
- `configClient`: OpenShift config client
- `tlsProfileType`: `"Modern"`, `"Intermediate"`, `"Old"`, or `"Custom"`
- `tlsAdherencePolicy`: `"StrictAllComponents"` or `"LegacyAdheringComponentsOnly"`

**What it does**:
1. Gets the current `apiserver cluster` CR
2. Sets `spec.tlsSecurityProfile` based on profile type
3. Sets `spec.tlsAdherence` to the adherence policy
4. Updates the APIServer CR

## Files Modified

1. **test/e2e/tls/tls.go**
   - Added `EnableTLSAdherenceWithProfile()` function
   - Modified `EnableTLSAdherence()` to call new function
   - Added `patchAPIServerTLSProfile()` helper function
   - Updated step numbering (now 7 steps instead of 6)

2. **test/e2e/tls/verify_config.sh** (NEW)
   - Verification script for manual checking
   - Validates both FeatureGate and APIServer configuration
   - Checks cluster stability (MCPs, operators, nodes)

3. **test/e2e/tls/CHANGES.md** (THIS FILE)
   - Documentation of changes

## Testing

```bash
# Compile check
go build -tags=e2etests ./test/e2e/tls/...

# Run test (requires active cluster)
go test -v -tags=e2etests \
  github.com/openshift/ingress-node-firewall/test/e2e/tls \
  -run TestEnableTLSAdherence \
  -timeout 60m
```

## Related Documentation

- OpenShift TLS Security Profiles: https://docs.openshift.com/container-platform/4.21/security/tls-security-profiles.html
- Feature Gates: https://docs.openshift.com/container-platform/4.21/nodes/clusters/nodes-cluster-enabling-features.html

## Next Steps

After enabling TLS adherence, you can:

1. ✅ Verify ingress-node-firewall TLS compliance
2. ✅ Verify multus-cni TLS compliance  
3. ✅ Verify ovn-kubernetes TLS compliance
4. ✅ Verify cluster-network-operator TLS compliance
5. ✅ Verify openshift-network-console TLS compliance

(Test implementations in `test/e2e/functional/tests/e2e.go`)
