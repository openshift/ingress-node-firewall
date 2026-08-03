# TLS Profile Compliance Test Structure - Final

**Date:** 2026-08-03  
**Status:** ✅ Implemented and Configured

---

## Overview

The TLS Profile Compliance test suite has been organized with three test contexts, with the focus on **Modern TLS Profile with LegacyAdheringComponentsOnly** testing.

---

## Test Execution Order

### 1. Modern TLS Profile with LegacyAdheringComponentsOnly ⭐ **ACTIVE**

**Location:** `test/e2e/functional/tests/e2e.go:1154`  
**Status:** ✅ **Enabled and Running**

**Components:**
- ✅ **ingress-node-firewall** - Implemented and tested
- ⏳ multus-cni - TODO
- ⏳ ovn-kubernetes - TODO
- ⏳ cluster-network-operator - TODO
- ⏳ openshift-network-console - TODO

**Test Behavior:**
```
Modern with LegacyAdheringComponentsOnly:
- TLS 1.3 connections: ✅ SHOULD WORK
- TLS 1.2 connections: ✅ SHOULD WORK (legacy allowed)
- TLS 1.1 connections: ❌ SHOULD FAIL
```

**BeforeEach Configuration:**
```go
err := tls.EnableTLSAdherenceWithProfile(testclient.Client, "Modern", "LegacyAdheringComponentsOnly")
```

---

### 2. Modern TLS Profile with StrictAllComponents ⏸️ **SKIPPED**

**Location:** `test/e2e/functional/tests/e2e.go:1216`  
**Status:** ⏸️ **Skipped** (focusing on LegacyAdheringComponentsOnly)

**Skip Reason:**
```go
Skip("Skipping Modern TLS Profile with StrictAllComponents tests")
```

**Components:**
- ⏸️ ingress-node-firewall - Implemented but skipped
- ⏸️ multus-cni - Implemented but skipped
- ⏸️ ovn-kubernetes - Implemented but skipped
- ⏸️ cluster-network-operator - Implemented but skipped
- ⏸️ openshift-network-console - Implemented but skipped

**Test Behavior (when enabled):**
```
Modern with StrictAllComponents:
- TLS 1.3 connections: ✅ SHOULD WORK
- TLS 1.2 connections: ❌ SHOULD FAIL (strict enforcement)
- TLS 1.1 connections: ❌ SHOULD FAIL
```

---

### 3. Custom TLS Profile ⏸️ **SKIPPED**

**Location:** `test/e2e/functional/tests/e2e.go:1340`  
**Status:** ⏸️ **Skipped** (focusing on LegacyAdheringComponentsOnly)

**Skip Reason:**
```go
Skip("Skipping Custom TLS Profile tests")
```

**Components:**
- ⏸️ ingress-node-firewall - Implemented but skipped
- ⏸️ multus-cni - TODO
- ⏸️ ovn-kubernetes - TODO
- ⏸️ cluster-network-operator - TODO
- ⏸️ openshift-network-console - TODO

**Test Behavior (when enabled):**
```
Custom Profile (minTLSVersion=VersionTLS12):
- TLS 1.3 connections: ✅ SHOULD WORK
- TLS 1.2 connections: ✅ SHOULD WORK
- TLS 1.1 connections: ❌ SHOULD FAIL
```

---

## Complete Test Hierarchy

```
Describe("Ingress Node Firewall")
└── Context("Disruption")
    └── Context("TLS Profile Compliance")
        │
        ├── BeforeEach() ────────────────────────────────────┐
        │   └── Check if OpenShift cluster                    │ RUNS ONCE
        │       └── Skip if not OpenShift                      │ (Quick check)
        │
        ├── Context("Modern TLS Profile with LegacyAdheringComponentsOnly") ⭐ ACTIVE
        │   ├── BeforeEach() ────────────────────────────────┐
        │   │   └── Enable TLSAdherence + Configure Modern    │ RUNS ONCE
        │   │       with LegacyAdheringComponentsOnly         │ (~21 min max)
        │   │
        │   ├── It("should verify ingress-node-firewall TLS compliance") ✅ DONE
        │   ├── It("should verify multus-cni TLS compliance") [TODO]
        │   ├── It("should verify ovn-kubernetes TLS compliance") [TODO]
        │   ├── It("should verify cluster-network-operator TLS compliance") [TODO]
        │   └── It("should verify openshift-network-console TLS compliance") [TODO]
        │
        ├── Context("Modern TLS Profile with StrictAllComponents") ⏸️ SKIPPED
        │   ├── BeforeEach() ────────────────────────────────┐
        │   │   └── Skip("Skipping...")                       │ SKIPS ALL
        │   │
        │   ├── It("should verify ingress-node-firewall TLS compliance") ⏸️
        │   ├── It("should verify multus-cni TLS compliance") ⏸️
        │   ├── It("should verify ovn-kubernetes TLS compliance") ⏸️
        │   ├── It("should verify cluster-network-operator TLS compliance") ⏸️
        │   └── It("should verify openshift-network-console TLS compliance") ⏸️
        │
        └── Context("Custom TLS Profile") ⏸️ SKIPPED
            ├── BeforeEach() ────────────────────────────────┐
            │   └── Skip("Skipping...")                       │ SKIPS ALL
            │
            ├── It("should verify ingress-node-firewall TLS compliance") ⏸️
            ├── It("should verify multus-cni TLS compliance") ⏸️
            ├── It("should verify ovn-kubernetes TLS compliance") ⏸️
            ├── It("should verify cluster-network-operator TLS compliance") ⏸️
            └── It("should verify openshift-network-console TLS compliance") ⏸️
```

---

## Test Execution Summary

### Active Tests
- **Total Active Contexts:** 1
- **Total Active Tests:** 5 (1 implemented, 4 TODO)
- **Focus:** Modern TLS Profile with LegacyAdheringComponentsOnly

### Skipped Tests
- **Skipped Contexts:** 2
- **Skipped Tests:** 10 (6 implemented, 4 TODO)

### Overall
- **Total Test Contexts:** 3
- **Total Test Specs:** 15
- **Runnable Specs:** 5 (LegacyAdheringComponentsOnly only)
- **Skipped Specs:** 10

---

## How to Enable/Disable Test Contexts

### To Enable StrictAllComponents Tests

**File:** `test/e2e/functional/tests/e2e.go:1218`

**Remove or comment out:**
```go
Skip("Skipping Modern TLS Profile with StrictAllComponents tests")
```

### To Enable Custom TLS Profile Tests

**File:** `test/e2e/functional/tests/e2e.go:1342`

**Remove or comment out:**
```go
Skip("Skipping Custom TLS Profile tests")
```

### To Disable LegacyAdheringComponentsOnly Tests

**File:** `test/e2e/functional/tests/e2e.go:1156`

**Add after BeforeEach opening:**
```go
BeforeEach(func() {
    Skip("Skipping Modern TLS Profile with LegacyAdheringComponentsOnly tests")
    // ... rest of BeforeEach code
})
```

---

## Test Execution Commands

### Run All TLS Compliance Tests (Only LegacyAdheringComponentsOnly will run)
```bash
go test -tags e2etests -v -ginkgo.v \
  -ginkgo.focus="TLS Profile Compliance"
```

### Run Only LegacyAdheringComponentsOnly Tests
```bash
go test -tags e2etests -v -ginkgo.v \
  -ginkgo.focus="Modern TLS Profile with LegacyAdheringComponentsOnly"
```

### Run Specific Component Test
```bash
go test -tags e2etests -v -ginkgo.v \
  -ginkgo.focus="Modern TLS Profile with LegacyAdheringComponentsOnly.*ingress-node-firewall"
```

### Run All Tests (Including Skipped - Not Recommended)
The skipped tests will still be skipped even with broad focus. To run them, you must remove the `Skip()` statements.

---

## Key Features

### 1. **Focused Testing**
- Only LegacyAdheringComponentsOnly tests are active
- Other contexts are preserved but skipped
- Easy to re-enable when needed

### 2. **Clear Test Organization**
- Tests ordered by priority (LegacyAdheringComponentsOnly first)
- Consistent structure across all contexts
- Each context has 5 component tests

### 3. **Flexible Configuration**
- Skip statements are easy to add/remove
- BeforeEach handles all cluster configuration
- No test code duplication

### 4. **Comprehensive Coverage (When All Enabled)**
- 3 TLS profile types
- 5 networking components per profile
- 15 total test scenarios

---

## Next Steps

### For LegacyAdheringComponentsOnly Context

1. **Implement multus-cni test** (webhook port 6443)
2. **Implement ovn-kubernetes test** (metrics port 9105)
3. **Implement cluster-network-operator test** (metrics port 9104)
4. **Implement openshift-network-console test** (plugin port 9443)

### Testing Strategy
- Keep StrictAllComponents and Custom Profile contexts skipped
- Focus on completing all 5 tests for LegacyAdheringComponentsOnly
- Once complete, evaluate whether to enable other contexts

### Future Considerations
- **StrictAllComponents** - May be needed for strict security requirements
- **Custom TLS Profile** - Useful for testing specific cipher configurations
- **Performance Testing** - Measure impact of different TLS profiles

---

## References

- **Test Implementation:** `test/e2e/functional/tests/e2e.go`
- **TLS Helper Functions:** `test/e2e/tls/tls.go`
- **TLS Compliance Logic:** `test/e2e/tls/tls_compliance.go`
- **Documentation:** `MODERN_LEGACY_ADHERING_TEST_IMPLEMENTATION.md`

---

## Compliance Matrix

| Profile Type | Adherence Policy | TLS 1.3 | TLS 1.2 | TLS 1.1 | Status |
|--------------|------------------|---------|---------|---------|--------|
| **Modern** | LegacyAdheringComponentsOnly | ✅ Work | ✅ Work | ❌ Fail | ⭐ **ACTIVE** |
| **Modern** | StrictAllComponents | ✅ Work | ❌ Fail | ❌ Fail | ⏸️ Skipped |
| **Custom** | StrictAllComponents | ✅ Work | ✅ Work | ❌ Fail | ⏸️ Skipped |

---

**Configuration Date:** 2026-08-03  
**Last Updated:** 2026-08-03 10:45:00  
**Status:** ✅ Ready for Testing
