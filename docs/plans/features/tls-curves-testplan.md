# Test Plan: TLS Curve/Group Preferences in Ingress Node Firewall Webhook Server

**Feature:** TLS curve/group preferences support in Ingress Node Firewall webhook server  
**Parent Feature:** [OCPSTRAT-3145](https://redhat.atlassian.net/browse/OCPSTRAT-3145) — Add TLSGroupPreferences field to support TLS 1.3 curve configuration  
**OCP Version:** 5.1+  
**Target Release:** OpenShift 5.1

## Table of Contents

1. [References](#references) — Enhancement proposals, JIRA tickets, and standards
2. [Introduction](#introduction) — Feature overview and scope
3. [Test Strategy](#test-strategy) — Testing approach for Ingress Node Firewall webhook server
4. [Test Scope](#test-scope) — Functional and negative scenarios
5. [Out of Scope](#out-of-scope) — What we're not testing
6. [Target Environments](#target-environments) — OCP versions and architectures
7. [Test Deliverables](#test-deliverables) — Test reports and automation
8. [Test Tasks](#test-tasks) — Work breakdown
9. [Pass/Fail Criteria](#passfail-criteria) — Exit criteria
10. [Risks and Mitigation](#risks-and-mitigation) — Known blockers and limitations

## References

### Documentation and Enhancement Proposals

| Type | Reference | Description |
|------|-----------|-------------|
| **Enhancement Proposal** | [api-tls-curves-config.md](https://github.com/openshift/enhancements/blob/master/enhancements/security/api-tls-curves-config.md) | TLS curve/group preferences configuration API |
| **Parent Jira** | [OCPSTRAT-3145](https://redhat.atlassian.net/browse/OCPSTRAT-3145) | TLSGroupPreferences field for TLS 1.3 |
| **Repository** | [openshift/ingress-node-firewall](https://github.com/openshift/ingress-node-firewall) | Ingress Node Firewall webhook server |

## Introduction

The TLS curve/group preferences feature enables cluster administrators to configure which elliptic curve cryptography (ECC) groups are used during TLS 1.3 handshakes. This enhancement affects all OpenShift components that serve HTTPS endpoints, including the Ingress Node Firewall webhook server.

### What Changed

**Before OCP 5.1:**
- OpenShift components used hardcoded default TLS curves from the Go `crypto/tls` library

**Starting in OCP 5.1, administrators can:**

1. **Configure custom TLS curve preferences** via `spec.tlsSecurityProfile.custom.groups` on the API server
2. **Specify classical curves:**
   - NIST curves: `secp256r1`, `secp384r1`, `secp521r1`
   - Non-NIST curves: `X25519`

### Affected Component

The TLS curve preferences apply to the **Ingress Node Firewall webhook server**:

| Component | Namespace | Purpose |
|-----------|-----------|---------|
| **Ingress Node Firewall webhook server** | `openshift-ingress-node-firewall` | Admission webhook for IngressNodeFirewall resources |

## Test Strategy

### Testing Approach

This test plan validates that the Ingress Node Firewall webhook server correctly:

1. **Apply** configured TLS curves from the cluster-level `tlsSecurityProfile`
2. **Negotiate** TLS handshakes using the configured curves

### Test Methodology

**Component Focus:** Ingress Node Firewall webhook server

**Environment Coverage:** The webhook server will be verified in:
- OCP clusters

**Curve Coverage:** All supported TLS curves/groups will be tested (see [Supported TLS Curves/Groups](#supported-tls-curvesgroups))

**Test Execution:** The webhook server serves admission endpoints for IngressNodeFirewall resources, providing an ideal integration point for validating TLS curve preferences during HTTPS connections.

## Test Scope

### Downstream Testing Focus

This test plan focuses on the Ingress Node Firewall webhook server for TLS curve/group preferences validation.

**Primary Repository:**
- [openshift/ingress-node-firewall](https://github.com/openshift/ingress-node-firewall)

**Component Under Test:**
- Ingress Node Firewall webhook server (admission webhook for IngressNodeFirewall resources)

### Supported TLS Curves/Groups

| Curve / Group | Type | Feature Gate Required | Availability |
|---------------|------|----------------------|--------------|
| **X25519** | Classical (non-NIST) | No | All OCP versions |
| **secp256r1** | Classical (NIST P-256) | No | All OCP versions |
| **secp384r1** | Classical (NIST P-384) | No | All OCP versions |
| **secp521r1** | Classical (NIST P-521) | No | All OCP versions |

### E2E Test Cases

#### E1: Verify TLS curve preferences for Ingress Node Firewall webhook server

**Component:** `ingress-node-firewall` webhook server  
**Namespace:** `openshift-ingress-node-firewall`

**Objective:**  
Validates that the Ingress Node Firewall admission webhook server correctly applies TLS curve preferences during HTTPS connections for IngressNodeFirewall resource admissions.

**Test Coverage:**
- ✓ Verify all supported TLS curves/groups (see [Supported TLS Curves/Groups](#supported-tls-curvesgroups))
- ✓ Validate successful TLS handshakes using the configured curves

**Test Environments:**
- OCP cluster

**Expected Results:**
- TLS connections successfully negotiate using configured curves

**Test Steps:**

**Step 1: Enable TLSGroupPreferences Feature Gate**

If the `TLSGroupPreferences` feature gate is not enabled, enable it:

```bash
oc patch featuregate cluster --type=merge -p '
{
  "spec": {
    "featureSet": "CustomNoUpgrade",
    "customNoUpgrade": {
      "enabled": ["TLSGroupPreferences"]
    }
  }
}'
```

**Step 2: Wait for Cluster Stability**

Use existing functions to wait for MCP, nodes, and operators to reboot and return to healthy state.

**Step 3: Configure TLS Groups**

Apply custom TLS group preferences via the API server:

```bash
oc patch apiserver cluster --type=merge -p '
{
  "spec": {
    "tlsSecurityProfile": {
      "type": "Custom",
      "custom": {
        "minTLSVersion": "VersionTLS12",
        "groups": [
          "secp521r1",
          "secp256r1"
        ],
        "ciphers": [
          "TLS_AES_128_GCM_SHA256",
          "TLS_AES_256_GCM_SHA384",
          "TLS_CHACHA20_POLY1305_SHA256",
          "ECDHE-ECDSA-AES128-GCM-SHA256",
          "ECDHE-RSA-AES128-GCM-SHA256",
          "ECDHE-ECDSA-AES256-GCM-SHA384",
          "ECDHE-RSA-AES256-GCM-SHA384"
        ]
      }
    },
    "tlsAdherence": "StrictAllComponents"
  }
}'
```

**Step 4: Wait for Cluster Reconciliation**

Use existing functions to wait for MCP, nodes, and operators to reboot and return to healthy state.

**Step 5: Validate API TLS Group Configuration**

Verify the configured TLS groups:

```bash
oc get apiserver/cluster -o jsonpath='{.spec.tlsSecurityProfile.custom.groups}' | jq .
```

**Step 6: Test Ingress Node Firewall Webhook Server**

Test the webhook server with different TLS groups using `openssl s_client`:

**Test with secp256r1 (should pass):**
```bash
oc debug node/<worknode>
openssl s_client \
   -connect <webhook-service-ip>:443 \
   -tls1_3 \
   -groups secp256r1 \
   -brief </dev/null
```

**Test with secp521r1 (should pass):**
```bash
oc debug node/<worknode>
openssl s_client \
   -connect <webhook-service-ip>:443 \
   -tls1_3 \
   -groups secp521r1 \
   -brief </dev/null
```

**Test with secp384r1 (should fail - not in configured groups):**
```bash
oc debug node/<worknode>
openssl s_client \
   -connect <webhook-service-ip>:443 \
   -tls1_3 \
   -groups secp384r1 \
   -brief </dev/null
```

**Expected Test Results:**
- **Pass groups:** `secp256r1` and `secp521r1` — TLS handshake succeeds
- **Fail groups:** `secp384r1` — TLS handshake fails (not in configured groups list)

## Out of Scope

The following components and scenarios are **explicitly excluded** from this test plan:

### Other OpenShift Components
| Component | Reason |
|-----------|--------|
| **API Server TLS** | Covered by separate API server test plans |
| **CNO Managed Components** | multus-admission-controller, ovn-kubernetes, CNO, and networking-console-plugin are covered in separate CNO test plan |
| **Ingress Controller TLS** | Covered by ingress/router team test plans |
| **etcd TLS Configuration** | Managed separately from Ingress Node Firewall |
| **Service Mesh / Istio TLS** | Not related to Ingress Node Firewall |

### Additional Exclusions
- **User Workload TLS** — Applications deployed by users manage their own TLS configuration
- **OpenSSL Version Compatibility** — Assumes OpenSSL 3.x+ with modern curve support
- **Certificate Authority Changes** — This plan only covers curve negotiation, not CA trust chains
- **Performance Impact** — Curve selection performance benchmarking is not included
- **Upgrade Scenarios** — TLS curve migration during cluster upgrades (covered separately)

## Target Environments

| Environment Type | Version/Configuration | Priority | Notes |
|-----------------|----------------------|----------|-------|
| **OpenShift** | 5.1+ | Critical | Primary target release |

## Test Deliverables

| Deliverable | Description | Target Audience |
|-------------|-------------|-----------------|
| **E2E Test Automation** | Downstream PRs with e2e tests in `ingress-node-firewall` repository | QE, CI/CD (Prow) |
| **Test Execution Report** | Comprehensive test results with coverage metrics and findings | QE, Engineering |
| **Documentation Feedback** | Configuration examples and known limitations | Docs team |
| **Bug Reports** | Detailed reports for any discrepancies between expected and actual behavior | Engineering |

## Test Tasks

| Task | Status | Owner | Notes |
|------|--------|-------|-------|
| Test plan creation and review | ☐ | QE Team | This document |
| Execute e2e tests on OCP cluster | ☐ | QE Team | Ingress Node Firewall webhook server |
| Automate curve validation script | ☐ | QE Team | For Ingress Node Firewall webhook server |
| Document test results | ☐ | QE Team | Create test execution report |
| File bugs for failures | ☐ | QE Team | Track issues in Jira |
| Provide documentation feedback | ☐ | QE Team | Configuration examples and notes |

## Pass/Fail Criteria

### Pass Criteria

The feature is considered **ready for release** when all of the following conditions are met:

- ✓ **Zero critical or major defects** remain open in Jira
- ✓ **All e2e test cases** pass consistently in Prow CI
- ✓ **Test automation complete** — All tests merged into `ingress-node-firewall` repository
- ✓ **Documentation feedback provided** — Configuration examples and known limitations shared with Docs team
- ✓ **Test execution report published** — Comprehensive results documented

### Fail Criteria

The feature is **NOT ready for release** if any of the following occur:

- ✗ **Critical defects** that block core TLS functionality
- ✗ **Consistent test failures** on Prow CI
- ✗ **Security vulnerabilities** identified in TLS configuration handling

## Risks and Mitigation

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| **Platform-specific issues** | Different behavior on ARM64, s390x, ppc64le | Low | Test on all supported architectures |

### Current Status

**No known blockers or critical limitations** at the time of test plan creation.

---

---


**End of Test Plan**
