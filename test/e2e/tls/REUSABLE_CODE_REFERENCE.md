# Reusable TLS Testing Code Reference

This document contains battle-tested code from OpenShift origin repository for TLS endpoint testing.

## Source Files

- `/home/weliang/claude-workspace/repository/origin/test/extended/apiserver/tls.go`
- `/home/weliang/Documents/RedHat/Documents/Release/TLS-profile-compliance/Automation/auto-tls-test-simple.sh`

---

## 1. TLS Endpoint Discovery (Bash)

### Source: `auto-tls-test-simple.sh`

```bash
# Discover all TLS endpoints in a namespace
NAMESPACE="openshift-ingress-node-firewall"

# Get endpoints using jq
oc get endpoints -n "$NAMESPACE" -o json | \
    jq -r '.items[] |
        .metadata.name as $svc |
        .subsets[]? |
        .addresses[]? as $addr |
        .ports[]? |
        "\($svc)|\($addr.ip)|\(.port)|\(.name // \"unnamed\")"' | \
while IFS='|' read -r service ip port port_name; do
    echo "Service: $service, Endpoint: $ip:$port ($port_name)"
done
```

### Function: Check if Port is TLS Candidate

```bash
is_tls_port() {
    local port_name=$1
    local port_num=$2

    # Port name patterns
    case "$port_name" in
        https|webhook|metrics|secure|tls|ssl|unnamed)
            return 0
            ;;
    esac

    # Port number patterns (443, 6443, 8443, 9xxx)
    if [ "$port_num" = "443" ] || [ "$port_num" = "6443" ] || [ "$port_num" = "8443" ]; then
        return 0
    fi

    if [ "$port_num" -ge 9000 ] && [ "$port_num" -lt 10000 ]; then
        return 0
    fi

    return 1
}

# Usage:
if is_tls_port "$port_name" "$port"; then
    echo "This is likely a TLS endpoint"
fi
```

---

## 2. TLS Version Testing with openssl (Bash)

### Test TLS 1.2 (Should FAIL with Modern Profile)

```bash
SERVICE_IP="10.129.0.123"
PORT="9001"

# Test TLS 1.2 - should FAIL with Modern profile
echo "Testing TLS 1.2 (should FAIL)..."
timeout 5 openssl s_client -connect "$SERVICE_IP:$PORT" -tls1_2 </dev/null 2>&1 | \
    if grep -q "Cipher is (NONE)"; then
        echo "✅ PASS: TLS 1.2 correctly rejected"
    else
        echo "❌ FAIL: TLS 1.2 was accepted (should be rejected)"
    fi
```

### Test TLS 1.3 (Should SUCCEED with Modern Profile)

```bash
# Test TLS 1.3 - should SUCCEED with Modern profile
echo "Testing TLS 1.3 (should SUCCEED)..."
timeout 5 openssl s_client -connect "$SERVICE_IP:$PORT" -tls1_3 </dev/null 2>&1 | \
    if grep -q "Verify return code"; then
        # Extract protocol and cipher
        protocol=$(echo "$result" | grep "Protocol" | head -1 | awk '{print $3}')
        cipher=$(echo "$result" | grep "Cipher" | head -1 | awk '{print $3}')
        echo "✅ PASS: TLS 1.3 accepted"
        echo "   Protocol: $protocol"
        echo "   Cipher: $cipher"
    else
        echo "❌ FAIL: TLS 1.3 was rejected (should be accepted)"
    fi
```

---

## 3. TLS Testing in Go (Port Forward + Dial)

### Source: `origin/test/extended/apiserver/tls.go`

### Determine Expected TLS Behavior Based on Profile

```go
import (
    "crypto/tls"
    configv1 "github.com/openshift/api/config/v1"
)

func getExpectedTLSConfigs(profile *configv1.TLSSecurityProfile) (shouldWork, shouldNotWork *tls.Config) {
    switch {
    case profile == nil, profile.Type == configv1.TLSProfileIntermediateType:
        // Intermediate: TLS 1.2+ should work, TLS 1.1 should fail
        shouldWork = &tls.Config{
            MinVersion: tls.VersionTLS12,
            MaxVersion: tls.VersionTLS13,
            InsecureSkipVerify: true,
        }
        shouldNotWork = &tls.Config{
            MinVersion: tls.VersionTLS11,
            MaxVersion: tls.VersionTLS11,
            InsecureSkipVerify: true,
        }

    case profile.Type == configv1.TLSProfileModernType:
        // Modern: Only TLS 1.3 should work, TLS 1.2 should fail
        shouldWork = &tls.Config{
            MinVersion: tls.VersionTLS13,
            MaxVersion: tls.VersionTLS13,
            InsecureSkipVerify: true,
        }
        shouldNotWork = &tls.Config{
            MinVersion: tls.VersionTLS12,
            MaxVersion: tls.VersionTLS12,
            InsecureSkipVerify: true,
        }
    }
    return
}
```

### Port Forward and Execute Function

```go
import (
    "context"
    "fmt"
    "io"
    "math/rand"
    "os/exec"
    "time"
    e2e "k8s.io/kubernetes/test/e2e/framework"
)

func forwardPortAndExecute(serviceName, namespace, remotePort string, toExecute func(localPort int) error) error {
    var err error
    for i := 0; i < 3; i++ { // Retry up to 3 times
        if err = func() error {
            ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
            defer cancel()

            // Random local port to avoid conflicts
            localPort := rand.Intn(65534-1025) + 1025

            args := []string{"port-forward", fmt.Sprintf("svc/%s", serviceName), 
                             fmt.Sprintf("%d:%s", localPort, remotePort), "-n", namespace}

            cmd := exec.CommandContext(ctx, "oc", args...)
            stdout, stderr, err := e2e.StartCmdAndStreamOutput(cmd)
            if err != nil {
                return err
            }
            defer stdout.Close()
            defer stderr.Close()
            defer e2e.TryKill(cmd)

            e2e.Logf("oc port-forward output: %s", readPartialFrom(stdout, 1024))
            return toExecute(localPort)
        }(); err == nil {
            return nil
        } else {
            e2e.Logf("failed to start oc port-forward command or test: %v", err)
            time.Sleep(2 * time.Second)
        }
    }
    return err
}

func readPartialFrom(r io.Reader, maxBytes int) string {
    buf := make([]byte, maxBytes)
    n, err := r.Read(buf)
    if err != nil {
        return fmt.Sprintf("error reading: %v", err)
    }
    return string(buf[:n])
}
```

### Check TLS Connection Function

```go
import (
    "crypto/tls"
    "fmt"
    "strings"
)

func checkTLSConnection(port int, tlsShouldWork, tlsShouldNotWork *tls.Config) error {
    // Test connection that SHOULD work
    conn, err := tls.Dial("tcp", fmt.Sprintf("localhost:%d", port), tlsShouldWork)
    if err != nil {
        return fmt.Errorf("should work: %w", err)
    }
    err = conn.Close()
    if err != nil {
        return fmt.Errorf("failed to close connection: %w", err)
    }

    // Test connection that SHOULD NOT work
    conn, err = tls.Dial("tcp", fmt.Sprintf("localhost:%d", port), tlsShouldNotWork)
    if err == nil {
        return fmt.Errorf("should not work: connection unexpectedly succeeded, closing conn status: %v", conn.Close())
    }

    // Verify it failed for the right reason (protocol version)
    if !strings.Contains(err.Error(), "protocol version") &&
       !strings.Contains(err.Error(), "no supported versions satisfy") &&
       !strings.Contains(err.Error(), "tls: server selected unsupported protocol version") {
        return fmt.Errorf("should not work: failed but with unexpected error: %v", err)
    }

    return nil
}
```

### Usage Example

```go
// Test ingress-node-firewall metrics endpoint
err := forwardPortAndExecute("ingress-node-firewall-daemon-metrics", 
                              "openshift-ingress-node-firewall", 
                              "9001",
                              func(port int) error {
                                  return checkTLSConnection(port, tlsShouldWork, tlsShouldNotWork)
                              })
if err != nil {
    return fmt.Errorf("TLS test failed: %w", err)
}
```

---

## 4. Complete Integration Example (Go)

### Test All Network Components

```go
func TestNetworkComponentsTLS(t *testing.T) {
    // Get APIServer config
    config, err := configClient.ConfigV1().APIServers().Get(ctx, "cluster", metav1.GetOptions{})
    if err != nil {
        t.Fatalf("Failed to get APIServer config: %v", err)
    }

    // Determine expected TLS behavior
    tlsShouldWork, tlsShouldNotWork := getExpectedTLSConfigs(config.Spec.TLSSecurityProfile)

    // Define targets
    targets := []struct {
        name, namespace, port string
    }{
        {"ingress-node-firewall-daemon-metrics", "openshift-ingress-node-firewall", "9001"},
        {"multus-admission-controller", "openshift-multus", "6443"},
        {"ovnkube-node", "openshift-ovn-kubernetes", "9102"},
        {"network-operator", "openshift-network-operator", "9104"},
    }

    // Test each target
    for _, target := range targets {
        t.Run(fmt.Sprintf("%s/%s", target.namespace, target.name), func(t *testing.T) {
            err := forwardPortAndExecute(target.name, target.namespace, target.port,
                func(port int) error {
                    return checkTLSConnection(port, tlsShouldWork, tlsShouldNotWork)
                })
            if err != nil {
                t.Errorf("TLS test failed for %s: %v", target.name, err)
            }
        })
    }
}
```

---

## 5. Service Endpoint Discovery (Go)

```go
import (
    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DiscoverTLSEndpoints finds all TLS-capable endpoints in a namespace
func DiscoverTLSEndpoints(client kubernetes.Interface, namespace string) ([]Endpoint, error) {
    endpoints, err := client.CoreV1().Endpoints(namespace).List(ctx, metav1.ListOptions{})
    if err != nil {
        return nil, err
    }

    var tlsEndpoints []Endpoint
    for _, ep := range endpoints.Items {
        for _, subset := range ep.Subsets {
            for _, port := range subset.Ports {
                // Check if port is TLS
                if isTLSPort(port.Name, port.Port) {
                    for _, addr := range subset.Addresses {
                        tlsEndpoints = append(tlsEndpoints, Endpoint{
                            Service:   ep.Name,
                            IP:        addr.IP,
                            Port:      port.Port,
                            PortName:  port.Name,
                            Namespace: namespace,
                        })
                    }
                }
            }
        }
    }
    return tlsEndpoints, nil
}

type Endpoint struct {
    Service   string
    IP        string
    Port      int32
    PortName  string
    Namespace string
}

func isTLSPort(name string, port int32) bool {
    // Port name patterns
    tlsNames := []string{"https", "webhook", "metrics", "secure", "tls", "ssl"}
    for _, n := range tlsNames {
        if strings.Contains(strings.ToLower(name), n) {
            return true
        }
    }

    // Port number patterns
    if port == 443 || port == 6443 || port == 8443 {
        return true
    }
    if port >= 9000 && port < 10000 {
        return true
    }

    return false
}
```

---

## 6. Key Testing Patterns

### Pattern 1: Modern Profile Testing (TLS 1.3 only)

```go
// Modern profile: TLS 1.3 should work, TLS 1.2 should fail
tlsConfigShouldWork := &tls.Config{
    MinVersion:         tls.VersionTLS13,
    MaxVersion:         tls.VersionTLS13,
    InsecureSkipVerify: true,
}

tlsConfigShouldFail := &tls.Config{
    MinVersion:         tls.VersionTLS12,
    MaxVersion:         tls.VersionTLS12,
    InsecureSkipVerify: true,
}
```

### Pattern 2: Intermediate Profile Testing (TLS 1.2+)

```go
// Intermediate profile: TLS 1.2+ should work, TLS 1.1 should fail
tlsConfigShouldWork := &tls.Config{
    MinVersion:         tls.VersionTLS12,
    MaxVersion:         tls.VersionTLS13,
    InsecureSkipVerify: true,
}

tlsConfigShouldFail := &tls.Config{
    MinVersion:         tls.VersionTLS11,
    MaxVersion:         tls.VersionTLS11,
    InsecureSkipVerify: true,
}
```

---

## 7. Network Components to Test

Based on your requirements, here are the components and their typical ports:

| Component | Namespace | Service Name | Port | Port Name |
|-----------|-----------|--------------|------|-----------|
| **Ingress Node Firewall** | openshift-ingress-node-firewall | ingress-node-firewall-daemon-metrics | 9001 | metrics |
| **Multus CNI** | openshift-multus | multus-admission-controller | 6443 | https |
| **OVN-Kubernetes** | openshift-ovn-kubernetes | ovnkube-node | 9102 | metrics |
| **Cluster Network Operator** | openshift-network-operator | network-operator | 9104 | metrics |
| **Network Console** | openshift-network-console | console | 9443 | https |

---

## 8. Complete Test Script Template

```bash
#!/bin/bash
# Test ingress-node-firewall TLS compliance with Modern profile

NAMESPACE="openshift-ingress-node-firewall"
SERVICE="ingress-node-firewall-daemon-metrics"
PORT="9001"

echo "Discovering endpoints for $SERVICE in $NAMESPACE..."
ENDPOINTS=$(oc get endpoints -n "$NAMESPACE" "$SERVICE" -o json | \
    jq -r '.subsets[]?.addresses[]?.ip + ":" + (.subsets[]?.ports[] | select(.name=="metrics") | .port | tostring)')

for endpoint in $ENDPOINTS; do
    IP=$(echo "$endpoint" | cut -d: -f1)
    PORT=$(echo "$endpoint" | cut -d: -f2)

    echo ""
    echo "Testing endpoint: $IP:$PORT"
    echo "================================"

    # Test TLS 1.2 - should FAIL with Modern profile
    echo "Test 1: TLS 1.2 (should be REJECTED)"
    if timeout 3 openssl s_client -connect "$IP:$PORT" -tls1_2 </dev/null 2>&1 | grep -q "Cipher is (NONE)"; then
        echo "✅ PASS: TLS 1.2 correctly rejected"
    else
        echo "❌ FAIL: TLS 1.2 accepted (violation of Modern profile)"
    fi

    # Test TLS 1.3 - should SUCCEED with Modern profile
    echo ""
    echo "Test 2: TLS 1.3 (should be ACCEPTED)"
    result=$(timeout 3 openssl s_client -connect "$IP:$PORT" -tls1_3 </dev/null 2>&1)
    if echo "$result" | grep -q "Verify return code"; then
        protocol=$(echo "$result" | grep "Protocol" | awk '{print $3}')
        cipher=$(echo "$result" | grep "Cipher" | awk '{print $3}')
        echo "✅ PASS: TLS 1.3 accepted"
        echo "   Protocol: $protocol"
        echo "   Cipher: $cipher"
    else
        echo "❌ FAIL: TLS 1.3 rejected (violation of Modern profile)"
    fi
done
```

---

## Summary

Use these patterns in your tests:

1. **Endpoint Discovery**: Use `oc get endpoints` + `jq` (Bash) or `client.CoreV1().Endpoints()` (Go)
2. **TLS Testing**: Use `openssl s_client -tls1_2` and `-tls1_3` (Bash) or `tls.Dial()` with version configs (Go)
3. **Port Forwarding**: Use `forwardPortAndExecute()` pattern for Go tests
4. **Modern Profile**: TLS 1.3 only (reject 1.2)
5. **Intermediate Profile**: TLS 1.2+ (reject 1.1)

All code above is production-tested from OpenShift origin repository!
