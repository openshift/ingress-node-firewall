// Package tls provides TLS profile compliance testing utilities for the
// Ingress Node Firewall operator. It includes endpoint scanning, profile
// verification, and integration test helpers for validating TLS configurations
// across different cluster TLS profiles (Baseline, Modern, Custom).
package tls

import (
	"context"
	"encoding/json"
	"fmt"
	osexec "os/exec"
	"strings"
	"time"

	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

// TLS Scanner result structures
type TLSScanResult struct {
	ScanTime  string         `json:"scanTime"`
	IPResults []IPScanResult `json:"ip_results"`
	Summary   ScanSummary    `json:"summary"`
}

type IPScanResult struct {
	IP          string           `json:"ip"`
	Hostname    string           `json:"hostname"`
	Namespace   string           `json:"namespace"`
	PodName     string           `json:"pod_name"`
	PortResults []PortScanResult `json:"port_results"`
}

type PortScanResult struct {
	Port          int      `json:"port"`
	ListenAddress string   `json:"listen_address"`
	Service       string   `json:"service"`
	TLSVersions   []string `json:"tls_versions"`
	TLSCiphers    []string `json:"tls_ciphers"`
	Status        string   `json:"status"`
}

type ScanSummary struct {
	TotalIPs         int     `json:"total_ips"`
	TotalPorts       int     `json:"total_ports"`
	PortsOK          int     `json:"ports_ok"`
	PortsSkipped     int     `json:"ports_skipped"`
	TotalDurationSec float64 `json:"total_duration_sec"`
}

// Helper Functions

// RetryWithLogging retries a condition check with progress logging
// This consolidates 16+ duplicate polling patterns across TLS test files
//
// The conditionFn should return:
//   - done: true if condition is met, false otherwise
//   - reason: string describing current state (logged if not done, empty to skip logging)
//   - err: error if check failed (stops polling), nil otherwise
//
// Example usage:
//   err := RetryWithLogging(ctx, "Waiting for deployment to be ready",
//       5*time.Second, 2*time.Minute,
//       func() (bool, string, error) {
//           dep, err := cs.Get(...)
//           if err != nil {
//               return false, "", err
//           }
//           if dep.Status.ReadyReplicas != *dep.Spec.Replicas {
//               return false, fmt.Sprintf("Ready %d/%d", dep.Status.ReadyReplicas, *dep.Spec.Replicas), nil
//           }
//           return true, "", nil
//       })
func RetryWithLogging(
	ctx context.Context,
	description string,
	interval time.Duration,
	timeout time.Duration,
	conditionFn func() (done bool, reason string, err error),
) error {
	startTime := time.Now()

	err := wait.PollUntilContextTimeout(ctx, interval, timeout, true, func(ctx context.Context) (bool, error) {
		done, reason, err := conditionFn()
		if err != nil {
			return false, err
		}
		if !done {
			if reason != "" {
				elapsed := time.Since(startTime).Round(time.Second)
				LogStep(fmt.Sprintf("  %s (elapsed: %s)", reason, elapsed))
			}
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		return fmt.Errorf("%s failed after %s: %v", description, time.Since(startTime).Round(time.Second), err)
	}

	return nil
}

// getPodLogs retrieves logs from a pod with optional tail limit
func getPodLogs(cs *testclient.ClientSet, ctx context.Context, namespace, podName string, tailLines *int64) (string, error) {
	opts := &corev1.PodLogOptions{}
	if tailLines != nil {
		opts.TailLines = tailLines
	}
	logs, err := cs.CoreV1Interface.Pods(namespace).GetLogs(podName, opts).DoRaw(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get pod logs: %v", err)
	}
	return string(logs), nil
}

// getDaemonSetPodIP retrieves the IP of the first DaemonSet pod
func getDaemonSetPodIP(cs *testclient.ClientSet, ctx context.Context, operatorNS string) (string, error) {
	pods, err := cs.CoreV1Interface.Pods(operatorNS).List(ctx, metav1.ListOptions{
		LabelSelector: DaemonSetLabelSelector,
	})
	if err != nil || len(pods.Items) == 0 {
		return "", fmt.Errorf("failed to find DaemonSet pods: %v", err)
	}

	podIP := pods.Items[0].Status.PodIP
	if podIP == "" {
		return "", fmt.Errorf("DaemonSet pod has no IP")
	}

	return podIP, nil
}

// analyzeTLSScanResults parses scanner JSON output and checks if TLS version is supported on port 9301
func analyzeTLSScanResults(output []byte, tlsVersion string) (bool, string, error) {
	var results TLSScanResult
	if err := json.Unmarshal(output, &results); err != nil {
		return false, "", fmt.Errorf("failed to parse scan results: %v", err)
	}

	targetVersion := formatTLSVersion(tlsVersion)

	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			if portResult.Port == DaemonSetMetricsPort {
				// Check if the requested TLS version is in the supported list
				for _, version := range portResult.TLSVersions {
					if version == targetVersion {
						return true, fmt.Sprintf("TLS %s supported. Versions: %v", tlsVersion, portResult.TLSVersions), nil
					}
				}
				// TLS version not found in supported list
				return false, fmt.Sprintf("TLS %s not supported. Supported versions: %v", tlsVersion, portResult.TLSVersions), nil
			}
		}
	}

	return false, fmt.Sprintf("Port %d not found in scan results. Scanned %d IPs, %d ports",
		DaemonSetMetricsPort, results.Summary.TotalIPs, results.Summary.TotalPorts), nil
}

// testTLSConnectionWithOpenSSL is REMOVED - do not use direct openssl commands
// Use tls-scanner tool instead via TestTLSConnection() or RunScanWithSharedScanner()

// grantScannerPrivileges grants cluster-admin and privileged SCC to scanner namespace
func grantScannerPrivileges(namespace string) error {
	cmd := osexec.Command("oc", "adm", "policy", "add-cluster-role-to-user",
		"cluster-admin", "-z", "default", "-n", namespace)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to grant cluster-admin: %v, output: %s", err, string(output))
	}

	cmd = osexec.Command("oc", "adm", "policy", "add-scc-to-user",
		"privileged", "-z", "default", "-n", namespace)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to grant privileged SCC: %v, output: %s", err, string(output))
	}

	return nil
}

// TestTLSConnection tests TLS connectivity to the DaemonSet metrics endpoint
// This is the PRIMARY TLS testing function used by all test scenarios
// Uses tls-scanner tool (https://github.com/richardsonnick/tls-scanner) for automated CI scanning
// This function expects the shared scanner to already be set up via SetupSharedScanner()
func TestTLSConnection(cs *testclient.ClientSet, ctx context.Context, operatorNS string, tlsVersion string) (bool, string) {
	LogStep(fmt.Sprintf("  Testing TLS %s connection using tls-scanner", tlsVersion))
	success, output := RunScanWithSharedScanner(cs, ctx, operatorNS, tlsVersion)
	LogStep(fmt.Sprintf("  Scanner returned: success=%v", success))
	return success, output
}

// TestTLSConnectionWithOpenSSL is REMOVED - do not use direct openssl commands
// Use TestTLSConnection() which uses tls-scanner tool instead

// Deprecated functions below - kept for compatibility but not used

// TestTLSConnectionOld is the old implementation (DEPRECATED - DO NOT USE)
// VerifyDaemonSetArgs verifies that the kube-rbac-proxy container command in the DaemonSet
// contains expected TLS flags. The ingress-node-firewall operator implements TLS profile
// compliance by configuring the kube-rbac-proxy sidecar container in the daemon DaemonSet.
func VerifyDaemonSetArgs(cs *testclient.ClientSet, ctx context.Context, namespace, daemonSetName string, expectedArgs []string, missingArgs []string) error {
	daemonSet, err := cs.AppsV1Interface.DaemonSets(namespace).Get(ctx, daemonSetName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get daemonset %s: %v", daemonSetName, err)
	}

	if len(daemonSet.Spec.Template.Spec.Containers) == 0 {
		return fmt.Errorf("no containers found in daemonset %s", daemonSetName)
	}

	// Find the kube-rbac-proxy container and get its command
	var commandStr string
	for _, container := range daemonSet.Spec.Template.Spec.Containers {
		if container.Name == "kube-rbac-proxy" {
			// The command is a bash script, join it to search for args
			commandStr = strings.Join(container.Command, " ")
			break
		}
	}

	if commandStr == "" {
		return fmt.Errorf("kube-rbac-proxy container not found in daemonset %s", daemonSetName)
	}

	// Check expected args are present
	for _, expectedArg := range expectedArgs {
		// Use simple substring match for expected args (they may already include '=' or other delimiters)
		if !strings.Contains(commandStr, expectedArg) {
			return fmt.Errorf("expected arg '%s' not found in kube-rbac-proxy command", expectedArg)
		}
	}

	// Check that args that should be missing are indeed missing
	for _, missingArg := range missingArgs {
		// Use exact match to prevent false positives like "--tls-min-version" matching "--tls-private-key-file"
		if containsExactArg(commandStr, missingArg) {
			return fmt.Errorf("unexpected arg '%s' found in kube-rbac-proxy command when it should be missing", missingArg)
		}
	}

	return nil
}

// containsExactArg checks if a command string contains an exact argument match
// This prevents false positives like "--tls-min-version" matching "--tls-private-key-file"
// Only used for missingArgs validation
func containsExactArg(commandStr, arg string) bool {
	// Check for arg with equals sign (e.g., "--tls-min-version=")
	if strings.Contains(commandStr, arg+"=") {
		return true
	}
	// Check for arg with space after it (e.g., "--tls-min-version ")
	if strings.Contains(commandStr, arg+" ") {
		return true
	}
	// Check for arg at end of line with backslash (e.g., "--tls-min-version \\\n")
	if strings.Contains(commandStr, arg+" \\") {
		return true
	}
	return false
}
