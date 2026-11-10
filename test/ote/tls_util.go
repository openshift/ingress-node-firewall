package ote

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os/exec"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	configv1 "github.com/openshift/api/config/v1"
	e2e "github.com/openshift/ingress-node-firewall/test/e2e"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	// MCPRolloutStartTimeout increased to 20 minutes to account for API unavailability
	// during TLS profile changes (Modern/Intermediate). When TLS changes trigger API
	// server restarts, the API may be unavailable for 10-15 minutes.
	MCPRolloutStartTimeout    = 20 * time.Minute
	MCPRolloutCompleteTimeout = 120 * time.Minute
	NodeStabilityTimeout      = 90 * time.Minute
	OperatorSettleTimeMinutes = 60
)

func logf(format string, args ...interface{}) {
	fmt.Fprintf(g.GinkgoWriter, format+"\n", args...)
}

type TLSAdherenceNotSupportedError struct {
	Message string
}

func (e *TLSAdherenceNotSupportedError) Error() string {
	return e.Message
}

func IsTLSAdherenceNotSupported(err error) bool {
	_, ok := err.(*TLSAdherenceNotSupportedError)
	return ok
}

// IsOpenShiftCluster checks if the cluster is an OpenShift cluster
func IsOpenShiftCluster(ctx context.Context, oc *e2e.OCClient) (bool, error) {
	_, err := oc.Run(ctx, "get", "featuregate", "cluster", "-o=name")
	if err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "no matches") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isINFWOperatorInstalled checks if the Ingress Node Firewall operator is installed
// by verifying the existence of its CRDs. This follows the same pattern as the
// e2e validation tests in test/e2e/validation/tests/validation.go.
func isINFWOperatorInstalled(ctx context.Context, oc *e2e.OCClient) bool {
	_, err := oc.Run(ctx, "get", "crd", "ingressnodefirewallconfigs.ingressnodefirewall.openshift.io")
	if err != nil {
		return false
	}
	_, err = oc.Run(ctx, "get", "crd", "ingressnodefirewalls.ingressnodefirewall.openshift.io")
	if err != nil {
		return false
	}
	_, err = oc.Run(ctx, "get", "namespace", opNamespace)
	if err != nil {
		return false
	}
	return true
}

// ConfigureTLSProfileWithAdherence configures the cluster with the specified TLS profile and adherence policy
func ConfigureTLSProfileWithAdherence(ctx context.Context, oc *e2e.OCClient, tlsProfileType configv1.TLSProfileType, tlsAdherencePolicy configv1.TLSAdherencePolicy) error {
	logf("=== Configuring %s TLS Profile with %s ===", tlsProfileType, tlsAdherencePolicy)

	logf("Enabling TLSAdherence feature gate")
	alreadyEnabled, err := enableTLSAdherenceFeatureGate(ctx, oc)
	if err != nil {
		return err
	}

	if !alreadyEnabled {
		logf("Waiting for cluster operators to settle after feature gate enablement")
		if err := waitForOperatorsToSettle(ctx, oc, OperatorSettleTimeMinutes); err != nil {
			return fmt.Errorf("failed waiting for operators after feature gate enablement: %w", err)
		}
		logf("All cluster operators settled after feature gate enablement")
	}

	tlsProfileChangeTime := time.Now()
	logf("Configuring APIServer with %s TLS profile and tlsAdherence=%s", tlsProfileType, tlsAdherencePolicy)
	configChanged, err := patchAPIServerTLSProfile(ctx, oc, tlsProfileType, tlsAdherencePolicy)
	if err != nil {
		return err
	}

	requiresMCPRollout := configChanged && ((tlsProfileType == configv1.TLSProfileModernType &&
		tlsAdherencePolicy == configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly) ||
		(tlsProfileType == configv1.TLSProfileIntermediateType &&
			tlsAdherencePolicy == configv1.TLSAdherencePolicyStrictAllComponents))

	if requiresMCPRollout {
		logf("Waiting for MCP rollout to start (timeout: %v)", MCPRolloutStartTimeout)
		logf("Note: During TLS profile changes, API may be unavailable for 10-15 minutes")

		rolloutStartErr := waitForMCPRolloutStart(ctx, oc, MCPRolloutStartTimeout)
		if rolloutStartErr != nil {
			// During TLS changes (especially Modern profile), API can be unavailable
			// for the entire timeout period. This doesn't mean the rollout didn't happen.
			// Log warning and proceed with verification steps.
			logf("WARNING: Could not detect MCP rollout start within %v: %v", MCPRolloutStartTimeout, rolloutStartErr)
			logf("This is expected during TLS profile changes when API is restarting")
			logf("Proceeding to verify cluster stability via node and operator checks")
		} else {
			logf("MCP rollout detected, waiting for completion")
			if err := waitForAllMCPsComplete(ctx, oc, MCPRolloutCompleteTimeout); err != nil {
				return fmt.Errorf("failed waiting for MCP rollout: %w", err)
			}
		}

		logf("Waiting for all nodes to be ready and stable")
		if err := waitForNodesStability(ctx, oc, NodeStabilityTimeout, tlsProfileChangeTime); err != nil {
			return err
		}

		logf("Waiting for cluster operators to settle")
		if err := waitForOperatorsToSettle(ctx, oc, OperatorSettleTimeMinutes); err != nil {
			return err
		}

		if rolloutStartErr != nil {
			logf("Verifying MCP status after stability checks")
			if err := verifyMCPsUpdated(ctx, oc); err != nil {
				return fmt.Errorf("MCP rollout detection failed and MCPs are not in updated state: %w", err)
			}
			logf("MCPs confirmed to be in Updated state - rollout completed successfully")
		}
	} else {
		logf("Waiting for cluster operators to settle")
		if err := waitForOperatorsToSettle(ctx, oc, OperatorSettleTimeMinutes); err != nil {
			return err
		}
	}

	logf("Verifying TLSAdherence is active in feature gate status")
	if err := verifyTLSAdherenceActive(ctx, oc); err != nil {
		return err
	}

	logf("Verifying APIServer TLS profile configuration")
	if err := verifyAPIServerTLSProfile(ctx, oc, tlsProfileType, tlsAdherencePolicy); err != nil {
		return err
	}

	logf("=== %s TLS Profile successfully configured and cluster is stable ===", tlsProfileType)
	return nil
}

// VerifyIngressNodeFirewallTLSComplianceInPod verifies TLS compliance for ingress-node-firewall daemon pods
func VerifyIngressNodeFirewallTLSComplianceInPod(ctx context.Context, oc *e2e.OCClient, namespace, labelSelector string) error {
	apiServerJSON, err := oc.Run(ctx, "get", "apiserver", "cluster", "-o=json")
	if err != nil {
		return fmt.Errorf("failed to get APIServer config: %w", err)
	}

	var expectTLS12Reject bool
	var testDescription string

	if strings.Contains(apiServerJSON, `"type":"Modern"`) {
		if strings.Contains(apiServerJSON, `"tlsAdherence":"StrictAllComponents"`) {
			expectTLS12Reject = true
			testDescription = "Modern + StrictAllComponents: TLS 1.3 only, TLS 1.2 should be rejected"
		} else {
			expectTLS12Reject = false
			testDescription = "Modern + LegacyAdheringComponentsOnly: both TLS 1.2 and TLS 1.3 should work (non-adhering component)"
		}
	} else {
		expectTLS12Reject = false
		testDescription = "Intermediate profile: both TLS 1.2 and TLS 1.3 should work"
	}

	logf("Testing ingress-node-firewall-daemon with: %s", testDescription)

	podName, err := oc.Run(ctx, "get", "pods", "-n", namespace, "-l", labelSelector,
		"-o=jsonpath={.items[0].metadata.name}")
	if err != nil {
		return fmt.Errorf("failed to list pods with selector %s: %w", labelSelector, err)
	}
	if podName == "" {
		return fmt.Errorf("no pods found with selector %s in namespace %s", labelSelector, namespace)
	}

	waitForPodReady(ctx, oc, namespace, podName)
	port := "9301"
	logf("Testing TLS on %s/%s port %s (Daemon Metrics)", namespace, podName, port)

	resourceName := fmt.Sprintf("pod/%s", podName)
	err = ForwardPortAndExecute(ctx, oc, resourceName, namespace, port, func(localPort int) error {
		tls13Config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, InsecureSkipVerify: true}
		logf("Testing TLS 1.3 on port %s (should succeed)", port)
		if err := CheckTLSConnection(localPort, tls13Config, nil); err != nil {
			return fmt.Errorf("TLS 1.3 test failed: %w", err)
		}
		logf("TLS 1.3 test PASSED on port %s", port)

		tls12Config := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, InsecureSkipVerify: true}
		if expectTLS12Reject {
			logf("Testing TLS 1.2 on port %s (should be REJECTED)", port)
			if err := CheckTLSConnection(localPort, tls12Config, nil); err == nil {
				return fmt.Errorf("TLS 1.2 connection on port %s SUCCEEDED but should have been REJECTED", port)
			}
			logf("TLS 1.2 correctly REJECTED on port %s", port)
		} else {
			logf("Testing TLS 1.2 on port %s (should succeed)", port)
			if err := CheckTLSConnection(localPort, tls12Config, nil); err != nil {
				return fmt.Errorf("TLS 1.2 test failed: %w", err)
			}
			logf("TLS 1.2 test PASSED on port %s", port)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("TLS test failed on port %s: %w", port, err)
	}

	logf("All TLS endpoints verified for %s/%s", namespace, podName)
	return nil
}

// ForwardPortAndExecute forwards a port to a service or pod and executes a function with the local port
func ForwardPortAndExecute(ctx context.Context, oc *e2e.OCClient, resourceName, namespace, remotePort string, toExecute func(localPort int) error) error {
	var err error
	for i := 0; i < 3; i++ {
		if err = func() error {
			pfCtx, cancel := context.WithCancel(ctx)
			defer cancel()

			localPort := 1025 + rand.Intn(65534-1025)
			args := []string{"port-forward", resourceName, fmt.Sprintf("%d:%s", localPort, remotePort), "-n", namespace}

			cmd := exec.CommandContext(pfCtx, "oc", args...)
			stdout, stderr, err := startCmdAndStreamOutput(cmd)
			if err != nil {
				return err
			}
			defer stdout.Close()
			defer stderr.Close()
			defer tryKill(cmd)

			_ = readPartialFrom(stdout, 1024)

			if err := waitForLocalPort(pfCtx, localPort, 5*time.Second); err != nil {
				return fmt.Errorf("port-forward failed to become ready: %w", err)
			}

			return toExecute(localPort)
		}(); err == nil {
			return nil
		} else {
			logf("Failed to start oc port-forward command or test: %v", err)
			time.Sleep(2 * time.Second)
		}
	}
	return err
}

// CheckTLSConnection verifies that a TLS connection works with the expected config
func CheckTLSConnection(port int, tlsShouldWork, tlsShouldNotWork *tls.Config) error {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout: 10 * time.Second,
		},
		Config: tlsShouldWork,
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return fmt.Errorf("should work: %w", err)
	}
	err = conn.Close()
	if err != nil {
		return fmt.Errorf("failed to close connection: %w", err)
	}

	if tlsShouldNotWork == nil {
		return nil
	}

	negDialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout: 10 * time.Second,
		},
		Config: tlsShouldNotWork,
	}

	conn, err = negDialer.DialContext(context.Background(), "tcp", fmt.Sprintf("localhost:%d", port))
	if err == nil {
		return fmt.Errorf("should not work: connection unexpectedly succeeded, closing conn status: %v", conn.Close())
	}
	if !strings.Contains(err.Error(), "protocol version") &&
		!strings.Contains(err.Error(), "no supported versions satisfy") &&
		!strings.Contains(err.Error(), "handshake failure") {
		return fmt.Errorf("should not work: got error, but not a TLS version mismatch: %w", err)
	}
	return nil
}


func enableTLSAdherenceFeatureGate(ctx context.Context, oc *e2e.OCClient) (bool, error) {
	fgJSON, err := oc.Run(ctx, "get", "featuregate", "cluster", "-o=json")
	if err != nil {
		return false, fmt.Errorf("failed to get featuregate: %w", err)
	}

	if strings.Contains(fgJSON, `"TLSAdherence"`) {
		logf("TLSAdherence feature gate already enabled")
		return true, nil
	}

	logf("Patching FeatureGate to enable TLSAdherence")
	patch := `{"spec":{"customNoUpgrade":{"enabled":["TLSAdherence"]},"featureSet":"CustomNoUpgrade"}}`
	_, err = oc.Run(ctx, "patch", "featuregate", "cluster", "--type=merge", "-p", patch)
	if err != nil {
		return false, fmt.Errorf("failed to patch FeatureGate: %w", err)
	}

	return false, nil
}

func patchAPIServerTLSProfile(ctx context.Context, oc *e2e.OCClient, tlsProfileType configv1.TLSProfileType, tlsAdherencePolicy configv1.TLSAdherencePolicy) (bool, error) {
	apiServerJSON, err := oc.Run(ctx, "get", "apiserver", "cluster", "-o=json")
	if err != nil {
		return false, fmt.Errorf("failed to get apiserver: %w", err)
	}

	profileTypeStr := fmt.Sprintf(`"type":"%s"`, tlsProfileType)
	adherencePolicyStr := fmt.Sprintf(`"tlsAdherence":"%s"`, tlsAdherencePolicy)

	if strings.Contains(apiServerJSON, profileTypeStr) && strings.Contains(apiServerJSON, adherencePolicyStr) {
		logf("APIServer already configured with %s profile and tlsAdherence=%s", tlsProfileType, tlsAdherencePolicy)
		return false, nil
	}

	var patch string
	switch tlsProfileType {
	case configv1.TLSProfileModernType:
		patch = fmt.Sprintf(`{"spec":{"tlsSecurityProfile":{"type":"Modern","modern":{}},"tlsAdherence":"%s"}}`, tlsAdherencePolicy)
	case configv1.TLSProfileIntermediateType:
		patch = fmt.Sprintf(`{"spec":{"tlsSecurityProfile":{"type":"Intermediate","intermediate":{}},"tlsAdherence":"%s"}}`, tlsAdherencePolicy)
	case configv1.TLSProfileOldType:
		patch = fmt.Sprintf(`{"spec":{"tlsSecurityProfile":{"type":"Old","old":{}},"tlsAdherence":"%s"}}`, tlsAdherencePolicy)
	default:
		return false, fmt.Errorf("unsupported TLS profile type: %s", tlsProfileType)
	}

	_, err = oc.Run(ctx, "patch", "apiserver", "cluster", "--type=merge", "-p", patch)
	if err != nil {
		return false, fmt.Errorf("failed to update apiserver: %w", err)
	}

	return true, nil
}

func waitForMCPRolloutStart(ctx context.Context, oc *e2e.OCClient, timeout time.Duration) error {
	consecutiveErrors := 0
	totalErrors := 0
	startTime := time.Now()

	return wait.PollUntilContextTimeout(ctx, 10*time.Second, timeout, true, func(pollCtx context.Context) (bool, error) {
		updatingStatus, err := oc.Run(pollCtx, "get", "mcp",
			"-o=jsonpath={.items[*].status.conditions[?(@.type=='Updating')].status}")
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, "connection refused") ||
				strings.Contains(errMsg, "i/o timeout") ||
				strings.Contains(errMsg, "context deadline exceeded") ||
				strings.Contains(errMsg, "request canceled") ||
				strings.Contains(errMsg, "Client.Timeout exceeded") ||
				strings.Contains(errMsg, "time allotted") ||
				strings.Contains(errMsg, "Service Unavailable") {
				consecutiveErrors++
				totalErrors++
				elapsed := time.Since(startTime)

				if consecutiveErrors%3 == 1 {
					logf("API unavailable during TLS restart (elapsed: %v, consecutive errors: %d, total errors: %d): %v",
						elapsed.Round(time.Second), consecutiveErrors, totalErrors, errMsg)
				}

				return false, nil
			}

			logf("Error checking MCP Updating status: %v", err)
			return false, err
		}

		if consecutiveErrors > 0 {
			logf("API connection restored after %d consecutive errors (total errors: %d, elapsed: %v)",
				consecutiveErrors, totalErrors, time.Since(startTime).Round(time.Second))
			consecutiveErrors = 0
		}

		if strings.Contains(updatingStatus, "True") {
			logf("MCP rollout has started (detected after %v)", time.Since(startTime).Round(time.Second))
			return true, nil
		}

		return false, nil
	})
}

func waitForAllMCPsComplete(ctx context.Context, oc *e2e.OCClient, timeout time.Duration) error {
	var mcpNames string
	listErr := wait.PollUntilContextTimeout(ctx, 10*time.Second, 5*time.Minute, true, func(pollCtx context.Context) (bool, error) {
		var err error
		mcpNames, err = oc.Run(pollCtx, "get", "mcp", "-o=jsonpath={.items[*].metadata.name}")
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, "connection refused") ||
				strings.Contains(errMsg, "i/o timeout") ||
				strings.Contains(errMsg, "context deadline exceeded") ||
				strings.Contains(errMsg, "request canceled") ||
				strings.Contains(errMsg, "Client.Timeout exceeded") ||
				strings.Contains(errMsg, "Service Unavailable") {
				logf("Transient API error listing MCPs (will retry): %v", err)
				return false, nil
			}
			return false, err
		}
		return true, nil
	})
	if listErr != nil {
		return fmt.Errorf("failed to list MCPs after retries: %w", listErr)
	}

	mcps := strings.Fields(mcpNames)
	for _, mcpName := range mcps {
		logf("Waiting for MCP %s to complete rollout", mcpName)
		if err := waitForMCPComplete(ctx, oc, mcpName, timeout); err != nil {
			return fmt.Errorf("MCP %s did not complete: %w", mcpName, err)
		}
	}

	return nil
}

func waitForMCPComplete(ctx context.Context, oc *e2e.OCClient, mcpName string, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, 30*time.Second, timeout, true, func(pollCtx context.Context) (bool, error) {
		updatedStatus, err := oc.Run(pollCtx, "get", "mcp", mcpName,
			"-o=jsonpath={.status.conditions[?(@.type=='Updated')].status}")
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, "connection refused") ||
				strings.Contains(errMsg, "i/o timeout") ||
				strings.Contains(errMsg, "context deadline exceeded") ||
				strings.Contains(errMsg, "request canceled") ||
				strings.Contains(errMsg, "Client.Timeout exceeded") ||
				strings.Contains(errMsg, "Service Unavailable") {
				logf("Transient API error getting MCP %s (will retry): %v", mcpName, err)
				return false, nil
			}
			logf("Error getting MCP %s: %v", mcpName, err)
			return false, nil
		}

		updatedStatus = strings.TrimSpace(updatedStatus)
		if updatedStatus == "True" {
			logf("MCP %s is updated", mcpName)
			return true, nil
		}

		logf("MCP %s is not yet updated (Updated=%s)", mcpName, updatedStatus)
		return false, nil
	})
}

// verifyMCPsUpdated checks if all MCPs are currently in Updated=True state
// This is used as a fallback verification when we couldn't detect the rollout start
// due to API unavailability during TLS profile changes
func verifyMCPsUpdated(ctx context.Context, oc *e2e.OCClient) error {
	var mcpJSON string
	var err error
	for i := 0; i < 5; i++ {
		mcpJSON, err = oc.Run(ctx, "get", "mcp", "-o=json")
		if err == nil {
			break
		}
		logf("Attempt %d: Error getting MCP status (will retry): %v", i+1, err)
		time.Sleep(10 * time.Second)
	}
	if err != nil {
		return fmt.Errorf("failed to get MCP status after retries: %w", err)
	}

	if (strings.Contains(mcpJSON, `"type":"Updating"`) || strings.Contains(mcpJSON, `"type": "Updating"`)) &&
		(strings.Contains(mcpJSON, `"status":"True"`) || strings.Contains(mcpJSON, `"status": "True"`)) {
		return fmt.Errorf("MCPs still updating - rollout not complete")
	}

	if !(strings.Contains(mcpJSON, `"type":"Updated"`) || strings.Contains(mcpJSON, `"type": "Updated"`)) ||
		!(strings.Contains(mcpJSON, `"status":"True"`) || strings.Contains(mcpJSON, `"status": "True"`)) {
		return fmt.Errorf("MCPs not in Updated=True state")
	}

	if (strings.Contains(mcpJSON, `"type":"Updated"`) || strings.Contains(mcpJSON, `"type": "Updated"`)) &&
		(strings.Contains(mcpJSON, `"status":"False"`) || strings.Contains(mcpJSON, `"status": "False"`)) {
		return fmt.Errorf("some MCPs have Updated=False")
	}

	return nil
}

func waitForOperatorsToSettle(ctx context.Context, oc *e2e.OCClient, waitTimeMinutes int) error {
	timeout := time.Duration(waitTimeMinutes) * time.Minute
	logf("Waiting for all cluster operators to settle (timeout: %v)", timeout)

	return wait.PollUntilContextTimeout(ctx, 10*time.Second, timeout, true, func(pollCtx context.Context) (bool, error) {
		coJSON, err := oc.Run(pollCtx, "get", "co", "-o=json")
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, "connection refused") ||
				strings.Contains(errMsg, "i/o timeout") ||
				strings.Contains(errMsg, "context deadline exceeded") ||
				strings.Contains(errMsg, "request canceled") ||
				strings.Contains(errMsg, "Client.Timeout exceeded") ||
				strings.Contains(errMsg, "Service Unavailable") {
				logf("Transient API error getting ClusterOperators (will retry): %v", err)
				return false, nil
			}
			logf("Error getting ClusterOperators: %v (retrying)", err)
			return false, nil
		}

		if strings.Contains(coJSON, `"Available","status":"False"`) ||
			strings.Contains(coJSON, `"Degraded","status":"True"`) ||
			strings.Contains(coJSON, `"Progressing","status":"True"`) {
			logf("Waiting for operators to settle...")
			return false, nil
		}

		logf("All cluster operators settled")
		return true, nil
	})
}

func waitForNodesStability(ctx context.Context, oc *e2e.OCClient, timeout time.Duration, afterTime time.Time) error {
	return wait.PollUntilContextTimeout(ctx, 30*time.Second, timeout, true, func(pollCtx context.Context) (bool, error) {
		nodesJSON, err := oc.Run(pollCtx, "get", "nodes", "-o=json")
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, "connection refused") ||
				strings.Contains(errMsg, "i/o timeout") ||
				strings.Contains(errMsg, "context deadline exceeded") ||
				strings.Contains(errMsg, "request canceled") ||
				strings.Contains(errMsg, "Client.Timeout exceeded") ||
				strings.Contains(errMsg, "Service Unavailable") {
				logf("Transient API error getting nodes (will retry): %v", err)
				return false, nil
			}
			logf("Error getting nodes: %v", err)
			return false, nil
		}

		if strings.Contains(nodesJSON, `"type":"Ready","status":"False"`) ||
			strings.Contains(nodesJSON, `"type":"Ready","status":"Unknown"`) {
			logf("Waiting for nodes to be ready...")
			return false, nil
		}

		logf("All nodes are ready")
		return true, nil
	})
}

func verifyTLSAdherenceActive(ctx context.Context, oc *e2e.OCClient) error {
	cvJSON, err := oc.Run(ctx, "get", "clusterversion", "version", "-o=json")
	if err != nil {
		return fmt.Errorf("failed to get cluster version: %w", err)
	}

	if !strings.Contains(cvJSON, `"desired"`) {
		return fmt.Errorf("failed to extract cluster version from JSON")
	}

	logf("Verifying TLSAdherence is active in feature gate status")

	return wait.PollUntilContextTimeout(ctx, 15*time.Second, 15*time.Minute, true, func(pollCtx context.Context) (bool, error) {
		enabledFeatures, err := oc.Run(pollCtx, "get", "featuregate", "cluster",
			"-o=jsonpath={.status.featureGates[*].enabled[?(@.name=='TLSAdherence')].name}")
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, "connection refused") ||
				strings.Contains(errMsg, "i/o timeout") ||
				strings.Contains(errMsg, "context deadline exceeded") ||
				strings.Contains(errMsg, "request canceled") ||
				strings.Contains(errMsg, "Client.Timeout exceeded") ||
				strings.Contains(errMsg, "Service Unavailable") {
				logf("Transient API error getting FeatureGate (will retry): %v", err)
				return false, nil
			}
			logf("Error getting FeatureGate: %v", err)
			return false, nil
		}

		if strings.Contains(enabledFeatures, "TLSAdherence") {
			logf("TLSAdherence is active in feature gate status")
			return true, nil
		}

		logf("TLSAdherence not yet in status (waiting...)")
		return false, nil
	})
}

func verifyAPIServerTLSProfile(ctx context.Context, oc *e2e.OCClient, tlsProfileType configv1.TLSProfileType, tlsAdherencePolicy configv1.TLSAdherencePolicy) error {
	profileType, err := oc.Run(ctx, "get", "apiserver", "cluster", "-o=jsonpath={.spec.tlsSecurityProfile.type}")
	if err != nil {
		return fmt.Errorf("failed to get APIServer TLS profile type: %w", err)
	}

	if strings.TrimSpace(profileType) != string(tlsProfileType) {
		return fmt.Errorf("APIServer TLS profile is not %s (got: %s)", tlsProfileType, profileType)
	}

	if tlsAdherencePolicy != "" {
		adherence, err := oc.Run(ctx, "get", "apiserver", "cluster", "-o=jsonpath={.spec.tlsAdherence}")
		if err != nil {
			return fmt.Errorf("failed to get APIServer tlsAdherence: %w", err)
		}

		adherence = strings.TrimSpace(adherence)
		if adherence == "" {
			apiServerJSON, _ := oc.Run(ctx, "get", "apiserver", "cluster", "-o=json")
			if !strings.Contains(apiServerJSON, `"tlsAdherence"`) {
				return &TLSAdherenceNotSupportedError{
					Message: fmt.Sprintf("tlsAdherence API field not supported in this cluster version (tried to set %s but field is missing)", tlsAdherencePolicy),
				}
			}
		}

		if adherence != string(tlsAdherencePolicy) {
			return fmt.Errorf("APIServer tlsAdherence is not %s (got: %s)", tlsAdherencePolicy, adherence)
		}
	}

	logf("APIServer configuration verified: tlsSecurityProfile.type=%s, tlsAdherence=%s", tlsProfileType, tlsAdherencePolicy)
	return nil
}

func waitForLocalPort(ctx context.Context, localPort int, timeout time.Duration) error {
	addr := fmt.Sprintf("127.0.0.1:%d", localPort)
	return wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, timeout, true,
		func(ctx context.Context) (bool, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			if err != nil {
				return false, nil
			}
			conn.Close()
			return true, nil
		})
}

func startCmdAndStreamOutput(cmd *exec.Cmd) (io.ReadCloser, io.ReadCloser, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdout.Close()
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		stdout.Close()
		stderr.Close()
		return nil, nil, err
	}
	return stdout, stderr, nil
}

func readPartialFrom(r io.Reader, maxBytes int) string {
	buf := make([]byte, maxBytes)
	n, err := r.Read(buf)
	if err != nil && err != io.EOF {
		return fmt.Sprintf("error reading: %v", err)
	}
	return string(buf[:n])
}

func tryKill(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}
