package tls

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"slices"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	podutil "k8s.io/kubernetes/pkg/api/v1/pod"
	"sigs.k8s.io/controller-runtime/pkg/client"

	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
	executil "github.com/openshift/ingress-node-firewall/test/e2e/exec"
	"github.com/openshift/ingress-node-firewall/test/e2e/pods"
	remoteexec "k8s.io/client-go/util/exec"
)

const (
	MCPRolloutStartTimeout    = 10 * time.Minute
	MCPRolloutCompleteTimeout = 120 * time.Minute // Increased from 60 to match Origin
	NodeStabilityTimeout      = 90 * time.Minute  // Increased from 60 to match Origin
	OperatorSettleTimeMinutes = 60

	MCPPollingInterval = 10 * time.Second

	DaemonMetricsPort      = "9301"
	DaemonMetricsContainer = "daemon"
	DaemonSetLabelSelector = "app=ingress-node-firewall-daemon"

	OperatorWebhookPort      = "9443"
	OperatorWebhookContainer = "manager"
	OperatorLabelSelector    = "control-plane=controller-manager"
)

type TLSAdherenceNotSupportedError struct {
	Message string
}

func (e *TLSAdherenceNotSupportedError) Error() string {
	return e.Message
}

func IsTLSAdherenceNotSupported(err error) bool {
	var target *TLSAdherenceNotSupportedError
	return errors.As(err, &target)
}

func parseLabelSelector(selector string) map[string]string {
	labels := make(map[string]string)
	parts := strings.Split(selector, ",")
	for _, part := range parts {
		kv := strings.Split(strings.TrimSpace(part), "=")
		if len(kv) == 2 {
			labels[kv[0]] = kv[1]
		}
	}
	return labels
}

func IsOpenShiftCluster(c *testclient.ClientSet) bool {
	fg := &configv1.FeatureGate{}
	err := c.Get(context.Background(), types.NamespacedName{Name: "cluster"}, fg)
	return err == nil
}

func ConfigureTLSProfileWithAdherence(c *testclient.ClientSet, tlsProfileType configv1.TLSProfileType,
	tlsAdherencePolicy configv1.TLSAdherencePolicy) (*configv1.APIServerSpec, error) {
	overallStartTime := time.Now()
	log.Printf("=== Configuring %s TLS Profile with %s (started: %s) ===",
		tlsProfileType, tlsAdherencePolicy, overallStartTime.Format("15:04:05"))

	ctx := context.Background()

	log.Printf("Configuring APIServer with %s TLS profile and tlsAdherence=%s", tlsProfileType, tlsAdherencePolicy)
	if err := patchAPIServerTLSProfile(ctx, c, tlsProfileType, tlsAdherencePolicy); err != nil {
		return nil, err
	}

	log.Println("Waiting for cluster to stabilize after TLS profile configuration")
	requiresMCPRollout := ((tlsProfileType == configv1.TLSProfileModernType &&
		tlsAdherencePolicy == configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly) ||
		(tlsProfileType == configv1.TLSProfileIntermediateType && tlsAdherencePolicy == configv1.TLSAdherencePolicyStrictAllComponents))
	if err := waitForClusterStabilization(ctx, c, requiresMCPRollout, false); err != nil {
		return nil, err
	}

	log.Println("Verifying APIServer TLS profile configuration")
	if err := verifyAPIServerTLSProfile(ctx, c, tlsProfileType, tlsAdherencePolicy); err != nil {
		return nil, err
	}

	log.Printf("=== %s TLS Profile successfully configured (total time: %v) ===",
		tlsProfileType, time.Since(overallStartTime))

	apiserver := &configv1.APIServer{}
	err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, apiserver)
	if err != nil {
		return nil, fmt.Errorf("failed to get APIServer config: %w", err)
	}

	return &apiserver.Spec, nil
}

// enableFeatureGate enables a feature gate and waits for cluster stabilization.
// Returns true if the feature was already enabled.
func enableFeatureGate(ctx context.Context, c client.Client, featureName string) (bool, error) {
	fg := &configv1.FeatureGate{}
	err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, fg)
	if err != nil {
		return false, fmt.Errorf("failed to get featuregate: %w", err)
	}

	// Check if already enabled
	if fg.Spec.FeatureSet == configv1.CustomNoUpgrade && fg.Spec.CustomNoUpgrade != nil {
		for _, enabled := range fg.Spec.CustomNoUpgrade.Enabled {
			if string(enabled) == featureName {
				log.Printf("  %s feature gate is already enabled", featureName)
				return true, nil
			}
		}
	}

	log.Printf("  Enabling %s feature gate", featureName)
	// Add the feature to existing features
	if fg.Spec.FeatureSet == configv1.CustomNoUpgrade && fg.Spec.CustomNoUpgrade != nil {
		fg.Spec.CustomNoUpgrade.Enabled = append(fg.Spec.CustomNoUpgrade.Enabled, configv1.FeatureGateName(featureName))
	} else {
		fg.Spec.FeatureSet = configv1.CustomNoUpgrade
		fg.Spec.CustomNoUpgrade = &configv1.CustomFeatureGates{
			Enabled: []configv1.FeatureGateName{configv1.FeatureGateName(featureName)},
		}
	}

	err = c.Update(ctx, fg)
	if err != nil {
		return false, fmt.Errorf("failed to update featuregate: %w", err)
	}

	return false, waitForClusterStabilization(ctx, c, true, true)
}

// waitForClusterStabilization waits for cluster to stabilize.
// If waitForMCP is true, waits for MCP rollout completion.
// If warnOnMCPTimeout is true, logs a warning instead of failing when MCP rollout doesn't start.
func waitForClusterStabilization(ctx context.Context, c client.Client, waitForMCP, warnOnMCPTimeout bool) error {
	if waitForMCP {
		log.Println("  Waiting for MCP rollout to start")
		if err := waitForMCPRolloutStart(c, MCPRolloutStartTimeout); err != nil {
			if warnOnMCPTimeout {
				log.Printf("  WARNING: MCP rollout did not start within timeout: %v", err)
			} else {
				return err
			}
		} else {
			log.Println("  Waiting for MCP rollout to complete")
			if err := waitForAllMCPsComplete(c, MCPRolloutCompleteTimeout); err != nil {
				return fmt.Errorf("failed waiting for MCP rollout: %w", err)
			}
		}
	}

	log.Println("  Waiting for nodes to be ready")
	if err := waitForNodesStability(c, NodeStabilityTimeout); err != nil {
		return fmt.Errorf("failed waiting for nodes: %w", err)
	}

	log.Println("  Waiting for cluster operators to settle")
	if err := waitForOperatorsToSettle(ctx, c, OperatorSettleTimeMinutes); err != nil {
		return fmt.Errorf("failed waiting for operators: %w", err)
	}

	return nil
}

func verifyAPIServerTLSProfile(ctx context.Context, c client.Client, tlsProfileType configv1.TLSProfileType, tlsAdherencePolicy configv1.TLSAdherencePolicy) error {
	apiserver := &configv1.APIServer{}
	err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, apiserver)
	if err != nil {
		return fmt.Errorf("failed to get APIServer: %w", err)
	}

	if apiserver.Spec.TLSSecurityProfile == nil {
		return fmt.Errorf("APIServer TLS security profile is nil, expected %s", tlsProfileType)
	}

	actualProfileType := apiserver.Spec.TLSSecurityProfile.Type
	if actualProfileType != tlsProfileType {
		return fmt.Errorf("APIServer TLS profile type mismatch: actual=%s, expected=%s", actualProfileType, tlsProfileType)
	}
	log.Printf("  TLS profile type verified: %s", tlsProfileType)

	actualAdherence := apiserver.Spec.TLSAdherence
	if tlsAdherencePolicy != "" && actualAdherence == "" {
		return &TLSAdherenceNotSupportedError{
			Message: fmt.Sprintf("tlsAdherence API field not supported in this cluster version (tried to set %s but got empty value)", tlsAdherencePolicy),
		}
	}

	if actualAdherence != "" && actualAdherence != tlsAdherencePolicy {
		return fmt.Errorf("APIServer tlsAdherence mismatch: actual=%s, expected=%s", actualAdherence, tlsAdherencePolicy)
	}

	if actualAdherence == "" {
		log.Println("  TLS adherence policy verified: <empty> (default)")
	} else {
		log.Printf("  TLS adherence policy verified: %s", actualAdherence)
	}

	return nil
}

func patchAPIServerTLSProfile(ctx context.Context, c client.Client, tlsProfileType configv1.TLSProfileType, tlsAdherencePolicy configv1.TLSAdherencePolicy) error {
	apiserver := &configv1.APIServer{}
	err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, apiserver)
	if err != nil {
		return fmt.Errorf("failed to get apiserver: %w", err)
	}

	switch tlsProfileType {
	case configv1.TLSProfileModernType:
		apiserver.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
			Type:   configv1.TLSProfileModernType,
			Modern: &configv1.ModernTLSProfile{},
		}
	case configv1.TLSProfileIntermediateType:
		apiserver.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
			Type:         configv1.TLSProfileIntermediateType,
			Intermediate: &configv1.IntermediateTLSProfile{},
		}
	case configv1.TLSProfileOldType:
		apiserver.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileOldType,
			Old:  &configv1.OldTLSProfile{},
		}
	default:
		return fmt.Errorf("unsupported TLS profile type: %s (must be Modern, Intermediate, or Old)", tlsProfileType)
	}

	apiserver.Spec.TLSAdherence = tlsAdherencePolicy

	err = c.Update(ctx, apiserver)
	if err != nil {
		return fmt.Errorf("failed to update apiserver: %w", err)
	}

	return nil
}

func waitForMCPRolloutStart(c client.Client, timeout time.Duration) error {
	ctx := context.Background()
	return wait.PollUntilContextTimeout(ctx, MCPPollingInterval, timeout, true, func(ctx context.Context) (bool, error) {
		mcpList := &mcfgv1.MachineConfigPoolList{}
		err := c.List(ctx, mcpList)
		if err != nil {
			return false, err
		}

		for _, mcp := range mcpList.Items {
			for _, cond := range mcp.Status.Conditions {
				if cond.Type == mcfgv1.MachineConfigPoolUpdating && cond.Status == corev1.ConditionTrue {
					log.Printf("    MCP %s has started updating", mcp.Name)
					return true, nil
				}
			}
		}
		return false, nil
	})
}

func waitForAllMCPsComplete(c client.Client, timeout time.Duration) error {
	ctx := context.Background()
	mcpList := &mcfgv1.MachineConfigPoolList{}
	err := c.List(ctx, mcpList)
	if err != nil {
		return fmt.Errorf("failed to list MCPs: %w", err)
	}
	mcps := mcpList.Items

	for _, mcp := range mcps {
		if mcp.Status.MachineCount == 0 {
			continue
		}

		log.Printf("    Waiting for MCP %s (%d machines)", mcp.Name, mcp.Status.MachineCount)
		if err := waitForMCPComplete(c, mcp.Name, timeout); err != nil {
			return fmt.Errorf("MCP %s did not complete: %w", mcp.Name, err)
		}
	}

	return nil
}

func waitForMCPComplete(c client.Client, mcpName string, timeout time.Duration) error {
	ctx := context.Background()
	return wait.PollUntilContextTimeout(ctx, 30*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		mcp := &mcfgv1.MachineConfigPool{}
		err := c.Get(ctx, types.NamespacedName{Name: mcpName}, mcp)
		if err != nil {
			return false, nil
		}

		updated := false
		for _, cond := range mcp.Status.Conditions {
			if cond.Type == mcfgv1.MachineConfigPoolUpdated && cond.Status == corev1.ConditionTrue {
				updated = true
				break
			}
		}

		if updated && mcp.Status.UpdatedMachineCount == mcp.Status.MachineCount {
			return true, nil
		}

		log.Printf("      MCP %s: %d/%d machines updated (waiting...)",
			mcpName, mcp.Status.UpdatedMachineCount, mcp.Status.MachineCount)
		return false, nil
	})
}

func waitForOperatorsToSettle(ctx context.Context, c client.Client, waitTimeMinutes int) error {
	return wait.PollUntilContextTimeout(ctx, 10*time.Second, time.Duration(waitTimeMinutes)*time.Minute, true, func(ctx context.Context) (bool, error) {
		coList := &configv1.ClusterOperatorList{}
		err := c.List(ctx, coList)
		if err != nil {
			return false, nil
		}

		unsettled := []string{}
		for _, co := range coList.Items {
			available, degraded, progressing := getOperatorConditions(&co)

			if available && !degraded && !progressing {
				continue
			}

			if !available {
				unsettled = append(unsettled, fmt.Sprintf("%s: Available=False", co.Name))
			}
			if degraded {
				unsettled = append(unsettled, fmt.Sprintf("%s: Degraded=True", co.Name))
			}
			if progressing {
				unsettled = append(unsettled, fmt.Sprintf("%s: Progressing=True", co.Name))
			}
		}

		if len(unsettled) > 0 {
			log.Printf("    Waiting for operators to settle: %s", strings.Join(unsettled, ", "))
			return false, nil
		}

		return true, nil
	})
}

func getOperatorConditions(co *configv1.ClusterOperator) (available, degraded, progressing bool) {
	for _, cond := range co.Status.Conditions {
		switch cond.Type {
		case configv1.OperatorAvailable:
			available = (cond.Status == configv1.ConditionTrue)
		case configv1.OperatorDegraded:
			degraded = (cond.Status == configv1.ConditionTrue)
		case configv1.OperatorProgressing:
			progressing = (cond.Status == configv1.ConditionTrue)
		}
	}
	return
}

func waitForNodesStability(c client.Client, timeout time.Duration) error {
	ctx := context.Background()
	return wait.PollUntilContextTimeout(ctx, 5*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		nodeList := &corev1.NodeList{}
		err := c.List(ctx, nodeList)
		if err != nil {
			return false, nil
		}
		nodes := nodeList.Items

		notReady := []string{}
		for _, node := range nodes {
			if !isNodeReady(&node) {
				notReady = append(notReady, node.Name)
			}
		}

		if len(notReady) > 0 {
			log.Printf("    Waiting for nodes to be ready: %s", strings.Join(notReady, ", "))
			return false, nil
		}

		log.Printf("    All %d nodes are ready", len(nodes))
		return true, nil
	})
}

func isNodeReady(node *corev1.Node) bool {
	return slices.ContainsFunc(node.Status.Conditions, func(condition corev1.NodeCondition) bool {
		return condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue
	})
}

// EnableTLSGroupPreferencesFeatureGate enables the TLSGroupPreferences feature gate and waits for cluster stabilization.
// It returns true if the feature was already enabled, false if it was newly enabled.
func EnableTLSGroupPreferencesFeatureGate(c *testclient.ClientSet) (bool, error) {
	ctx := context.Background()
	log.Println("Checking and enabling TLSGroupPreferences feature gate")
	return enableFeatureGate(ctx, c, "TLSGroupPreferences")
}

// ConfigureAPIServerWithTLSGroups configures the APIServer with custom TLS profile including groups.
// It checks if the requested groups are already configured (idempotent) and only updates if needed.
// Returns (true, nil) if APIServer was updated, (false, nil) if already configured, or (false, error) on failure.
func ConfigureAPIServerWithTLSGroups(ctx context.Context, c *testclient.ClientSet, tlsGroups []configv1.TLSGroup) error {
	log.Printf("Configuring APIServer with TLS groups: %v", tlsGroups)

	apiserver := &configv1.APIServer{}
	err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, apiserver)
	if err != nil {
		return fmt.Errorf("failed to get apiserver: %w", err)
	}

	// Check if already configured (idempotent)
	if apiserver.Spec.TLSSecurityProfile != nil &&
		apiserver.Spec.TLSSecurityProfile.Type == configv1.TLSProfileCustomType &&
		apiserver.Spec.TLSSecurityProfile.Custom != nil &&
		slices.Equal(apiserver.Spec.TLSSecurityProfile.Custom.Groups, tlsGroups) &&
		apiserver.Spec.TLSAdherence == configv1.TLSAdherencePolicyStrictAllComponents {
		log.Println("APIServer TLS groups already configured, no update needed")
		return nil
	}

	// If no ciphers specified, use a default set that satisfies OpenShift requirements
	// OpenShift requires at least one HTTP/2-compatible cipher (AES_128_GCM_SHA256)
	ciphers := []string{
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"ECDHE-ECDSA-AES128-GCM-SHA256",
		"ECDHE-RSA-AES128-GCM-SHA256",
		"ECDHE-ECDSA-AES256-GCM-SHA384",
		"ECDHE-RSA-AES256-GCM-SHA384",
	}

	apiserver.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
		Type: configv1.TLSProfileCustomType,
		Custom: &configv1.CustomTLSProfile{
			TLSProfileSpec: configv1.TLSProfileSpec{
				MinTLSVersion: configv1.VersionTLS12,
				Ciphers:       ciphers,
				Groups:        tlsGroups,
			},
		},
	}
	apiserver.Spec.TLSAdherence = configv1.TLSAdherencePolicyStrictAllComponents

	err = c.Update(ctx, apiserver)
	if err != nil {
		return fmt.Errorf("failed to update apiserver: %w", err)
	}

	log.Println("APIServer TLS groups updated successfully")
	log.Println("Waiting for cluster to stabilize after TLS configuration")
	log.Println("  This may take time if MCP rollout is triggered")

	return waitForClusterStabilization(ctx, c, true, true)
}

// selectWorkerNode selects the first available worker node.
func selectWorkerNode(ctx context.Context, c *testclient.ClientSet) (string, error) {
	nodeList := &corev1.NodeList{}
	err := c.List(ctx, nodeList, client.MatchingLabels{"node-role.kubernetes.io/worker": ""})
	if err != nil {
		return "", fmt.Errorf("failed to list worker nodes: %w", err)
	}

	if len(nodeList.Items) == 0 {
		return "", fmt.Errorf("no worker nodes found")
	}

	return nodeList.Items[0].Name, nil
}

// verifyTLSGroups tests TLS group compliance using the provided executor function.
// It verifies that allowed groups succeed and rejected groups fail with proper TLS errors.
func verifyTLSGroups(ctx context.Context, allowedGroups []configv1.TLSGroup, rejectedGroup configv1.TLSGroup,
	execOpenssl func(context.Context, string) (string, error)) error {
	// Helper to get expected output name for a group
	// secp256r1 is special - openssl outputs "prime256v1", all others use the group name
	getExpectedOutputName := func(group configv1.TLSGroup) string {
		if group == configv1.TLSGroupSecP256r1 {
			return "prime256v1"
		}
		return string(group)
	}

	// Test each allowed group individually
	for _, group := range allowedGroups {
		log.Printf("  TLS 1.3 with %s curve (should succeed)", group)
		output, err := execOpenssl(ctx, string(group))
		if err != nil {
			return fmt.Errorf("%s handshake failed: %w\nOutput: %s", group, err, output)
		}
		if !strings.Contains(output, "CONNECTION ESTABLISHED") {
			return fmt.Errorf("%s: expected connection established, but handshake failed\nOutput: %s", group, output)
		}
		expectedOutputName := getExpectedOutputName(group)
		if !strings.Contains(output, expectedOutputName) {
			return fmt.Errorf("%s: expected negotiated key %s, got different key\nOutput: %s", group, expectedOutputName, output)
		}
		log.Printf("  ✓ %s handshake succeeded with %s", group, expectedOutputName)
	}

	// Test rejected group - should fail
	log.Printf("  TLS 1.3 with %s curve (should fail)", rejectedGroup)
	output, err := execOpenssl(ctx, string(rejectedGroup))
	if err == nil {
		return fmt.Errorf("%s: expected handshake to fail, but it succeeded\nOutput: %s", rejectedGroup, output)
	}
	// Require specific TLS handshake failure, not generic connection errors
	if strings.Contains(output, "CONNECTION ESTABLISHED") {
		return fmt.Errorf("%s: connection was established, but should have been rejected\nOutput: %s", rejectedGroup, output)
	}
	if !strings.Contains(output, "handshake failure") {
		return fmt.Errorf("%s: expected TLS handshake failure, got different error (may be transport/connection failure)\nOutput: %s",
			rejectedGroup, output)
	}
	log.Printf("  ✓ %s handshake correctly rejected", rejectedGroup)

	log.Println("All TLS groups compliance tests passed")
	return nil
}

func VerifyTLSGroupsOnWorkerNode(ctx context.Context, c *testclient.ClientSet, allowedGroups []configv1.TLSGroup, rejectedGroup configv1.TLSGroup) error {
	log.Printf("Testing TLS groups compliance on worker node (allowed: %v, rejected: %s)", allowedGroups, rejectedGroup)

	workerNode, err := selectWorkerNode(ctx, c)
	if err != nil {
		return err
	}
	log.Printf("  Testing on worker node: %s", workerNode)

	return verifyTLSGroups(ctx, allowedGroups, rejectedGroup, func(ctx context.Context, group string) (string, error) {
		return execOpensslOnNode(ctx, c, workerNode, group)
	})
}

// awaitPortReady polls the given address to check if it accepts connections.
// Returns nil when the port is ready, or an error if it times out.
func awaitPortReady(ctx context.Context, address string) error {
	timeout := 10 * time.Second
	err := wait.PollUntilContextTimeout(ctx, 300*time.Millisecond, timeout, true, func(ctx context.Context) (done bool, err error) {
		conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			log.Printf("    Address %s is ready", address)
			return true, nil
		}
		return false, nil
	})

	if err != nil {
		return fmt.Errorf("address %s did not become ready within %v: %w", address, timeout, err)
	}
	return nil
}

// VerifyTLSGroupsForOperatorWebhook tests TLS handshake behavior for the operator webhook on port 9443.
// It uses kubectl port-forward to create a local tunnel to the specified controller-manager pod
// and verifies that each allowed group can successfully handshake and that rejected groups fail.
func VerifyTLSGroupsForOperatorWebhook(ctx context.Context, c *testclient.ClientSet, namespace string, allowedGroups []configv1.TLSGroup,
	rejectedGroup configv1.TLSGroup) error {
	pod, err := pods.GetReadyPodWithLabel(ctx, c, namespace, OperatorLabelSelector)
	if err != nil {
		return fmt.Errorf("failed to get ready operator pod: %w", err)
	}

	log.Printf("Testing TLS groups compliance for operator webhook on port 9443 (pod: %s, allowed: %v, rejected: %s)",
		pod.Name, allowedGroups, rejectedGroup)

	return verifyTLSGroups(ctx, allowedGroups, rejectedGroup, func(ctx context.Context, group string) (string, error) {
		return execOpensslViaPortForward(ctx, namespace, pod.Name, group)
	})
}

// execOpensslViaPortForward uses kubectl port-forward to test the webhook port 9443.
// It creates a local tunnel to the specified controller-manager pod and tests TLS handshake via localhost.
func execOpensslViaPortForward(ctx context.Context, namespace, podName, groups string) (string, error) {
	log.Printf("    Using port-forward to pod %s", podName)

	// Let kubectl pick an available port to avoid TOCTOU race
	// Use :9443 syntax so kubectl selects the local port
	portForwardCmd := exec.CommandContext(ctx, "kubectl", "port-forward", "-n", namespace,
		fmt.Sprintf("pod/%s", podName), fmt.Sprintf(":%s", OperatorWebhookPort))

	// Capture stdout to parse the actual port kubectl chose
	stdoutPipe, err := portForwardCmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Capture stderr for debugging
	stderrPipe, err := portForwardCmd.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := portForwardCmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start port-forward: %w", err)
	}

	// Ensure port-forward process is killed and reaped on return
	defer func() {
		log.Printf("    Stopping port-forward")
		if portForwardCmd.Process != nil {
			if killErr := portForwardCmd.Process.Kill(); killErr != nil {
				log.Printf("    Warning: failed to kill port-forward process: %v", killErr)
			}
		}
		// Wait for the process to exit and release resources
		// This is required after Start() to prevent resource leaks
		if waitErr := portForwardCmd.Wait(); waitErr != nil {
			// Ignore the expected "signal: killed" error after Kill()
			if !strings.Contains(waitErr.Error(), "signal: killed") {
				log.Printf("    Warning: unexpected error waiting for port-forward: %v", waitErr)
			}
		}
	}()

	// Read stdout to parse the actual endpoint kubectl selected
	// kubectl outputs: "Forwarding from 127.0.0.1:PORT -> 9443" or "Forwarding from [::1]:PORT -> 9443"
	scanner := bufio.NewScanner(stdoutPipe)
	var localEndpoint string
	done := make(chan error, 1)
	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			log.Printf("    kubectl: %s", line)
			// Parse "Forwarding from 127.0.0.1:12345 -> 9443" or "Forwarding from [::1]:12345 -> 9443"
			if strings.Contains(line, "Forwarding from") {
				// Extract the endpoint before " -> "
				parts := strings.Split(line, " -> ")
				if len(parts) >= 2 {
					// Get the local endpoint after "Forwarding from "
					endpoint := strings.TrimSpace(strings.TrimPrefix(parts[0], "Forwarding from "))
					// Validate it's a valid host:port using net.SplitHostPort
					// This handles both IPv4 (127.0.0.1:12345) and IPv6 ([::1]:12345)
					if _, _, err := net.SplitHostPort(endpoint); err == nil {
						localEndpoint = endpoint
						done <- nil
						return
					}
				}
			}
		}
		done <- fmt.Errorf("failed to parse endpoint from kubectl output")
	}()

	// Also read stderr to prevent pipe blocking
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			log.Printf("    kubectl stderr: %s", scanner.Text())
		}
	}()

	// Wait for endpoint parsing with timeout
	select {
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("failed to get endpoint from kubectl: %w", err)
		}
	case <-time.After(30 * time.Second):
		return "", fmt.Errorf("timeout waiting for kubectl to report endpoint")
	case <-ctx.Done():
		return "", ctx.Err()
	}

	log.Printf("    kubectl selected local endpoint %s", localEndpoint)

	// Poll for port readiness using the same endpoint kubectl bound to
	if err := awaitPortReady(ctx, localEndpoint); err != nil {
		return "", fmt.Errorf("port-forward did not become ready: %w", err)
	}

	// Test TLS handshake with bounded timeout to prevent hanging
	// Create a timeout context even if caller passed Background()
	probeCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	// Execute openssl directly (not via bash) for proper signal handling
	// Use the same endpoint that kubectl bound to (supports both IPv4 and IPv6)
	log.Printf("    Executing: openssl s_client -connect %s -tls1_3 -groups %s -brief", localEndpoint, groups)
	cmd := exec.CommandContext(probeCtx, "openssl", "s_client",
		"-connect", localEndpoint,
		"-tls1_3",
		"-groups", groups,
		"-brief")

	// Provide "Q" as stdin to make openssl exit after handshake
	cmd.Stdin = strings.NewReader("Q\n")

	output, execErr := cmd.CombinedOutput()
	return string(output), execErr
}

// execOpensslOnNode executes openssl s_client on a node using a debug pod.
// This creates a privileged debug pod on the node and runs the openssl command in it.
func execOpensslOnNode(ctx context.Context, c *testclient.ClientSet, nodeName, groups string) (string, error) {

	// Create unique debug pod name
	debugPodName := fmt.Sprintf("tls-groups-debug-%d", time.Now().UnixNano())

	// Create a privileged pod that has access to the host filesystem
	privileged := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      debugPodName,
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			NodeName:      nodeName,
			HostNetwork:   true,
			HostPID:       true,
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:    "debug",
					Image:   "registry.redhat.io/rhel8/support-tools:latest",
					Command: []string{"/bin/bash", "-c", "sleep 600"},
					SecurityContext: &corev1.SecurityContext{
						Privileged: &privileged,
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "host-root",
							MountPath: "/host",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "host-root",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/",
						},
					},
				},
			},
		},
	}

	log.Printf("    Creating debug pod %s on node %s", debugPodName, nodeName)

	// Create the pod
	err := c.Create(ctx, pod)
	if err != nil {
		return "", fmt.Errorf("failed to create debug pod: %w", err)
	}

	// Ensure pod is deleted on return
	defer func() {
		log.Printf("    Cleaning up debug pod %s", debugPodName)

		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		deletePolicy := metav1.DeletePropagationForeground
		deleteOptions := &client.DeleteOptions{
			PropagationPolicy: &deletePolicy,
		}
		if err := c.Delete(cleanupCtx, pod, deleteOptions); err != nil {
			log.Printf("    Warning: failed to delete debug pod %s: %v", debugPodName, err)
		}
	}()

	// Wait for pod to be running and ready
	log.Printf("    Waiting for debug pod to be ready...")
	var readyPod *corev1.Pod
	pollErr := wait.PollUntilContextTimeout(ctx, 2*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		tempPod := &corev1.Pod{}
		getErr := c.Get(ctx, types.NamespacedName{Name: debugPodName, Namespace: "default"}, tempPod)
		if getErr != nil {
			log.Printf("    Pod not found yet: %v", getErr)
			return false, nil
		}

		if tempPod.Status.Phase == corev1.PodRunning && podutil.IsPodReady(tempPod) {
			readyPod = tempPod
			return true, nil
		}

		log.Printf("    Pod status: %s, Ready: %v", tempPod.Status.Phase, podutil.IsPodReady(tempPod))
		return false, nil
	})

	if pollErr != nil {
		return "", fmt.Errorf("debug pod did not become ready within timeout: %w", pollErr)
	}

	log.Printf("    Debug pod is ready")

	// Execute openssl command using chroot to access host binaries
	// We need to use sh -c because we need the pipe and proper input handling
	opensslCmd := fmt.Sprintf("echo Q | chroot /host openssl s_client -connect 127.0.0.1:9301 -tls1_3 -groups %s -brief 2>&1", groups)
	cmd := []string{
		"sh", "-c", opensslCmd,
	}

	log.Printf("    Executing: echo Q | chroot /host openssl s_client -connect 127.0.0.1:9301 -tls1_3 -groups %s -brief", groups)

	stdout, stderr, execErr := executil.RunExecCommandWithContext(ctx, c, readyPod, cmd...)
	fullOutput := stdout + stderr

	log.Printf("    Command output length: stdout=%d, stderr=%d", len(stdout), len(stderr))
	if len(fullOutput) > 0 {
		// Log full output for debugging
		log.Printf("    Full output:\n%s", fullOutput)
	}

	if execErr != nil {
		// For rejected handshakes, openssl returns an error, so we return both output and error
		// This is expected for test 3 (secp384r1 should fail)
		log.Printf("    Exec error: %v", execErr)
		return fullOutput, execErr
	}

	return fullOutput, nil
}

func determineTLSTestBehavior(apiServerSpec *configv1.APIServerSpec) (expectTLS12Reject bool, description string) {
	if apiServerSpec.TLSSecurityProfile == nil {
		return false, "No TLS security profile configured: both TLS 1.2 and TLS 1.3 should work"
	}

	tlsAdherence := apiServerSpec.TLSAdherence
	profileType := apiServerSpec.TLSSecurityProfile.Type

	if profileType == configv1.TLSProfileModernType && tlsAdherence == configv1.TLSAdherencePolicyStrictAllComponents {
		return true, "Modern with StrictAllComponents: TLS 1.3 only, TLS 1.2 should be rejected"
	}

	return false, "Both TLS 1.2 and TLS 1.3 should work"
}

func execCommandInPod(ctx context.Context, c *testclient.ClientSet, namespace, labelSelector, containerName string,
	command []string) (string, error) {
	pod, err := pods.GetReadyPodWithLabel(ctx, c, namespace, labelSelector)
	if err != nil {
		return "", fmt.Errorf("no ready pod found: %w", err)
	}

	log.Printf("Executing command in pod %s/%s (container: %s)", namespace, pod.Name, containerName)
	stdout, stderr, err := executil.RunExecCommandWithContext(ctx, c, pod, command...)
	return stdout + stderr, err
}

func testTLS13Connection(ctx context.Context, c *testclient.ClientSet, namespace, labelSelector, containerName, port string) error {
	log.Printf("Testing TLS 1.3 connection on port %s using curl...", port)
	cmd := []string{"curl", "-v", "--tls-max", "1.3", "--tlsv1.3", "-k", "https://localhost:" + port + "/metrics"}
	output, err := execCommandInPod(ctx, c, namespace, labelSelector, containerName, cmd)
	if err != nil {
		return fmt.Errorf("TLS 1.3 connection on port %s failed: %v\nOutput: %s", port, err, output)
	}

	if !strings.Contains(output, "TLSv1.3") && !strings.Contains(output, "HTTP/") && !strings.Contains(output, "Unauthorized") {
		return fmt.Errorf("TLS 1.3 connection on port %s did not complete successfully\nOutput: %s", port, output)
	}
	log.Printf("Port %s TLS 1.3 connection succeeded", port)
	return nil
}

func testTLS12Connection(ctx context.Context, c *testclient.ClientSet, namespace, labelSelector, containerName, port string, expectReject bool) error {
	if expectReject {
		log.Printf("Testing TLS 1.2 connection on port %s using curl (should be REJECTED)...", port)
		cmd := []string{"curl", "-v", "--tls-max", "1.2", "--tlsv1.2", "-k", "https://localhost:" + port + "/metrics"}
		output, err := execCommandInPod(ctx, c, namespace, labelSelector, containerName, cmd)

		if err == nil {
			return fmt.Errorf("TLS 1.2 connection on port %s SUCCEEDED but should have been REJECTED\nOutput: %s", port, output)
		}

		// Require BOTH exit code 35 AND explicit protocol version alert
		var exitErr remoteexec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitStatus() == 35 &&
			strings.Contains(strings.ToLower(output), "tlsv1 alert protocol version") {
			log.Printf("Port %s TLS 1.2 correctly rejected (protocol version)", port)
			return nil
		}

		return fmt.Errorf("TLS 1.2 rejection check on port %s failed without confirming protocol rejection: %w\nOutput: %s", port, err, output)
	} else {
		log.Printf("Testing TLS 1.2 connection on port %s using curl...", port)
		cmd := []string{"curl", "-v", "--tls-max", "1.2", "--tlsv1.2", "-k", "https://localhost:" + port + "/metrics"}
		output, err := execCommandInPod(ctx, c, namespace, labelSelector, containerName, cmd)
		if err != nil {
			return fmt.Errorf("TLS 1.2 connection on port %s failed: %v\nOutput: %s", port, err, output)
		}

		if !strings.Contains(output, "TLSv1.2") && !strings.Contains(output, "HTTP/") && !strings.Contains(output, "Unauthorized") {
			return fmt.Errorf("TLS 1.2 connection on port %s did not complete successfully\nOutput: %s", port, output)
		}
		log.Printf("Port %s TLS 1.2 connection succeeded", port)
	}
	return nil
}

func VerifyIngressNodeFirewallTLSComplianceInPod(ctx context.Context, c *testclient.ClientSet, namespace string,
	apiServerSpec *configv1.APIServerSpec) error {

	expectTLS12Reject, description := determineTLSTestBehavior(apiServerSpec)

	profileTypeLabel := "<unset>"
	if apiServerSpec.TLSSecurityProfile != nil {
		profileTypeLabel = string(apiServerSpec.TLSSecurityProfile.Type)
	}
	log.Printf("Testing with profile: %s (%s)", profileTypeLabel, description)

	// Test both daemon and operator components
	components := []struct {
		name          string
		labelSelector string
		containerName string
		port          string
	}{
		{
			name:          "daemon",
			labelSelector: DaemonSetLabelSelector,
			containerName: DaemonMetricsContainer,
			port:          DaemonMetricsPort,
		},
		{
			name:          "operator webhook",
			labelSelector: OperatorLabelSelector,
			containerName: OperatorWebhookContainer,
			port:          OperatorWebhookPort,
		},
	}

	for _, comp := range components {
		log.Printf("Testing TLS compliance for %s on port %s", comp.name, comp.port)

		if err := testTLS13Connection(ctx, c, namespace, comp.labelSelector, comp.containerName, comp.port); err != nil {
			return err
		}

		if err := testTLS12Connection(ctx, c, namespace, comp.labelSelector, comp.containerName, comp.port, expectTLS12Reject); err != nil {
			return err
		}

		if expectTLS12Reject {
			log.Printf("%s port %s: TLS 1.3 works, TLS 1.2 correctly rejected", comp.name, comp.port)
		} else {
			log.Printf("%s port %s: TLS 1.2 and TLS 1.3 compliance verified", comp.name, comp.port)
		}
	}

	return nil
}
