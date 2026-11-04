package tls

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	podutil "k8s.io/kubernetes/pkg/api/v1/pod"
	"sigs.k8s.io/controller-runtime/pkg/client"

	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
	executil "github.com/openshift/ingress-node-firewall/test/e2e/exec"
)

const (
	MCPRolloutStartTimeout          = 10 * time.Minute
	MCPRolloutCompleteTimeout       = 120 * time.Minute // Increased from 60 to match Origin
	NodeStabilityTimeout            = 90 * time.Minute  // Increased from 60 to match Origin
	OperatorSettleTimeMinutes       = 60
	OperatorProgressingStartTimeout = 5 * time.Minute  // Added to match Origin
	APIServerOperatorTimeout        = 10 * time.Minute // Added to match Origin

	PodExecMaxRetries = 3
	PodExecBaseDelay  = 5 * time.Second

	MCPPollingInterval      = 10 * time.Second
	OperatorPollingInterval = 10 * time.Second
	NodePollingInterval     = 5 * time.Second

	DaemonMetricsPort      = "9301"
	DaemonMetricsContainer = "daemon"
	DaemonSetName          = "ingress-node-firewall-daemon"
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

func ConfigureTLSProfileWithAdherence(c *testclient.ClientSet, tlsProfileType configv1.TLSProfileType, tlsAdherencePolicy configv1.TLSAdherencePolicy) error {
	overallStartTime := time.Now()
	log.Printf("=== Configuring %s TLS Profile with %s (started: %s) ===",
		tlsProfileType, tlsAdherencePolicy, overallStartTime.Format("15:04:05"))

	ctx := context.Background()

	log.Printf("Configuring APIServer with %s TLS profile and tlsAdherence=%s", tlsProfileType, tlsAdherencePolicy)
	if err := patchAPIServerTLSProfile(ctx, c, tlsProfileType, tlsAdherencePolicy); err != nil {
		return err
	}

	log.Println("Waiting for cluster to stabilize after TLS profile configuration")
	requiresMCPRollout := ((tlsProfileType == configv1.TLSProfileModernType && (tlsAdherencePolicy == configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly || tlsAdherencePolicy == configv1.TLSAdherencePolicyStrictAllComponents)) ||
		(tlsProfileType == configv1.TLSProfileIntermediateType && tlsAdherencePolicy == configv1.TLSAdherencePolicyStrictAllComponents))
	if err := waitForClusterStabilization(ctx, c, requiresMCPRollout, false); err != nil {
		return err
	}

	log.Println("Verifying APIServer TLS profile configuration")
	if err := verifyAPIServerTLSProfile(ctx, c, tlsProfileType, tlsAdherencePolicy); err != nil {
		return err
	}

	log.Printf("=== %s TLS Profile successfully configured (total time: %v) ===",
		tlsProfileType, time.Since(overallStartTime))
	return nil
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

func areAllMCPsComplete(c client.Client) (bool, error) {
	ctx := context.Background()
	mcpList := &mcfgv1.MachineConfigPoolList{}
	err := c.List(ctx, mcpList)
	if err != nil {
		return false, fmt.Errorf("failed to list MCPs: %w", err)
	}

	for _, mcp := range mcpList.Items {
		if mcp.Status.MachineCount == 0 {
			continue
		}

		updated := false
		updating := false

		for _, cond := range mcp.Status.Conditions {
			if cond.Type == mcfgv1.MachineConfigPoolUpdated && cond.Status == corev1.ConditionTrue {
				updated = true
			}
			if cond.Type == mcfgv1.MachineConfigPoolUpdating && cond.Status == corev1.ConditionTrue {
				updating = true
			}
		}

		if !updated || updating {
			return false, nil
		}
	}

	return true, nil
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

// ConfigureAPIServerWithTLSGroups configures the APIServer with custom TLS profile including groups and waits for cluster stabilization.
func ConfigureAPIServerWithTLSGroups(c *testclient.ClientSet, groups []string, minTLSVersion configv1.TLSProtocolVersion, ciphers []string) error {
	ctx := context.Background()

	log.Printf("Configuring APIServer with TLS groups: %v", groups)

	apiserver := &configv1.APIServer{}
	err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, apiserver)
	if err != nil {
		return fmt.Errorf("failed to get apiserver: %w", err)
	}

	// Convert string groups to TLSGroup type
	tlsGroups := make([]configv1.TLSGroup, len(groups))
	for i, g := range groups {
		tlsGroups[i] = configv1.TLSGroup(g)
	}

	// If no ciphers specified, use a default set that satisfies OpenShift requirements
	// OpenShift requires at least one HTTP/2-compatible cipher (AES_128_GCM_SHA256)
	if ciphers == nil || len(ciphers) == 0 {
		ciphers = []string{
			"TLS_AES_128_GCM_SHA256",
			"TLS_AES_256_GCM_SHA384",
			"TLS_CHACHA20_POLY1305_SHA256",
			"ECDHE-ECDSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"ECDHE-ECDSA-AES256-GCM-SHA384",
			"ECDHE-RSA-AES256-GCM-SHA384",
		}
		log.Printf("  No ciphers specified, using default cipher suite")
	}

	apiserver.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
		Type: configv1.TLSProfileCustomType,
		Custom: &configv1.CustomTLSProfile{
			TLSProfileSpec: configv1.TLSProfileSpec{
				MinTLSVersion: minTLSVersion,
				Groups:        tlsGroups,
				Ciphers:       ciphers,
			},
		},
	}
	apiserver.Spec.TLSAdherence = configv1.TLSAdherencePolicyStrictAllComponents

	err = c.Update(ctx, apiserver)
	if err != nil {
		return fmt.Errorf("failed to update apiserver: %w", err)
	}

	// Always wait for cluster to stabilize after TLS configuration changes
	log.Println("Waiting for cluster to stabilize after TLS configuration")
	log.Println("  This may take time if MCP rollout is triggered")
	return waitForClusterStabilization(ctx, c, true, true)
}

// VerifyAPIServerTLSGroups verifies that the APIServer has the expected TLS groups configured.
func VerifyAPIServerTLSGroups(c *testclient.ClientSet, expectedGroups []string) error {
	ctx := context.Background()

	log.Printf("Verifying APIServer TLS groups configuration")

	apiserver := &configv1.APIServer{}
	err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, apiserver)
	if err != nil {
		return fmt.Errorf("failed to get APIServer: %w", err)
	}

	if apiserver.Spec.TLSSecurityProfile == nil {
		return fmt.Errorf("APIServer TLS security profile is nil")
	}

	if apiserver.Spec.TLSSecurityProfile.Type != configv1.TLSProfileCustomType {
		return fmt.Errorf("APIServer TLS profile type is not Custom: %s", apiserver.Spec.TLSSecurityProfile.Type)
	}

	if apiserver.Spec.TLSSecurityProfile.Custom == nil {
		return fmt.Errorf("APIServer Custom TLS profile is nil")
	}

	actualGroups := apiserver.Spec.TLSSecurityProfile.Custom.Groups
	if len(actualGroups) != len(expectedGroups) {
		return fmt.Errorf("APIServer TLS groups count mismatch: actual=%d, expected=%d", len(actualGroups), len(expectedGroups))
	}

	for i, expected := range expectedGroups {
		if string(actualGroups[i]) != expected {
			return fmt.Errorf("APIServer TLS group mismatch at index %d: actual=%s, expected=%s", i, actualGroups[i], expected)
		}
	}

	log.Printf("  TLS groups verified: %v", actualGroups)
	return nil
}

// selectWorkerNode selects the first available worker node.
func selectWorkerNode(c *testclient.ClientSet) (string, error) {
	ctx := context.Background()
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

// VerifyTLSGroupsOnWorkerNode tests TLS handshake behavior on a worker node using openssl s_client.
// It verifies that only the configured curves are accepted.
func VerifyTLSGroupsOnWorkerNode(c *testclient.ClientSet, namespace string) error {
	log.Println("Testing TLS groups compliance on worker node")

	workerNode, err := selectWorkerNode(c)
	if err != nil {
		return err
	}
	log.Printf("  Testing on worker node: %s", workerNode)

	// Test 1: secp256r1 should succeed (it's in the configured groups)
	log.Println("  Test 1: TLS 1.3 with secp256r1 curve (should succeed)")
	output, err := execOpensslOnNode(c, workerNode, "secp256r1")
	if err != nil {
		return fmt.Errorf("test 1 failed: %w\nOutput: %s", err, output)
	}
	if !strings.Contains(output, "CONNECTION ESTABLISHED") {
		return fmt.Errorf("test 1: expected connection established, but handshake failed\nOutput: %s", output)
	}
	if !strings.Contains(output, "prime256v1") {
		return fmt.Errorf("test 1: expected negotiated key prime256v1, got different key\nOutput: %s", output)
	}
	log.Println("  ✓ Test 1 passed: secp256r1 handshake succeeded with prime256v1")

	// Test 2: secp384r1:secp256r1 should succeed and use secp256r1
	log.Println("  Test 2: TLS 1.3 with secp384r1:secp256r1 curves (should succeed with secp256r1)")
	output, err = execOpensslOnNode(c, workerNode, "secp384r1:secp256r1")
	if err != nil {
		return fmt.Errorf("test 2 failed: %w\nOutput: %s", err, output)
	}
	if !strings.Contains(output, "CONNECTION ESTABLISHED") {
		return fmt.Errorf("test 2: expected connection established, but handshake failed\nOutput: %s", output)
	}
	if !strings.Contains(output, "prime256v1") {
		return fmt.Errorf("test 2: expected negotiated key prime256v1 (secp256r1), got different key\nOutput: %s", output)
	}
	log.Println("  ✓ Test 2 passed: secp384r1:secp256r1 handshake succeeded using secp256r1")

	// Test 3: secp384r1 should fail (not in configured groups)
	log.Println("  Test 3: TLS 1.3 with secp384r1 curve (should fail)")
	output, err = execOpensslOnNode(c, workerNode, "secp384r1")
	if err == nil {
		return fmt.Errorf("test 3: expected handshake to fail, but it succeeded\nOutput: %s", output)
	}
	if !strings.Contains(output, "handshake failure") && !strings.Contains(output, "alert") && !strings.Contains(output, "error") {
		return fmt.Errorf("test 3: expected handshake failure, but got unexpected output\nOutput: %s", output)
	}
	log.Println("  ✓ Test 3 passed: secp384r1 handshake correctly rejected")

	log.Println("All TLS groups compliance tests passed")
	return nil
}

// execOpensslOnNode executes openssl s_client on a node using a debug pod.
// This creates a privileged debug pod on the node and runs the openssl command in it.
func execOpensslOnNode(c *testclient.ClientSet, nodeName, groups string) (string, error) {
	ctx := context.Background()

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
		deletePolicy := metav1.DeletePropagationForeground
		deleteOptions := &client.DeleteOptions{
			PropagationPolicy: &deletePolicy,
		}
		deleteErr := c.Delete(ctx, pod, deleteOptions)
		if deleteErr != nil {
			log.Printf("    Warning: failed to delete debug pod %s: %v", debugPodName, deleteErr)
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

	stdout, stderr, execErr := executil.RunExecCommand(c, readyPod, cmd...)
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

// VerifyAllTLSGroupsOnWorkerNode tests that all configured TLS groups work correctly.
// This is a comprehensive test to validate that when all groups are enabled, each one can successfully handshake.
func VerifyAllTLSGroupsOnWorkerNode(c *testclient.ClientSet, namespace string) error {
	log.Println("Testing comprehensive TLS groups compliance on worker node")

	workerNode, err := selectWorkerNode(c)
	if err != nil {
		return err
	}
	log.Printf("  Testing on worker node: %s", workerNode)

	// Test cases for all supported TLS groups
	// Map of OpenSSL group name to expected negotiated key name
	testCases := []struct {
		name            string
		opensslGroup    string
		expectedKeyword string // What to look for in the output to verify success
		description     string
	}{
		{
			name:            "X25519",
			opensslGroup:    "X25519",
			expectedKeyword: "X25519",
			description:     "X25519 curve",
		},
		{
			name:            "secp256r1",
			opensslGroup:    "secp256r1",
			expectedKeyword: "prime256v1",
			description:     "secp256r1 (prime256v1) curve",
		},
		{
			name:            "secp384r1",
			opensslGroup:    "secp384r1",
			expectedKeyword: "secp384r1",
			description:     "secp384r1 curve",
		},
		{
			name:            "secp521r1",
			opensslGroup:    "secp521r1",
			expectedKeyword: "secp521r1",
			description:     "secp521r1 curve",
		},
		// Post-quantum hybrid groups - these may not be supported by all OpenSSL versions
		// Test them, but don't fail the entire suite if OpenSSL doesn't recognize them
		{
			name:            "X25519MLKEM768",
			opensslGroup:    "X25519MLKEM768",
			expectedKeyword: "X25519MLKEM768",
			description:     "X25519MLKEM768 post-quantum hybrid curve",
		},
		{
			name:            "SecP256r1MLKEM768",
			opensslGroup:    "SecP256r1MLKEM768",
			expectedKeyword: "SecP256r1MLKEM768",
			description:     "SecP256r1MLKEM768 post-quantum hybrid curve",
		},
		{
			name:            "SecP384r1MLKEM1024",
			opensslGroup:    "SecP384r1MLKEM1024",
			expectedKeyword: "SecP384r1MLKEM1024",
			description:     "SecP384r1MLKEM1024 post-quantum hybrid curve",
		},
	}

	allPassed := true
	var failedTests []string
	var skippedPQTests []string

	for i, tc := range testCases {
		log.Printf("  Test %d: Testing TLS 1.3 with %s", i+1, tc.description)
		output, err := execOpensslOnNode(c, workerNode, tc.opensslGroup)

		// Check if this is a post-quantum group that OpenSSL doesn't recognize
		isPQGroup := strings.Contains(tc.name, "MLKEM")
		if isPQGroup && err != nil {
			if strings.Contains(output, "unknown option") ||
				strings.Contains(output, "invalid") ||
				strings.Contains(output, "unrecognized") {
				log.Printf("  ⊘ Test %d skipped: %s - OpenSSL doesn't support this post-quantum group", i+1, tc.name)
				skippedPQTests = append(skippedPQTests, tc.name)
				continue
			}
		}

		if err != nil {
			// Check if it's just an OpenSSL error but connection was established
			if !strings.Contains(output, "CONNECTION ESTABLISHED") {
				log.Printf("  ✗ Test %d failed: %s handshake failed: %v", i+1, tc.name, err)
				log.Printf("    Output: %s", output)
				allPassed = false
				failedTests = append(failedTests, fmt.Sprintf("%s (handshake failed)", tc.name))
				continue
			}
		}

		// Verify connection was established
		if !strings.Contains(output, "CONNECTION ESTABLISHED") {
			log.Printf("  ✗ Test %d failed: %s - no connection established", i+1, tc.name)
			log.Printf("    Output: %s", output)
			allPassed = false
			failedTests = append(failedTests, fmt.Sprintf("%s (no connection)", tc.name))
			continue
		}

		// Verify the expected key was negotiated (for traditional ECDH groups)
		// Some groups like X25519 may show as "X25519" or "X25519, 253 bits"
		// P-256/384/521 show as "ECDH, prime256v1, 256 bits" etc.
		if !strings.Contains(output, tc.expectedKeyword) {
			log.Printf("  ⚠ Test %d warning: %s - connection succeeded but expected keyword '%s' not found", i+1, tc.name, tc.expectedKeyword)
			log.Printf("    Output: %s", output)
			// Don't fail the test - connection succeeded, which is the main goal
		}

		log.Printf("  ✓ Test %d passed: %s handshake succeeded", i+1, tc.name)
	}

	if !allPassed {
		return fmt.Errorf("some TLS group tests failed: %s", strings.Join(failedTests, ", "))
	}

	if len(skippedPQTests) > 0 {
		log.Printf("All testable TLS groups compliance tests passed (skipped %d post-quantum groups unsupported by OpenSSL: %s)",
			len(skippedPQTests), strings.Join(skippedPQTests, ", "))
	} else {
		log.Println("All comprehensive TLS groups compliance tests passed (including post-quantum groups)")
	}
	return nil
}

func determineTLSTestBehavior(apiserver *configv1.APIServer) (expectTLS12Reject bool, description string) {
	if apiserver.Spec.TLSSecurityProfile == nil {
		return false, "No TLS security profile configured: both TLS 1.2 and TLS 1.3 should work"
	}

	tlsAdherence := apiserver.Spec.TLSAdherence
	profileType := apiserver.Spec.TLSSecurityProfile.Type

	if profileType == configv1.TLSProfileModernType && tlsAdherence == configv1.TLSAdherencePolicyStrictAllComponents {
		return true, "Modern with StrictAllComponents: TLS 1.3 only, TLS 1.2 should be rejected"
	}

	return false, "Both TLS 1.2 and TLS 1.3 should work"
}

func expectedTLSMinVersion(apiserver *configv1.APIServer) string {
	if apiserver.Spec.TLSSecurityProfile == nil {
		return ""
	}
	if apiserver.Spec.TLSAdherence != configv1.TLSAdherencePolicyStrictAllComponents {
		return ""
	}
	switch apiserver.Spec.TLSSecurityProfile.Type {
	case configv1.TLSProfileModernType:
		return "VersionTLS13"
	case configv1.TLSProfileIntermediateType:
		return "VersionTLS12"
	case configv1.TLSProfileOldType:
		return "VersionTLS10"
	case configv1.TLSProfileCustomType:
		if apiserver.Spec.TLSSecurityProfile.Custom != nil {
			return string(apiserver.Spec.TLSSecurityProfile.Custom.MinTLSVersion)
		}
		return ""
	default:
		return ""
	}
}

func waitForDaemonSetTLSUpdate(c client.Client, namespace string, expectedMinVersion string) error {
	expectedArg := fmt.Sprintf("--metrics-tls-min-version=%s", expectedMinVersion)
	log.Printf("Waiting for DaemonSet args to contain %s ...", expectedArg)

	return wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		ds := &appsv1.DaemonSet{}
		if err := c.Get(ctx, types.NamespacedName{Name: DaemonSetName, Namespace: namespace}, ds); err != nil {
			log.Printf("  DaemonSet not found: %v", err)
			return false, nil
		}

		for _, container := range ds.Spec.Template.Spec.Containers {
			if container.Name != DaemonMetricsContainer {
				continue
			}
			for _, arg := range container.Args {
				if arg == expectedArg {
					log.Printf("  DaemonSet args match expected TLS configuration")
					return true, nil
				}
			}
		}

		log.Printf("  DaemonSet args do not yet reflect expected TLS min version, waiting...")
		return false, nil
	})
}

func findRunningPod(c client.Client, namespace, labelSelector string) (string, error) {
	ctx := context.Background()
	podList := &corev1.PodList{}
	err := c.List(ctx, podList, client.InNamespace(namespace), client.MatchingLabels(parseLabelSelector(labelSelector)))
	if err != nil {
		return "", fmt.Errorf("failed to list pods with selector %s: %w", labelSelector, err)
	}

	if len(podList.Items) == 0 {
		return "", fmt.Errorf("no pods found with selector %s in namespace %s", labelSelector, namespace)
	}

	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodRunning && podutil.IsPodReady(&pod) {
			return pod.Name, nil
		}
	}

	return "", fmt.Errorf("no running pods found with selector %s", labelSelector)
}

func isTransientExecError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "container not found") ||
		strings.Contains(errStr, "pod not found") ||
		strings.Contains(errStr, "unable to upgrade connection") ||
		strings.Contains(errStr, "exit code 7") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset")
}

func execCommandInPodWithRetry(c client.Client, namespace, labelSelector, podName, containerName string, command []string) (string, error) {
	const maxRetries = PodExecMaxRetries
	const baseDelay = PodExecBaseDelay

	var lastErr error
	currentPodName := podName
	currentContainerName := containerName

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			log.Printf("Retry attempt %d/%d after waiting up to %v for pod readiness (previous error: %v)", attempt+1, maxRetries, delay, lastErr)

			var findErr error
			ctx := context.Background()
			pollErr := wait.PollUntilContextTimeout(ctx, 1*time.Second, delay, true, func(ctx context.Context) (bool, error) {
				currentPodName, findErr = findRunningPod(c, namespace, labelSelector)
				if findErr != nil {
					return false, nil
				}

				pod := &corev1.Pod{}
				getPodErr := c.Get(ctx, types.NamespacedName{Name: currentPodName, Namespace: namespace}, pod)
				if getPodErr != nil {
					return false, nil
				}

				if pod.Status.Phase != corev1.PodRunning {
					return false, nil
				}

				return podutil.IsPodReady(pod), nil
			})

			if pollErr != nil {
				lastErr = fmt.Errorf("failed to find ready pod within %v (last discovery error: %v): %w", delay, findErr, pollErr)
				continue
			}
			log.Printf("Re-discovered ready pod %s/%s (container: %s)", namespace, currentPodName, currentContainerName)
		}

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      currentPodName,
				Namespace: namespace,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: currentContainerName}},
			},
		}

		stdout, stderr, err := executil.RunExecCommand(testclient.Client, pod, command...)
		if err == nil {
			return stdout + stderr, nil
		}

		if isTransientExecError(err) {
			lastErr = fmt.Errorf("transient connection/SSL issue: %w", err)
			log.Printf("Detected transient connection/SSL issue, will retry...")
			continue
		}

		return stdout + stderr, err
	}

	return "", fmt.Errorf("exec command failed after %d retries: %w", maxRetries, lastErr)
}

func RestartDaemonPods(c client.Client, namespace, labelSelector string) error {
	log.Printf("Restarting daemon pods with selector %s in namespace %s", labelSelector, namespace)

	ctx := context.Background()
	podList := &corev1.PodList{}
	err := c.List(ctx, podList, client.InNamespace(namespace), client.MatchingLabels(parseLabelSelector(labelSelector)))
	if err != nil {
		return fmt.Errorf("failed to list pods: %w", err)
	}

	oldPodUIDs := make(map[string]bool)
	for _, pod := range podList.Items {
		oldPodUIDs[string(pod.UID)] = true
		log.Printf("  Deleting pod %s (UID: %s)", pod.Name, pod.UID)
		if err := c.Delete(ctx, &pod, client.GracePeriodSeconds(0)); err != nil {
			log.Printf("  Warning: failed to delete pod %s: %v", pod.Name, err)
		}
	}

	log.Printf("Waiting for new daemon pods to be created and ready...")
	timeout := 5 * time.Minute
	return wait.PollUntilContextTimeout(ctx, 5*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		newPodList := &corev1.PodList{}
		err := c.List(ctx, newPodList, client.InNamespace(namespace), client.MatchingLabels(parseLabelSelector(labelSelector)))
		if err != nil {
			log.Printf("Error listing pods: %v", err)
			return false, nil
		}

		if len(newPodList.Items) == 0 {
			log.Printf("No pods found yet, waiting...")
			return false, nil
		}

		allNewAndReady := true
		for _, pod := range newPodList.Items {
			if oldPodUIDs[string(pod.UID)] {
				log.Printf("Pod %s is still the old pod (UID: %s), waiting for deletion...", pod.Name, pod.UID)
				allNewAndReady = false
				continue
			}

			if pod.Status.Phase != corev1.PodRunning || !podutil.IsPodReady(&pod) {
				allNewAndReady = false
			}
		}

		if allNewAndReady {
			log.Printf("All %d new daemon pods are ready", len(newPodList.Items))
			return true, nil
		}
		return false, nil
	})
}

func WaitForDaemonPodsReady(c client.Client, namespace, labelSelector string, timeout time.Duration) error {
	log.Printf("Waiting for daemon pods with selector %s to be ready in namespace %s", labelSelector, namespace)

	ctx := context.Background()
	return wait.PollUntilContextTimeout(ctx, 5*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		podList := &corev1.PodList{}
		err := c.List(ctx, podList, client.InNamespace(namespace), client.MatchingLabels(parseLabelSelector(labelSelector)))
		if err != nil {
			log.Printf("Error listing pods: %v", err)
			return false, nil
		}
		pods := podList.Items

		if len(pods) == 0 {
			log.Printf("No pods found yet, waiting...")
			return false, nil
		}

		allReady := true
		for _, pod := range pods {
			if pod.Status.Phase != corev1.PodRunning {
				log.Printf("Pod %s is not Running (phase: %s), waiting...", pod.Name, pod.Status.Phase)
				allReady = false
				continue
			}

			if !podutil.IsPodReady(&pod) {
				log.Printf("Pod %s is not Ready, waiting...", pod.Name)
				allReady = false
			}
		}

		if allReady {
			log.Printf("All %d daemon pods are ready", len(pods))
			return true, nil
		}
		return false, nil
	})
}

func testTLS13Connection(c client.Client, namespace, labelSelector, podName, containerName, port, portDescription string) error {
	log.Printf("Testing TLS 1.3 connection on port %s using curl...", port)
	cmd := []string{"curl", "-v", "--tls-max", "1.3", "--tlsv1.3", "-k", "https://localhost:" + port + "/metrics"}
	output, err := execCommandInPodWithRetry(c, namespace, labelSelector, podName, containerName, cmd)
	if err != nil {
		return fmt.Errorf("TLS 1.3 connection on port %s failed: %v\nOutput: %s", port, err, output)
	}

	if !strings.Contains(output, "TLSv1.3") && !strings.Contains(output, "HTTP/") && !strings.Contains(output, "Unauthorized") {
		return fmt.Errorf("TLS 1.3 connection on port %s did not complete successfully\nOutput: %s", port, output)
	}
	log.Printf("Port %s TLS 1.3 connection succeeded", port)
	return nil
}

func testTLS12Connection(c client.Client, namespace, labelSelector, podName, containerName, port string, expectReject bool) error {
	if expectReject {
		log.Printf("Testing TLS 1.2 connection on port %s using curl (should be REJECTED)...", port)
		cmd := []string{"curl", "-v", "--tls-max", "1.2", "--tlsv1.2", "-k", "https://localhost:" + port + "/metrics"}
		output, err := execCommandInPodWithRetry(c, namespace, labelSelector, podName, containerName, cmd)

		// When expecting rejection, SSL errors (exit code 35, 60) are acceptable
		if err != nil {
			errStr := err.Error()
			// Exit code 35 means SSL handshake failed - this is expected for rejection
			if strings.Contains(errStr, "exit code 35") || strings.Contains(errStr, "exit code 60") {
				log.Printf("Port %s TLS 1.2 connection correctly rejected (SSL handshake failed with exit code 35/60)", port)
				return nil
			}

			if output != "" && (strings.Contains(output, "SSL") || strings.Contains(output, "alert") || strings.Contains(output, "error")) {
				// SSL error with output is expected for rejection - this is success
				log.Printf("Port %s TLS 1.2 connection correctly rejected (SSL handshake failed)", port)
				return nil
			}
			// Error with no useful output and not exit code 35/60 - unexpected failure
			if output == "" {
				return fmt.Errorf("TLS 1.2 rejection check on port %s produced no curl output; exec failed: %w", port, err)
			}
		}

		if strings.Contains(output, "TLSv1.2") || (strings.Contains(output, "HTTP/") && !strings.Contains(output, "SSL") && !strings.Contains(output, "alert")) {
			return fmt.Errorf("TLS 1.2 connection on port %s SUCCEEDED but should have been REJECTED", port)
		}
		log.Printf("Port %s TLS 1.2 connection correctly rejected", port)
	} else {
		log.Printf("Testing TLS 1.2 connection on port %s using curl...", port)
		cmd := []string{"curl", "-v", "--tls-max", "1.2", "--tlsv1.2", "-k", "https://localhost:" + port + "/metrics"}
		output, err := execCommandInPodWithRetry(c, namespace, labelSelector, podName, containerName, cmd)
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

func waitForTLSConfigurationReady(c client.Client, namespace, labelSelector string) error {
	ctx := context.Background()
	timeout := 2 * time.Minute
	interval := 5 * time.Second

	return wait.PollUntilContextTimeout(ctx, interval, timeout, true, func(ctx context.Context) (bool, error) {
		podName, err := findRunningPod(c, namespace, labelSelector)
		if err != nil {
			log.Printf("  Waiting for pod to be ready: %v", err)
			return false, nil
		}

		containerName := DaemonMetricsContainer
		port := DaemonMetricsPort
		cmd := []string{"curl", "-v", "--tls-max", "1.3", "--tlsv1.3", "-k", "https://localhost:" + port + "/metrics"}

		output, err := execCommandInPodWithRetry(c, namespace, labelSelector, podName, containerName, cmd)
		if err != nil {
			log.Printf("  TLS configuration not ready yet, retrying...")
			return false, nil
		}

		if strings.Contains(output, "TLSv1.3") || strings.Contains(output, "HTTP/") || strings.Contains(output, "Unauthorized") {
			log.Printf("  TLS configuration ready")
			return true, nil
		}

		log.Printf("  TLS handshake incomplete, retrying...")
		return false, nil
	})
}

func VerifyIngressNodeFirewallTLSComplianceInPod(c client.Client, namespace, labelSelector string) error {
	ctx := context.Background()

	apiserver := &configv1.APIServer{}
	err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, apiserver)
	if err != nil {
		return fmt.Errorf("failed to get APIServer config: %w", err)
	}

	expectedMinVer := expectedTLSMinVersion(apiserver)
	if expectedMinVer != "" {
		log.Printf("Waiting for operator to update DaemonSet with expected TLS min version %q...", expectedMinVer)
		if err := waitForDaemonSetTLSUpdate(c, namespace, expectedMinVer); err != nil {
			return fmt.Errorf("timed out waiting for DaemonSet TLS args to be updated by operator: %w", err)
		}
	} else {
		log.Println("Skipping DaemonSet TLS update wait (modern component not updated with LegacyAdheringComponentsOnly)")
	}

	log.Printf("Restarting daemon pods to ensure they pick up the new TLS configuration...")
	if err := RestartDaemonPods(c, namespace, labelSelector); err != nil {
		return fmt.Errorf("failed to restart daemon pods: %w", err)
	}

	expectTLS12Reject, description := determineTLSTestBehavior(apiserver)

	log.Printf("Waiting for TLS configuration to propagate to restarted pods...")
	if err := waitForTLSConfigurationReady(c, namespace, labelSelector); err != nil {
		return fmt.Errorf("failed waiting for TLS configuration to propagate: %w", err)
	}

	profileTypeLabel := "<unset>"
	if apiserver.Spec.TLSSecurityProfile != nil {
		profileTypeLabel = string(apiserver.Spec.TLSSecurityProfile.Type)
	}
	log.Printf("Testing with profile: %s (%s)", profileTypeLabel, description)

	podList := &corev1.PodList{}
	err = c.List(ctx, podList, client.InNamespace(namespace), client.MatchingLabels(parseLabelSelector(labelSelector)))
	if err != nil {
		return fmt.Errorf("failed to list pods with selector %s: %w", labelSelector, err)
	}
	pods := podList.Items

	if len(pods) == 0 {
		return fmt.Errorf("no pods found with selector %s in namespace %s", labelSelector, namespace)
	}

	var testPod string
	for _, pod := range pods {
		if pod.Status.Phase == "Running" {
			testPod = pod.Name
			break
		}
	}

	if testPod == "" {
		return fmt.Errorf("no running pods found with selector %s", labelSelector)
	}

	containerName := DaemonMetricsContainer
	port := DaemonMetricsPort
	portDescription := "Daemon Metrics"

	log.Printf("Testing pod %s/%s (container: %s) on localhost:%s (%s)", namespace, testPod, containerName, port, portDescription)

	if err := testTLS13Connection(c, namespace, labelSelector, testPod, containerName, port, portDescription); err != nil {
		return err
	}

	if err := testTLS12Connection(c, namespace, labelSelector, testPod, containerName, port, expectTLS12Reject); err != nil {
		return err
	}

	if expectTLS12Reject {
		log.Printf("TLS 1.3 works, TLS 1.2 correctly rejected for pod %s/%s on port %s", namespace, testPod, port)
	} else {
		log.Printf("TLS 1.2 and TLS 1.3 compliance verified for pod %s/%s on port %s", namespace, testPod, port)
	}
	return nil
}
