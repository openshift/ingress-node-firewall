package tls

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
	executil "github.com/openshift/ingress-node-firewall/test/e2e/exec"

	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	MCPRolloutStartTimeout    = 10 * time.Minute
	MCPRolloutCompleteTimeout = 60 * time.Minute
	NodeStabilityTimeout      = 60 * time.Minute
	OperatorSettleTimeMinutes = 60

	PodExecMaxRetries = 3
	PodExecBaseDelay  = 5 * time.Second

	MCPPollingInterval      = 10 * time.Second
	OperatorPollingInterval = 10 * time.Second
	NodePollingInterval     = 5 * time.Second
)

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

// parseLabelSelector converts a label selector string to a map
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

func ConfigureTLSProfileWithAdherence(c *testclient.ClientSet, tlsProfileType string, tlsAdherencePolicy string) error {
	overallStartTime := time.Now()
	log.Printf("=== Configuring %s TLS Profile with %s (started: %s) ===",
		tlsProfileType, tlsAdherencePolicy, overallStartTime.Format("15:04:05"))

	ctx := context.Background()

	// Step 1: Enable TLSAdherence feature gate if needed
	log.Println("Step 2: Checking and enabling TLSAdherence feature gate")
	featureGateEnabled, err := enableTLSAdherenceFeatureGate(ctx, c)
	if err != nil {
		return err
	}
	if !featureGateEnabled {
		log.Println("  Feature gate enabled and cluster stabilized")
	}

	// Step 3: Configure APIServer TLS profile
	log.Printf("Step 3: Configuring APIServer with %s TLS profile and tlsAdherence=%s", tlsProfileType, tlsAdherencePolicy)
	if err := configureAPIServerTLSProfile(ctx, c, tlsProfileType, tlsAdherencePolicy); err != nil {
		return err
	}

	// Step 4: Wait for cluster to stabilize
	log.Println("Step 4: Waiting for cluster to stabilize after TLS profile configuration")
	requiresMCPRollout := (tlsProfileType == "Modern" && (tlsAdherencePolicy == "LegacyAdheringComponentsOnly" || tlsAdherencePolicy == "StrictAllComponents"))
	if err := waitForClusterStability(ctx, c, requiresMCPRollout); err != nil {
		return err
	}

	// Step 5: Verify TLSAdherence feature is active
	log.Println("Step 5: Verifying TLSAdherence is active in feature gate status")
	if err := verifyTLSAdherenceActive(ctx, c); err != nil {
		return err
	}

	// Step 6: Verify APIServer TLS profile configuration
	log.Println("Step 6: Verifying APIServer TLS profile configuration")
	if err := verifyAPIServerTLSProfile(ctx, c, tlsProfileType, tlsAdherencePolicy); err != nil {
		return err
	}

	log.Printf("=== %s TLS Profile successfully configured (total time: %v) ===",
		tlsProfileType, time.Since(overallStartTime))
	return nil
}

// enableTLSAdherenceFeatureGate enables the TLSAdherence feature gate and waits for cluster stabilization
// Returns true if already enabled, false if it was just enabled
func enableTLSAdherenceFeatureGate(ctx context.Context, c client.Client) (bool, error) {
	fg := &configv1.FeatureGate{}
	err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, fg)
	if err != nil {
		return false, fmt.Errorf("failed to get featuregate: %w", err)
	}

	if isAlreadyEnabled(fg) {
		log.Println("  TLSAdherence feature gate is already enabled")
		return true, nil
	}

	log.Println("  Enabling TLSAdherence feature gate")
	if err := patchFeatureGate(ctx, c, fg); err != nil {
		return false, fmt.Errorf("failed to patch FeatureGate: %w", err)
	}

	log.Println("  Waiting for MCP rollout to start")
	if err := waitForMCPRolloutStart(c, MCPRolloutStartTimeout); err != nil {
		log.Printf("  WARNING: MCP rollout did not start within timeout: %v", err)
	} else {
		log.Println("  Waiting for MCP rollout to complete")
		if err := waitForAllMCPsComplete(c, MCPRolloutCompleteTimeout); err != nil {
			return false, fmt.Errorf("failed waiting for MCP rollout: %w", err)
		}
	}

	log.Println("  Waiting for nodes to be ready")
	if err := waitForNodesStability(c, NodeStabilityTimeout); err != nil {
		return false, fmt.Errorf("failed waiting for nodes: %w", err)
	}

	log.Println("  Waiting for cluster operators to settle")
	if err := waitForOperatorsToSettle(ctx, c, OperatorSettleTimeMinutes); err != nil {
		return false, fmt.Errorf("failed waiting for operators: %w", err)
	}

	return false, nil
}

// configureAPIServerTLSProfile patches the APIServer with the desired TLS profile and adherence policy
func configureAPIServerTLSProfile(ctx context.Context, c client.Client, tlsProfileType string, tlsAdherencePolicy string) error {
	if err := patchAPIServerTLSProfile(ctx, c, tlsProfileType, tlsAdherencePolicy); err != nil {
		return err
	}
	return nil
}

// waitForClusterStability waits for the cluster to stabilize after TLS profile configuration
func waitForClusterStability(ctx context.Context, c client.Client, requiresMCPRollout bool) error {
	if requiresMCPRollout {
		mcpsComplete, err := areAllMCPsComplete(c)
		if err != nil {
			return fmt.Errorf("failed to check MCP status: %w", err)
		}

		if !mcpsComplete {
			log.Println("  Waiting for MCP rollout to start")
			if err := waitForMCPRolloutStart(c, MCPRolloutStartTimeout); err != nil {
				return err
			}

			log.Println("  Waiting for MCP rollout to complete")
			if err := waitForAllMCPsComplete(c, MCPRolloutCompleteTimeout); err != nil {
				return err
			}
		}

		log.Println("  Waiting for nodes to be ready")
		if err := waitForNodesStability(c, NodeStabilityTimeout); err != nil {
			return err
		}

		log.Println("  Waiting for cluster operators to settle")
		if err := waitForOperatorsToSettle(ctx, c, OperatorSettleTimeMinutes); err != nil {
			return err
		}
	} else {
		log.Println("  Waiting for cluster operators to settle")
		if err := waitForOperatorsToSettle(ctx, c, OperatorSettleTimeMinutes); err != nil {
			return err
		}

		log.Println("  Waiting for nodes to be ready")
		if err := waitForNodesStability(c, NodeStabilityTimeout); err != nil {
			return err
		}
	}

	return nil
}

// verifyAPIServerTLSProfile verifies the APIServer TLS profile configuration
func verifyAPIServerTLSProfile(ctx context.Context, c client.Client, tlsProfileType string, tlsAdherencePolicy string) error {
	apiserver := &configv1.APIServer{}
	err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, apiserver)
	if err != nil {
		return fmt.Errorf("failed to get APIServer: %w", err)
	}

	// Verify TLS profile type
	var expectedProfileType configv1.TLSProfileType
	switch tlsProfileType {
	case "Modern":
		expectedProfileType = configv1.TLSProfileModernType
	case "Intermediate":
		expectedProfileType = configv1.TLSProfileIntermediateType
	case "Old":
		expectedProfileType = configv1.TLSProfileOldType
	default:
		return fmt.Errorf("unsupported TLS profile type: %s", tlsProfileType)
	}

	if apiserver.Spec.TLSSecurityProfile == nil {
		return fmt.Errorf("APIServer TLS security profile is nil, expected %s", tlsProfileType)
	}

	actualProfileType := apiserver.Spec.TLSSecurityProfile.Type
	if actualProfileType != expectedProfileType {
		return fmt.Errorf("APIServer TLS profile type mismatch: actual=%s, expected=%s", actualProfileType, expectedProfileType)
	}
	log.Printf("  TLS profile type verified: %s", tlsProfileType)

	// Verify TLS adherence policy
	actualAdherence := string(apiserver.Spec.TLSAdherence)
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

func isAlreadyEnabled(fg *configv1.FeatureGate) bool {
	if fg.Spec.FeatureSet == configv1.CustomNoUpgrade && fg.Spec.CustomNoUpgrade != nil {
		for _, enabled := range fg.Spec.CustomNoUpgrade.Enabled {
			if enabled == "TLSAdherence" {
				return true
			}
		}
	}
	return false
}

func patchFeatureGate(ctx context.Context, c client.Client, fg *configv1.FeatureGate) error {
	if fg.Spec.FeatureSet == configv1.CustomNoUpgrade && fg.Spec.CustomNoUpgrade != nil {
		fg.Spec.CustomNoUpgrade.Enabled = append(fg.Spec.CustomNoUpgrade.Enabled, "TLSAdherence")
	} else {
		fg.Spec.FeatureSet = configv1.CustomNoUpgrade
		fg.Spec.CustomNoUpgrade = &configv1.CustomFeatureGates{
			Enabled: []configv1.FeatureGateName{"TLSAdherence"},
		}
	}

	err := c.Update(ctx, fg)
	if err != nil {
		return fmt.Errorf("failed to update featuregate: %w", err)
	}
	return nil
}

func patchAPIServerTLSProfile(ctx context.Context, c client.Client, tlsProfileType string, tlsAdherencePolicy string) error {
	apiserver := &configv1.APIServer{}
	err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, apiserver)
	if err != nil {
		return fmt.Errorf("failed to get apiserver: %w", err)
	}

	switch tlsProfileType {
	case "Modern":
		apiserver.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
			Type:   configv1.TLSProfileModernType,
			Modern: &configv1.ModernTLSProfile{},
		}
	case "Intermediate":
		apiserver.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
			Type:         configv1.TLSProfileIntermediateType,
			Intermediate: &configv1.IntermediateTLSProfile{},
		}
	case "Old":
		apiserver.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileOldType,
			Old:  &configv1.OldTLSProfile{},
		}
	default:
		return fmt.Errorf("unsupported TLS profile type: %s (must be Modern, Intermediate, or Old)", tlsProfileType)
	}

	apiserver.Spec.TLSAdherence = configv1.TLSAdherencePolicy(tlsAdherencePolicy)

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
		return false, err
	}
	mcps := mcpList.Items
	if err != nil {
		return false, fmt.Errorf("failed to list MCPs: %w", err)
	}

	for _, mcp := range mcps {
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
	return wait.PollImmediate(MCPPollingInterval, timeout, func() (bool, error) {
		mcpList := &mcfgv1.MachineConfigPoolList{}
		err := c.List(ctx, mcpList)
		if err != nil {
			return false, err
		}
		mcps := mcpList.Items
		if err != nil {
			return false, nil
		}

		for _, mcp := range mcps {
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
	return wait.PollImmediate(30*time.Second, timeout, func() (bool, error) {
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
	return wait.PollImmediate(10*time.Second, time.Duration(waitTimeMinutes)*time.Minute, func() (bool, error) {
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
	return wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
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
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func verifyTLSAdherenceActive(ctx context.Context, c client.Client) error {
	cv := &configv1.ClusterVersion{}
	err := c.Get(ctx, types.NamespacedName{Name: "version"}, cv)
	if err != nil {
		return fmt.Errorf("failed to get cluster version: %w", err)
	}
	version := cv.Status.Desired.Version
	log.Printf("  Verifying TLSAdherence is active for cluster version %s", version)

	return wait.PollImmediate(15*time.Second, 15*time.Minute, func() (bool, error) {
		fg := &configv1.FeatureGate{}
		err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, fg)
		if err != nil {
			log.Printf("Error getting FeatureGate: %v", err)
			return false, nil
		}

		for _, fgStatus := range fg.Status.FeatureGates {
			if fgStatus.Version == version {
				for _, enabled := range fgStatus.Enabled {
					if enabled.Name == "TLSAdherence" {
						return true, nil
					}
				}
			}
		}

		log.Printf("TLSAdherence not yet in status for version %s (waiting...)", version)
		return false, nil
	})
}

func determineTLSTestBehavior(apiserver *configv1.APIServer) (expectTLS12Reject bool, description string) {
	tlsAdherence := string(apiserver.Spec.TLSAdherence)
	profileType := apiserver.Spec.TLSSecurityProfile.Type

	if profileType == configv1.TLSProfileModernType && tlsAdherence == "StrictAllComponents" {
		return true, "Modern with StrictAllComponents: TLS 1.3 only, TLS 1.2 should be rejected"
	}

	return false, "Both TLS 1.2 and TLS 1.3 should work"
}

func findRunningPod(c client.Client, namespace, labelSelector string) (string, error) {
	ctx := context.Background()
	podList := &corev1.PodList{}
	err := c.List(ctx, podList, client.InNamespace(namespace), client.MatchingLabels(parseLabelSelector(labelSelector)))
	if err != nil {
		return "", err
	}
	pods := podList.Items
	if err != nil {
		return "", fmt.Errorf("failed to list pods with selector %s: %w", labelSelector, err)
	}

	if len(pods) == 0 {
		return "", fmt.Errorf("no pods found with selector %s in namespace %s", labelSelector, namespace)
	}

	for _, pod := range pods {
		if pod.Status.Phase == "Running" {
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
		strings.Contains(errStr, "exit code 35") ||
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

			var err error
			pollErr := wait.PollImmediate(1*time.Second, delay, func() (bool, error) {
				currentPodName, err = findRunningPod(c, namespace, labelSelector)
				if err != nil {
					return false, nil
				}

				ctx := context.Background()
				pod := &corev1.Pod{}
				getPodErr := c.Get(ctx, types.NamespacedName{Name: currentPodName, Namespace: namespace}, pod)
				if getPodErr != nil {
					return false, nil
				}

				if pod.Status.Phase != corev1.PodRunning {
					return false, nil
				}

				for _, condition := range pod.Status.Conditions {
					if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
						return true, nil
					}
				}
				return false, nil
			})

			if pollErr != nil {
				lastErr = fmt.Errorf("failed to find ready pod within %v: %w", delay, err)
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

func WaitForDaemonPodsReady(c client.Client, namespace, labelSelector string, timeout time.Duration) error {
	log.Printf("Waiting for daemon pods with selector %s to be ready in namespace %s", labelSelector, namespace)

	return wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		ctx := context.Background()
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

			ready := false
			for _, condition := range pod.Status.Conditions {
				if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
					ready = true
					break
				}
			}
			if !ready {
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

func VerifyIngressNodeFirewallTLSComplianceInPod(c client.Client, namespace, labelSelector string) error {
	ctx := context.Background()

	log.Printf("Waiting for daemon pods to be ready before TLS compliance testing...")
	if err := WaitForDaemonPodsReady(c, namespace, labelSelector, 2*time.Minute); err != nil {
		return fmt.Errorf("daemon pods did not become ready: %w", err)
	}

	apiserver := &configv1.APIServer{}
	err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, apiserver)
	if err != nil {
		return fmt.Errorf("failed to get APIServer config: %w", err)
	}

	expectTLS12Reject, description := determineTLSTestBehavior(apiserver)
	log.Printf("Testing with profile: %s (%s)", apiserver.Spec.TLSSecurityProfile.Type, description)

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

	containerName := "kube-rbac-proxy"
	port := "9301"
	portDescription := "Daemon Metrics (kube-rbac-proxy)"

	log.Printf("Testing pod %s/%s (container: %s) on localhost:%s (%s)", namespace, testPod, containerName, port, portDescription)

	log.Printf("Testing TLS 1.3 connection on port %s using curl...", port)
	cmd13 := []string{"curl", "-v", "--tls-max", "1.3", "--tlsv1.3", "-k", "https://localhost:" + port + "/metrics"}
	output13, err := execCommandInPodWithRetry(c, namespace, labelSelector, testPod, containerName, cmd13)
	if err != nil {
		return fmt.Errorf("TLS 1.3 connection on port %s failed: %v\nOutput: %s", port, err, output13)
	}

	if !strings.Contains(output13, "TLSv1.3") && !strings.Contains(output13, "HTTP/") && !strings.Contains(output13, "Unauthorized") {
		return fmt.Errorf("TLS 1.3 connection on port %s did not complete successfully\nOutput: %s", port, output13)
	}
	log.Printf("Port %s TLS 1.3 connection succeeded", port)

	if expectTLS12Reject {
		log.Printf("Testing TLS 1.2 connection on port %s using curl (should be REJECTED)...", port)
		cmd12 := []string{"curl", "-v", "--tls-max", "1.2", "--tlsv1.2", "-k", "https://localhost:" + port + "/metrics"}
		output12, _ := execCommandInPodWithRetry(c, namespace, labelSelector, testPod, containerName, cmd12)

		if strings.Contains(output12, "TLSv1.2") || (strings.Contains(output12, "HTTP/") && !strings.Contains(output12, "SSL") && !strings.Contains(output12, "alert")) {
			return fmt.Errorf("TLS 1.2 connection on port %s SUCCEEDED but should have been REJECTED", port)
		}
		log.Printf("Port %s TLS 1.2 connection correctly rejected", port)
		log.Printf("TLS 1.3 works, TLS 1.2 correctly rejected for pod %s/%s on port %s", namespace, testPod, port)
	} else {
		log.Printf("Testing TLS 1.2 connection on port %s using curl...", port)
		cmd12 := []string{"curl", "-v", "--tls-max", "1.2", "--tlsv1.2", "-k", "https://localhost:" + port + "/metrics"}
		output12, err := execCommandInPodWithRetry(c, namespace, labelSelector, testPod, containerName, cmd12)
		if err != nil {
			return fmt.Errorf("TLS 1.2 connection on port %s failed: %v\nOutput: %s", port, err, output12)
		}

		if !strings.Contains(output12, "TLSv1.2") && !strings.Contains(output12, "HTTP/") && !strings.Contains(output12, "Unauthorized") {
			return fmt.Errorf("TLS 1.2 connection on port %s did not complete successfully\nOutput: %s", port, output12)
		}
		log.Printf("Port %s TLS 1.2 connection succeeded", port)
		log.Printf("TLS 1.2 and TLS 1.3 compliance verified for pod %s/%s on port %s", namespace, testPod, port)
	}
	return nil
}
