package tls

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"

	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned"
	machineconfigclient "github.com/openshift/client-go/machineconfiguration/clientset/versioned"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// IsOpenShiftCluster detects if running on an OpenShift cluster
// Returns true if OpenShift-specific APIs are available, false otherwise
func IsOpenShiftCluster(client *testclient.ClientSet) bool {
	configClient, err := configv1client.NewForConfig(client.Config)
	if err != nil {
		return false
	}

	_, err = configClient.ConfigV1().FeatureGates().Get(
		context.Background(),
		"cluster",
		metav1.GetOptions{},
	)
	return err == nil
}

// EnableTLSAdherence enables the TLSAdherence feature gate AND configures TLS profile with adherence policy
// This function does EVERYTHING:
// 1. Patches FeatureGate to enable TLSAdherence feature
// 2. Patches APIServer to set TLS profile (Modern) with tlsAdherence policy (StrictAllComponents)
// 3. Waits for MCP rollout to start
// 4. Waits for MCP rollout to complete (all MCPs)
// 5. Waits for all cluster operators to settle (Available=True, Degraded=False, Progressing=False)
// 6. Waits for cluster nodes to be ready and stable
// 7. Verifies TLSAdherence is active in feature gate status
func EnableTLSAdherence(client *testclient.ClientSet) error {
	return EnableTLSAdherenceWithProfile(client, "Modern", "StrictAllComponents")
}

// EnableTLSAdherenceWithProfile enables TLSAdherence feature gate and configures TLS profile
// tlsProfileType: "Modern", "Intermediate", "Old", or "Custom"
// tlsAdherencePolicy: "StrictAllComponents" or other supported policies
func EnableTLSAdherenceWithProfile(client *testclient.ClientSet, tlsProfileType string, tlsAdherencePolicy string) error {
	// Create the required clients
	configClient, err := configv1client.NewForConfig(client.Config)
	if err != nil {
		return fmt.Errorf("failed to create config client: %w", err)
	}

	machineConfigClient, err := machineconfigclient.NewForConfig(client.Config)
	if err != nil {
		return fmt.Errorf("failed to create machine config client: %w", err)
	}

	k8sClient, err := kubernetes.NewForConfig(client.Config)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	ctx := context.Background()

	log.Println("=== Starting TLSAdherence feature gate enablement ===")

	// Step 1: Enable feature gate
	log.Printf("Step 1: Patching FeatureGate to enable TLSAdherence")
	fg, err := configClient.ConfigV1().FeatureGates().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get featuregate: %w", err)
	}

	// Check if already enabled
	tlsFeatureAlreadyEnabled := isAlreadyEnabled(fg)
	if tlsFeatureAlreadyEnabled {
		log.Printf("✓ TLSAdherence feature gate already enabled")
	} else {
		// Enable TLSAdherence feature gate
		if err := patchFeatureGate(ctx, configClient, fg); err != nil {
			return err
		}
		log.Printf("✓ Feature gate patched successfully")
	}

	// Step 2: Configure APIServer with TLS profile and adherence policy
	// ALWAYS configure this, even if feature gate was already enabled
	log.Printf("Step 2: Configuring APIServer with TLS profile=%s and tlsAdherence=%s", tlsProfileType, tlsAdherencePolicy)
	if err := patchAPIServerTLSProfile(ctx, configClient, tlsProfileType, tlsAdherencePolicy); err != nil {
		return err
	}
	log.Printf("✓ APIServer TLS profile configured successfully")

	// Step 3: Wait for MCP rollout to start (or verify already complete)
	log.Printf("Step 3: Checking MCP status")

	// First check if MCPs are already complete
	mcpsAlreadyComplete, err := areAllMCPsComplete(machineConfigClient)
	if err != nil {
		return fmt.Errorf("failed to check MCP status: %w", err)
	}

	if mcpsAlreadyComplete {
		log.Printf("✓ All MCPs are already updated (no rollout needed)")
	} else {
		log.Printf("Waiting for MCP rollout to start")
		if err := waitForMCPRolloutStart(machineConfigClient, 5*time.Minute); err != nil {
			return err
		}
		log.Printf("✓ MCP rollout started")

		// Step 4: Wait for all MCPs to complete
		log.Printf("Step 4: Waiting for MCP rollout to complete")
		if err := waitForAllMCPsComplete(machineConfigClient, 30*time.Minute); err != nil {
			return err
		}
		log.Printf("✓ All MCPs updated successfully")
	}

	// Step 5: Wait for operators to settle
	log.Printf("Step 5: Waiting for all cluster operators to settle")
	if err := waitForOperatorsToSettle(ctx, configClient, 30); err != nil {
		return err
	}
	log.Printf("✓ All cluster operators settled")

	// Step 5: Wait for nodes to be ready and stable
	log.Printf("Step 6: Waiting for all nodes to be ready and stable")
	if err := waitForNodesStability(k8sClient, 10*time.Minute); err != nil {
		return err
	}
	log.Printf("✓ All nodes are ready and stable")

	// Step 7: Verify TLSAdherence is active in status
	log.Printf("Step 7: Verifying TLSAdherence is active in feature gate status")
	if err := verifyTLSAdherenceActive(ctx, configClient); err != nil {
		return err
	}
	log.Printf("✓ TLSAdherence is active in feature gate status")

	// Step 8: Verify APIServer TLS configuration
	log.Printf("Step 8: Verifying APIServer TLS profile and adherence policy")
	if err := verifyAPIServerTLSConfiguration(ctx, configClient, tlsProfileType, tlsAdherencePolicy); err != nil {
		return err
	}
	log.Printf("✓ APIServer TLS profile=%s and tlsAdherence=%s verified", tlsProfileType, tlsAdherencePolicy)

	log.Printf("=== TLSAdherence feature gate successfully enabled and cluster is stable ===")
	return nil
}

// isAlreadyEnabled checks if TLSAdherence is already in the enabled list
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

// patchFeatureGate patches the FeatureGate to enable TLSAdherence
func patchFeatureGate(ctx context.Context, configClient configv1client.Interface, fg *configv1.FeatureGate) error {
	if fg.Spec.FeatureSet == configv1.CustomNoUpgrade && fg.Spec.CustomNoUpgrade != nil {
		// Add to existing CustomNoUpgrade
		fg.Spec.CustomNoUpgrade.Enabled = append(fg.Spec.CustomNoUpgrade.Enabled, "TLSAdherence")
	} else {
		// Set CustomNoUpgrade with TLSAdherence
		fg.Spec.FeatureSet = configv1.CustomNoUpgrade
		fg.Spec.CustomNoUpgrade = &configv1.CustomFeatureGates{
			Enabled: []configv1.FeatureGateName{"TLSAdherence"},
		}
	}

	_, err := configClient.ConfigV1().FeatureGates().Update(ctx, fg, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update featuregate: %w", err)
	}
	return nil
}

// patchAPIServerTLSProfile patches the APIServer to set TLS profile and adherence policy
// Example:
//
//	oc patch apiserver cluster --type=merge \
//	  -p '{"spec":{"tlsSecurityProfile":{"type":"Modern","modern":{}},"tlsAdherence":"StrictAllComponents"}}'
func patchAPIServerTLSProfile(ctx context.Context, configClient configv1client.Interface, tlsProfileType string, tlsAdherencePolicy string) error {
	apiserver, err := configClient.ConfigV1().APIServers().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get apiserver: %w", err)
	}

	// Set TLS Security Profile based on type
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
	case "Custom":
		// For Custom profile, user needs to provide custom configuration
		// We'll just set the type here
		apiserver.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileCustomType,
		}
	default:
		return fmt.Errorf("unsupported TLS profile type: %s (must be Modern, Intermediate, Old, or Custom)", tlsProfileType)
	}

	// Set TLS Adherence policy
	apiserver.Spec.TLSAdherence = configv1.TLSAdherencePolicy(tlsAdherencePolicy)

	_, err = configClient.ConfigV1().APIServers().Update(ctx, apiserver, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update apiserver: %w", err)
	}

	return nil
}

// ConfigureCustomTLSProfile configures a custom TLS profile with specific minTLSVersion and ciphers
func ConfigureCustomTLSProfile(client *testclient.ClientSet, minTLSVersion string, ciphers []string, tlsAdherencePolicy string) error {
	configClient, err := configv1client.NewForConfig(client.Config)
	if err != nil {
		return fmt.Errorf("failed to create config client: %w", err)
	}

	machineConfigClient, err := machineconfigclient.NewForConfig(client.Config)
	if err != nil {
		return fmt.Errorf("failed to create machine config client: %w", err)
	}

	k8sClient, err := kubernetes.NewForConfig(client.Config)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	ctx := context.Background()

	log.Println("=== Configuring Custom TLS Profile ===")

	// Step 1: Configure APIServer with custom TLS profile
	log.Printf("Step 1: Configuring APIServer with Custom TLS profile (minTLSVersion=%s, ciphers=%v, tlsAdherence=%s)", minTLSVersion, ciphers, tlsAdherencePolicy)

	apiserver, err := configClient.ConfigV1().APIServers().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get apiserver: %w", err)
	}

	// Set Custom TLS Security Profile
	apiserver.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
		Type: configv1.TLSProfileCustomType,
		Custom: &configv1.CustomTLSProfile{
			TLSProfileSpec: configv1.TLSProfileSpec{
				Ciphers:       ciphers,
				MinTLSVersion: configv1.TLSProtocolVersion(minTLSVersion),
			},
		},
	}

	// Set TLS Adherence policy
	apiserver.Spec.TLSAdherence = configv1.TLSAdherencePolicy(tlsAdherencePolicy)

	_, err = configClient.ConfigV1().APIServers().Update(ctx, apiserver, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update apiserver: %w", err)
	}
	log.Println("✓ APIServer Custom TLS profile configured successfully")

	// Step 2: Check if MCPs are already complete (no rollout needed)
	log.Println("Step 2: Checking MCP status")
	mcpsComplete, err := areAllMCPsComplete(machineConfigClient)
	if err != nil {
		return fmt.Errorf("failed to check MCP status: %w", err)
	}

	if mcpsComplete {
		log.Println("✓ All MCPs are already updated (no rollout needed)")
	} else {
		// Step 3: Wait for MCP rollout to start (with 5-minute timeout)
		log.Println("Step 3: Waiting for MCP rollout to start")
		err = waitForMCPRolloutStart(machineConfigClient, 5*time.Minute)
		if err != nil {
			return fmt.Errorf("failed waiting for MCP rollout to start: %w", err)
		}
		log.Println("✓ MCP rollout started")

		// Step 4: Wait for MCP rollout to complete (with 30-minute timeout)
		log.Println("Step 4: Waiting for MCP rollout to complete")
		err = waitForAllMCPsComplete(machineConfigClient, 30*time.Minute)
		if err != nil {
			return fmt.Errorf("failed waiting for MCP rollout to complete: %w", err)
		}
		log.Println("✓ MCP rollout completed")
	}

	// Step 5: Wait for all cluster operators to settle
	log.Println("Step 5: Waiting for all cluster operators to settle")
	log.Println("Waiting up to 30 minutes for all cluster operators to settle")
	err = waitForOperatorsToSettle(ctx, configClient, 30)
	if err != nil {
		return fmt.Errorf("failed waiting for cluster operators: %w", err)
	}
	log.Println("✓ All cluster operators settled")

	// Step 6: Wait for all nodes to be ready
	log.Println("Step 6: Waiting for all nodes to be ready and stable")
	err = waitForNodesStability(k8sClient, 10*time.Minute)
	if err != nil {
		return fmt.Errorf("failed waiting for nodes: %w", err)
	}
	log.Println("✓ All nodes are ready and stable")

	// Step 7: Verify APIServer TLS configuration
	log.Println("Step 7: Verifying APIServer Custom TLS profile configuration")
	err = verifyAPIServerTLSConfiguration(ctx, configClient, "Custom", tlsAdherencePolicy)
	if err != nil {
		return fmt.Errorf("failed to verify APIServer TLS configuration: %w", err)
	}
	log.Printf("✓ APIServer Custom TLS profile (minTLSVersion=%s) and tlsAdherence=%s verified", minTLSVersion, tlsAdherencePolicy)

	log.Println("=== Custom TLS Profile successfully configured and cluster is stable ===")

	return nil
}

// areAllMCPsComplete checks if all MCPs are already complete (Updated=True, Updating=False)
func areAllMCPsComplete(client machineconfigclient.Interface) (bool, error) {
	ctx := context.Background()
	mcps, err := client.MachineconfigurationV1().MachineConfigPools().List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to list MCPs: %w", err)
	}

	for _, mcp := range mcps.Items {
		if mcp.Status.MachineCount == 0 {
			continue
		}

		// Check if MCP is Updated and not Updating
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

		// If any MCP is not complete, return false
		if !updated || updating {
			return false, nil
		}
	}

	return true, nil
}

// waitForMCPRolloutStart waits for at least one MCP to enter Updating state
func waitForMCPRolloutStart(client machineconfigclient.Interface, timeout time.Duration) error {
	ctx := context.Background()
	return wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		mcps, err := client.MachineconfigurationV1().MachineConfigPools().List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Printf("Error getting MCPs: %v", err)
			return false, nil
		}

		for _, mcp := range mcps.Items {
			for _, cond := range mcp.Status.Conditions {
				if cond.Type == mcfgv1.MachineConfigPoolUpdating && cond.Status == corev1.ConditionTrue {
					log.Printf("MCP %s has started updating", mcp.Name)
					return true, nil
				}
			}
		}
		return false, nil
	})
}

// waitForAllMCPsComplete waits for all MCPs to complete their rollout
func waitForAllMCPsComplete(client machineconfigclient.Interface, timeout time.Duration) error {
	ctx := context.Background()

	// Get all MCPs
	mcps, err := client.MachineconfigurationV1().MachineConfigPools().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list MCPs: %w", err)
	}

	// Wait for each MCP with machines to complete
	for _, mcp := range mcps.Items {
		if mcp.Status.MachineCount == 0 {
			log.Printf("Skipping MCP %s (no machines)", mcp.Name)
			continue
		}

		log.Printf("Waiting for MCP %s (%d machines) to complete", mcp.Name, mcp.Status.MachineCount)
		if err := waitForMCPComplete(client, mcp.Name, timeout); err != nil {
			return fmt.Errorf("MCP %s did not complete: %w", mcp.Name, err)
		}
		log.Printf("✓ MCP %s: %d/%d machines updated", mcp.Name, mcp.Status.UpdatedMachineCount, mcp.Status.MachineCount)
	}

	return nil
}

// waitForMCPComplete waits for a specific MCP to complete its rollout
func waitForMCPComplete(client machineconfigclient.Interface, mcpName string, timeout time.Duration) error {
	ctx := context.Background()
	return wait.PollImmediate(30*time.Second, timeout, func() (bool, error) {
		mcp, err := client.MachineconfigurationV1().MachineConfigPools().Get(ctx, mcpName, metav1.GetOptions{})
		if err != nil {
			log.Printf("Error getting MCP %s: %v", mcpName, err)
			return false, nil
		}

		// Check if MCP is Updated
		updated := false
		for _, cond := range mcp.Status.Conditions {
			if cond.Type == mcfgv1.MachineConfigPoolUpdated && cond.Status == corev1.ConditionTrue {
				updated = true
				break
			}
		}

		// MCP is complete when Updated=True and all machines are updated
		if updated && mcp.Status.UpdatedMachineCount == mcp.Status.MachineCount {
			return true, nil
		}

		log.Printf("MCP %s: %d/%d machines updated, Updated=%v (waiting...)",
			mcpName, mcp.Status.UpdatedMachineCount, mcp.Status.MachineCount, updated)
		return false, nil
	})
}

// waitForOperatorsToSettle waits for all cluster operators to be healthy
// - Available = True
// - Degraded = False
// - Progressing = False
func waitForOperatorsToSettle(ctx context.Context, configClient configv1client.Interface, waitTimeMinutes int) error {
	log.Printf("Waiting up to %d minutes for all cluster operators to settle", waitTimeMinutes)

	return wait.PollImmediate(10*time.Second, time.Duration(waitTimeMinutes)*time.Minute, func() (bool, error) {
		coList, err := configClient.ConfigV1().ClusterOperators().List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Printf("Error getting ClusterOperators: %v", err)
			return false, nil
		}

		unsettled := []string{}
		for _, co := range coList.Items {
			// Skip image-registry operator (known issue with ImagePruner in test/dev clusters)
			if co.Name == "image-registry" {
				continue
			}

			available, degraded, progressing := getOperatorConditions(&co)

			// Operator is settled if: Available=True AND Degraded=False AND Progressing=False
			if available && !degraded && !progressing {
				continue
			}

			// Record unsettled operators
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
			log.Printf("Waiting for operators to settle: %s", strings.Join(unsettled, ", "))
			return false, nil
		}

		return true, nil
	})
}

// getOperatorConditions extracts the Available, Degraded, and Progressing conditions
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

// waitForNodesStability waits for all nodes to be Ready and stable
func waitForNodesStability(client kubernetes.Interface, timeout time.Duration) error {
	ctx := context.Background()

	return wait.PollImmediate(30*time.Second, timeout, func() (bool, error) {
		nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Printf("Error getting nodes: %v", err)
			return false, nil
		}

		notReady := []string{}
		for _, node := range nodes.Items {
			if !isNodeReady(&node) {
				notReady = append(notReady, node.Name)
			}
		}

		if len(notReady) > 0 {
			log.Printf("Waiting for nodes to be ready: %s", strings.Join(notReady, ", "))
			return false, nil
		}

		log.Printf("All %d nodes are ready", len(nodes.Items))
		return true, nil
	})
}

// isNodeReady checks if a node is Ready
func isNodeReady(node *corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// verifyTLSAdherenceActive verifies that TLSAdherence appears in the feature gate status
func verifyTLSAdherenceActive(ctx context.Context, configClient configv1client.Interface) error {
	// Get cluster version
	cv, err := configClient.ConfigV1().ClusterVersions().Get(ctx, "version", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get cluster version: %w", err)
	}
	version := cv.Status.Desired.Version

	log.Printf("Verifying TLSAdherence is active for cluster version %s", version)

	// Poll for TLSAdherence in status
	return wait.PollImmediate(15*time.Second, 15*time.Minute, func() (bool, error) {
		fg, err := configClient.ConfigV1().FeatureGates().Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			log.Printf("Error getting FeatureGate: %v", err)
			return false, nil
		}

		// Check if TLSAdherence is in status for current version
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

// verifyAPIServerTLSConfiguration verifies that APIServer has the expected TLS profile and adherence policy
func verifyAPIServerTLSConfiguration(ctx context.Context, configClient configv1client.Interface, expectedProfile string, expectedAdherence string) error {
	apiserver, err := configClient.ConfigV1().APIServers().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get apiserver: %w", err)
	}

	// Verify TLS Security Profile Type
	if apiserver.Spec.TLSSecurityProfile == nil {
		return fmt.Errorf("APIServer TLSSecurityProfile is not configured")
	}

	actualProfile := string(apiserver.Spec.TLSSecurityProfile.Type)
	if actualProfile != expectedProfile {
		return fmt.Errorf("APIServer TLS profile mismatch: expected=%s, actual=%s", expectedProfile, actualProfile)
	}

	// Verify TLS Adherence Policy
	actualAdherence := string(apiserver.Spec.TLSAdherence)
	if actualAdherence != expectedAdherence {
		return fmt.Errorf("APIServer tlsAdherence mismatch: expected=%s, actual=%s", expectedAdherence, actualAdherence)
	}

	log.Printf("APIServer configuration verified: tlsSecurityProfile.type=%s, tlsAdherence=%s", actualProfile, actualAdherence)
	return nil
}

// verifyClusterStability verifies all aspects of cluster stability when TLSAdherence is already enabled
func verifyClusterStability(ctx context.Context, configClient configv1client.Interface, machineConfigClient machineconfigclient.Interface, client kubernetes.Interface) error {
	log.Printf("Verifying cluster stability")

	// Check operators
	if err := waitForOperatorsToSettle(ctx, configClient, 5); err != nil {
		return fmt.Errorf("cluster operators not settled: %w", err)
	}

	// Check MCPs
	if err := waitForAllMCPsComplete(machineConfigClient, 5*time.Minute); err != nil {
		return fmt.Errorf("MCPs not complete: %w", err)
	}

	// Check nodes
	if err := waitForNodesStability(client, 5*time.Minute); err != nil {
		return fmt.Errorf("nodes not stable: %w", err)
	}

	// Verify TLSAdherence in status
	if err := verifyTLSAdherenceActive(ctx, configClient); err != nil {
		return fmt.Errorf("TLSAdherence not active: %w", err)
	}

	return nil
}

// IsTLSAdherenceEnabled checks if TLSAdherence feature gate is enabled in the cluster
func IsTLSAdherenceEnabled(configClient configv1client.Interface) (bool, error) {
	ctx := context.Background()
	fg, err := configClient.ConfigV1().FeatureGates().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to get featuregate: %w", err)
	}

	// Check in spec
	if fg.Spec.FeatureSet == configv1.CustomNoUpgrade && fg.Spec.CustomNoUpgrade != nil {
		for _, enabled := range fg.Spec.CustomNoUpgrade.Enabled {
			if enabled == "TLSAdherence" {
				return true, nil
			}
		}
	}

	// Also check in status for all versions
	for _, fgStatus := range fg.Status.FeatureGates {
		for _, enabled := range fgStatus.Enabled {
			if enabled.Name == "TLSAdherence" {
				return true, nil
			}
		}
	}

	return false, nil
}
