// Package tls - Common utilities and constants for TLS profile compliance testing
package tls

import (
	"fmt"
	"strings"
	"time"
)

// Test infrastructure constants
const (
	SharedScannerNamespace = "tls-scanner-shared"
	ScannerPodName         = "tls-scanner"
	ScannerContainerName   = "scanner"

	// Component selectors and names
	DaemonSetLabelSelector     = "app=ingress-node-firewall-daemon"
	DaemonSetName              = "ingress-node-firewall-daemon"
	DeploymentName             = "ingress-node-firewall-controller-manager"
	KubeRBACProxyContainerName = "kube-rbac-proxy"

	// Ports
	DaemonSetMetricsPort  = 9301
	ControllerMetricsPort = 9300
	ControllerWebhookPort = 9443

	// Timeouts
	ScannerBuildTimeout         = 20 * time.Minute
	OperatorReadyTimeout        = 5 * time.Minute
	MCPReadyTimeout             = 60 * time.Minute
	ClusterOperatorReadyTimeout = 60 * time.Minute // OpenShift TLS test standard for cluster operator stabilization
	TLSEndpointPollTimeout      = 2 * time.Minute

	// Scanner configuration
	ScannerImage         = "registry.access.redhat.com/ubi9/ubi:latest"
	ScannerCPURequest    = "2"
	ScannerMemoryRequest = "4Gi"
	ScannerCPULimit      = "4"
	ScannerMemoryLimit   = "4Gi"
)

// Pointer helper functions
func boolPtr(b bool) *bool {
	return &b
}

func int64Ptr(i int64) *int64 {
	return &i
}

func stringPtr(s string) *string {
	return &s
}

// formatTLSVersion formats TLS version for scanner result comparison (e.g., "1.2" -> "TLSv1.2")
func formatTLSVersion(tlsVersion string) string {
	return fmt.Sprintf("TLSv%s", tlsVersion)
}

// containsFeatureGate checks if a featuregate is in the enabled list
func containsFeatureGate(enabledGates, featureName string) bool {
	// enabledGates is a space-separated list like "FeatureA FeatureB TLSAdherence"
	gates := strings.Fields(enabledGates)
	for _, gate := range gates {
		if gate == featureName {
			return true
		}
	}
	return false
}
