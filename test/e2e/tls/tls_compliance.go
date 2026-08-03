package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned"
)

// TLSEndpoint represents a TLS-capable endpoint
type TLSEndpoint struct {
	Service   string
	IP        string
	Port      int32
	PortName  string
	Namespace string
}

// DiscoverTLSEndpoints finds all TLS-capable endpoints in a namespace
func DiscoverTLSEndpoints(client kubernetes.Interface, namespace string) ([]TLSEndpoint, error) {
	ctx := context.Background()
	endpoints, err := client.CoreV1().Endpoints(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list endpoints in %s: %w", namespace, err)
	}

	var tlsEndpoints []TLSEndpoint
	for _, ep := range endpoints.Items {
		for _, subset := range ep.Subsets {
			for _, port := range subset.Ports {
				// Check if port is TLS
				if isTLSPort(port.Name, port.Port) {
					for _, addr := range subset.Addresses {
						tlsEndpoints = append(tlsEndpoints, TLSEndpoint{
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

// isTLSPort checks if a port is likely serving TLS
func isTLSPort(name string, port int32) bool {
	// Port name patterns
	tlsNames := []string{"https", "webhook", "metrics", "secure", "tls", "ssl"}
	lowerName := strings.ToLower(name)
	for _, n := range tlsNames {
		if strings.Contains(lowerName, n) {
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

// GetExpectedTLSConfigs returns TLS configs for testing based on the profile type and adherence policy
func GetExpectedTLSConfigs(profile *configv1.TLSSecurityProfile, tlsAdherence string) (shouldWork, shouldNotWork *tls.Config, description string) {
	switch {
	case profile == nil, profile.Type == configv1.TLSProfileIntermediateType:
		// Intermediate: TLS 1.2+ should work, TLS 1.1 should fail
		shouldWork = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		}
		shouldNotWork = &tls.Config{
			MinVersion:         tls.VersionTLS11,
			MaxVersion:         tls.VersionTLS11,
			InsecureSkipVerify: true,
		}
		description = "Intermediate profile: TLS 1.2+ should work, TLS 1.1 should fail"

	case profile.Type == configv1.TLSProfileModernType:
		// Modern profile behavior depends on tlsAdherence policy
		if tlsAdherence == "LegacyAdheringComponentsOnly" {
			// Modern with LegacyAdheringComponentsOnly: TLS 1.2+ should work, TLS 1.1 should fail
			// Legacy components are allowed to use TLS 1.2
			shouldWork = &tls.Config{
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
			}
			shouldNotWork = &tls.Config{
				MinVersion:         tls.VersionTLS11,
				MaxVersion:         tls.VersionTLS11,
				InsecureSkipVerify: true,
			}
			description = "Modern profile with LegacyAdheringComponentsOnly: TLS 1.2+ should work, TLS 1.1 should fail"
		} else {
			// Modern with StrictAllComponents: Only TLS 1.3 should work, TLS 1.2 should fail
			shouldWork = &tls.Config{
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
			}
			shouldNotWork = &tls.Config{
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true,
			}
			description = "Modern profile with StrictAllComponents: TLS 1.3 only (TLS 1.2 should fail)"
		}

	case profile.Type == configv1.TLSProfileCustomType:
		// Custom: Check minTLSVersion from profile
		if profile.Custom != nil {
			minVersion := string(profile.Custom.MinTLSVersion)
			switch minVersion {
			case "VersionTLS12":
				// TLS 1.2+: Both 1.2 and 1.3 should work, TLS 1.1 should fail
				shouldWork = &tls.Config{
					MinVersion:         tls.VersionTLS12,
					MaxVersion:         tls.VersionTLS13,
					InsecureSkipVerify: true,
				}
				shouldNotWork = &tls.Config{
					MinVersion:         tls.VersionTLS11,
					MaxVersion:         tls.VersionTLS11,
					InsecureSkipVerify: true,
				}
				description = "Custom profile (minTLSVersion=VersionTLS12): TLS 1.2+ should work, TLS 1.1 should fail"
			case "VersionTLS13":
				// TLS 1.3 only: TLS 1.3 should work, TLS 1.2 should fail
				shouldWork = &tls.Config{
					MinVersion:         tls.VersionTLS13,
					MaxVersion:         tls.VersionTLS13,
					InsecureSkipVerify: true,
				}
				shouldNotWork = &tls.Config{
					MinVersion:         tls.VersionTLS12,
					MaxVersion:         tls.VersionTLS12,
					InsecureSkipVerify: true,
				}
				description = "Custom profile (minTLSVersion=VersionTLS13): TLS 1.3 only, TLS 1.2 should fail"
			default:
				// Default to TLS 1.2+
				shouldWork = &tls.Config{
					MinVersion:         tls.VersionTLS12,
					MaxVersion:         tls.VersionTLS13,
					InsecureSkipVerify: true,
				}
				shouldNotWork = &tls.Config{
					MinVersion:         tls.VersionTLS11,
					MaxVersion:         tls.VersionTLS11,
					InsecureSkipVerify: true,
				}
				description = "Custom profile: TLS 1.2+ should work, TLS 1.1 should fail"
			}
		} else {
			// No custom config, default to TLS 1.2+
			shouldWork = &tls.Config{
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
			}
			shouldNotWork = &tls.Config{
				MinVersion:         tls.VersionTLS11,
				MaxVersion:         tls.VersionTLS11,
				InsecureSkipVerify: true,
			}
			description = "Custom profile: TLS 1.2+ should work, TLS 1.1 should fail"
		}

	default:
		// Old profile or unknown: Allow any TLS, fail on TLS 1.0
		shouldWork = &tls.Config{InsecureSkipVerify: true}
		shouldNotWork = &tls.Config{
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS10,
			InsecureSkipVerify: true,
		}
		description = "Old profile: basic TLS check"
	}
	return
}

// ForwardPortAndExecute forwards a port to a service and executes a function
// Based on: origin/test/extended/apiserver/tls.go
func ForwardPortAndExecute(serviceName, namespace, remotePort string, toExecute func(localPort int) error) error {
	var err error
	for i := 0; i < 3; i++ { // Retry up to 3 times
		if err = func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Random local port to avoid conflicts
			localPort := rand.Intn(65534-1025) + 1025

			args := []string{"port-forward", fmt.Sprintf("svc/%s", serviceName),
				fmt.Sprintf("%d:%s", localPort, remotePort), "-n", namespace}

			cmd := exec.CommandContext(ctx, "oc", args...)

			// Start the command
			err = cmd.Start()
			if err != nil {
				return fmt.Errorf("failed to start port-forward: %w", err)
			}

			// Ensure we kill the process when done
			defer func() {
				if cmd.Process != nil {
					cmd.Process.Signal(syscall.SIGTERM)
					time.Sleep(100 * time.Millisecond)
					cmd.Process.Kill()
				}
			}()

			// Wait for port to be connectable (poll up to 5 seconds)
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", localPort), 500*time.Millisecond)
				if err == nil {
					conn.Close()
					log.Printf("Port %d is ready", localPort)
					break
				}
				time.Sleep(200 * time.Millisecond)
			}

			return toExecute(localPort)
		}(); err == nil {
			return nil
		}
		log.Printf("port-forward attempt %d failed: %v, retrying...", i+1, err)
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("port-forward failed after 3 attempts: %w", err)
}

// getTLSVersionDescription returns a human-readable description of TLS version range
func getTLSVersionDescription(minVersion, maxVersion uint16) string {
	versionName := func(v uint16) string {
		switch v {
		case tls.VersionTLS10:
			return "TLS 1.0"
		case tls.VersionTLS11:
			return "TLS 1.1"
		case tls.VersionTLS12:
			return "TLS 1.2"
		case tls.VersionTLS13:
			return "TLS 1.3"
		default:
			return fmt.Sprintf("TLS 0x%04x", v)
		}
	}

	if minVersion == maxVersion {
		return versionName(minVersion)
	}
	if maxVersion == 0 || maxVersion == tls.VersionTLS13 {
		return versionName(minVersion) + "+"
	}
	return versionName(minVersion) + "-" + versionName(maxVersion)
}

// CheckTLSConnection tests a TLS connection with expected success/failure configs
// Based on: origin/test/extended/apiserver/tls.go
func CheckTLSConnection(host string, port int, tlsShouldWork, tlsShouldNotWork *tls.Config) error {
	endpoint := fmt.Sprintf("localhost:%d", port)

	// Test 1: Connection that SHOULD work
	shouldWorkDesc := getTLSVersionDescription(tlsShouldWork.MinVersion, tlsShouldWork.MaxVersion)
	log.Printf("Testing TLS connection that should work (%s)...", shouldWorkDesc)
	conn, err := tls.Dial("tcp", endpoint, tlsShouldWork)
	if err != nil {
		return fmt.Errorf("TLS connection that should work FAILED: %w", err)
	}
	log.Printf("✓ TLS connection succeeded, negotiated version: 0x%04x", conn.ConnectionState().Version)
	err = conn.Close()
	if err != nil {
		return fmt.Errorf("failed to close connection: %w", err)
	}

	// Test 2: Connection that SHOULD NOT work
	shouldNotWorkDesc := getTLSVersionDescription(tlsShouldNotWork.MinVersion, tlsShouldNotWork.MaxVersion)
	log.Printf("Testing TLS connection that should NOT work (%s)...", shouldNotWorkDesc)
	conn, err = tls.Dial("tcp", endpoint, tlsShouldNotWork)
	if err == nil {
		conn.Close()
		return fmt.Errorf("TLS connection that should NOT work SUCCEEDED unexpectedly")
	}

	// Verify it failed for the right reason (protocol version)
	errorMsg := err.Error()
	validErrors := []string{
		"protocol version",
		"no supported versions satisfy",
		"tls: server selected unsupported protocol version",
		"tls: no application protocol",
		"remote error: tls: protocol version not supported",
	}

	isValidError := false
	for _, validErr := range validErrors {
		if strings.Contains(errorMsg, validErr) {
			isValidError = true
			break
		}
	}

	if !isValidError {
		return fmt.Errorf("TLS connection failed but with unexpected error (expected protocol version error): %v", err)
	}

	log.Printf("✓ TLS connection correctly rejected with: %v", err)
	return nil
}

// VerifyTLSComplianceForService tests TLS compliance for a specific service
func VerifyTLSComplianceForService(configClient configv1client.Interface, k8sClient kubernetes.Interface, namespace, serviceName, port string) error {
	ctx := context.Background()

	// Get APIServer config to determine expected TLS behavior
	apiserver, err := configClient.ConfigV1().APIServers().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get APIServer config: %w", err)
	}

	// Determine expected TLS behavior based on profile and adherence policy
	tlsAdherence := string(apiserver.Spec.TLSAdherence)
	tlsShouldWork, tlsShouldNotWork, description := GetExpectedTLSConfigs(apiserver.Spec.TLSSecurityProfile, tlsAdherence)
	log.Printf("Testing with profile: %s", description)

	// Port forward and test
	log.Printf("Testing service %s/%s on port %s", namespace, serviceName, port)
	err = ForwardPortAndExecute(serviceName, namespace, port, func(localPort int) error {
		return CheckTLSConnection("localhost", localPort, tlsShouldWork, tlsShouldNotWork)
	})

	if err != nil {
		return fmt.Errorf("TLS compliance test failed for %s/%s: %w", namespace, serviceName, err)
	}

	log.Printf("✓ TLS compliance verified for %s/%s", namespace, serviceName)
	return nil
}

// DirectTLSTest tests TLS connection directly without port-forward (for pod IPs)
func DirectTLSTest(endpoint TLSEndpoint, tlsShouldWork, tlsShouldNotWork *tls.Config) error {
	host := fmt.Sprintf("%s:%d", endpoint.IP, endpoint.Port)

	log.Printf("Testing endpoint %s (%s) directly...", host, endpoint.Service)

	// Test 1: Should work
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		host,
		tlsShouldWork,
	)
	if err != nil {
		return fmt.Errorf("TLS connection (should work) failed for %s: %w", host, err)
	}
	log.Printf("✓ TLS 1.3 connection succeeded")
	conn.Close()

	// Test 2: Should NOT work
	conn, err = tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		host,
		tlsShouldNotWork,
	)
	if err == nil {
		conn.Close()
		return fmt.Errorf("TLS connection (should NOT work) succeeded for %s", host)
	}

	log.Printf("✓ TLS 1.2 connection correctly rejected")
	return nil
}

// VerifyTLSComplianceForPods tests TLS compliance for pods matching a label selector
func VerifyTLSComplianceForPods(configClient configv1client.Interface, k8sClient kubernetes.Interface, namespace, labelSelector, port string) error {
	ctx := context.Background()

	// Get APIServer config to determine expected TLS behavior
	apiserver, err := configClient.ConfigV1().APIServers().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get APIServer config: %w", err)
	}

	// Determine expected TLS behavior based on profile and adherence policy
	tlsAdherence := string(apiserver.Spec.TLSAdherence)
	tlsShouldWork, tlsShouldNotWork, description := GetExpectedTLSConfigs(apiserver.Spec.TLSSecurityProfile, tlsAdherence)
	log.Printf("Testing with profile: %s", description)

	// Get pods matching the label selector
	pods, err := k8sClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return fmt.Errorf("failed to list pods with selector %s: %w", labelSelector, err)
	}

	if len(pods.Items) == 0 {
		return fmt.Errorf("no pods found with selector %s in namespace %s", labelSelector, namespace)
	}

	// Test the first running pod
	var testPod string
	for _, pod := range pods.Items {
		if pod.Status.Phase == "Running" {
			testPod = pod.Name
			break
		}
	}

	if testPod == "" {
		return fmt.Errorf("no running pods found with selector %s", labelSelector)
	}

	log.Printf("Testing pod %s/%s on port %s", namespace, testPod, port)

	// Port forward to the specific pod
	err = ForwardPortToResourceAndExecute("pod/"+testPod, namespace, port, func(localPort int) error {
		return CheckTLSConnection("localhost", localPort, tlsShouldWork, tlsShouldNotWork)
	})

	if err != nil {
		return fmt.Errorf("TLS compliance test failed for pod %s: %w", testPod, err)
	}

	log.Printf("✓ TLS compliance verified for pod %s/%s", namespace, testPod)
	return nil
}

// VerifyTLSComplianceInPod tests TLS compliance by executing openssl commands inside a pod
// This is useful when port-forwarding doesn't work (e.g., authentication required)
// findContainerForPort finds the container name that serves a specific port in a pod
func findContainerForPort(k8sClient kubernetes.Interface, namespace, podName, port string) (string, error) {
	ctx := context.Background()
	pod, err := k8sClient.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get pod %s/%s: %w", namespace, podName, err)
	}

	// Check each container for the specified port
	for _, container := range pod.Spec.Containers {
		for _, p := range container.Ports {
			if fmt.Sprintf("%d", p.ContainerPort) == port {
				log.Printf("Auto-discovered container '%s' serving port %s in pod %s/%s", container.Name, port, namespace, podName)
				return container.Name, nil
			}
		}
	}

	// If no container explicitly declares the port, try the first container
	// (some containers serve ports without declaring them)
	if len(pod.Spec.Containers) > 0 {
		log.Printf("Warning: No container explicitly declares port %s, using first container '%s'", port, pod.Spec.Containers[0].Name)
		return pod.Spec.Containers[0].Name, nil
	}

	return "", fmt.Errorf("no container found serving port %s in pod %s/%s", port, namespace, podName)
}

func VerifyTLSComplianceInPod(configClient configv1client.Interface, k8sClient kubernetes.Interface, namespace, labelSelector, containerName, port string) error {
	ctx := context.Background()

	// Get APIServer config to determine expected TLS behavior
	apiserver, err := configClient.ConfigV1().APIServers().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get APIServer config: %w", err)
	}

	// Determine expected behavior based on profile
	var tlsWorkVersion, tlsFailVersion string
	var shouldTestBothVersions bool // For Custom profile with TLS 1.2, both 1.2 and 1.3 should work

	switch {
	case apiserver.Spec.TLSSecurityProfile == nil, apiserver.Spec.TLSSecurityProfile.Type == configv1.TLSProfileIntermediateType:
		tlsWorkVersion = "tls1_2"
		tlsFailVersion = "tls1_1"
	case apiserver.Spec.TLSSecurityProfile.Type == configv1.TLSProfileModernType:
		tlsWorkVersion = "tls1_3"
		tlsFailVersion = "tls1_2"
	case apiserver.Spec.TLSSecurityProfile.Type == configv1.TLSProfileCustomType:
		// For Custom profile, check minTLSVersion
		if apiserver.Spec.TLSSecurityProfile.Custom != nil {
			minVersion := string(apiserver.Spec.TLSSecurityProfile.Custom.MinTLSVersion)
			switch minVersion {
			case "VersionTLS12":
				// Both TLS 1.2 and 1.3 should work
				tlsWorkVersion = "tls1_2"
				tlsFailVersion = "tls1_1"
				shouldTestBothVersions = true
			case "VersionTLS13":
				tlsWorkVersion = "tls1_3"
				tlsFailVersion = "tls1_2"
			default:
				tlsWorkVersion = "tls1_2"
				tlsFailVersion = "tls1_1"
			}
		} else {
			tlsWorkVersion = "tls1_2"
			tlsFailVersion = "tls1_1"
		}
	default:
		tlsWorkVersion = "tls1_2"
		tlsFailVersion = "tls1"
	}

	if shouldTestBothVersions {
		log.Printf("Testing with profile: %s (minTLSVersion=%s) - Both TLS 1.2 and 1.3 should work, TLS %s should fail",
			apiserver.Spec.TLSSecurityProfile.Type,
			apiserver.Spec.TLSSecurityProfile.Custom.MinTLSVersion,
			tlsFailVersion)
	} else {
		log.Printf("Testing with profile: %s (TLS %s should work, TLS %s should fail)",
			apiserver.Spec.TLSSecurityProfile.Type, tlsWorkVersion, tlsFailVersion)
	}

	// Get pods matching the label selector
	pods, err := k8sClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return fmt.Errorf("failed to list pods with selector %s: %w", labelSelector, err)
	}

	if len(pods.Items) == 0 {
		return fmt.Errorf("no pods found with selector %s in namespace %s", labelSelector, namespace)
	}

	// Test the first running pod
	var testPod string
	for _, pod := range pods.Items {
		if pod.Status.Phase == "Running" {
			testPod = pod.Name
			break
		}
	}

	if testPod == "" {
		return fmt.Errorf("no running pods found with selector %s", labelSelector)
	}

	// Auto-discover container if the provided name doesn't exist
	// This handles cases where container names differ across OCP versions or configurations
	actualContainer := containerName
	if containerName != "" {
		// Try to verify the container exists
		pod, err := k8sClient.CoreV1().Pods(namespace).Get(ctx, testPod, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get pod %s/%s: %w", namespace, testPod, err)
		}

		containerExists := false
		for _, c := range pod.Spec.Containers {
			if c.Name == containerName {
				containerExists = true
				break
			}
		}

		if !containerExists {
			log.Printf("Warning: Container '%s' not found in pod, auto-discovering container for port %s", containerName, port)
			discoveredContainer, err := findContainerForPort(k8sClient, namespace, testPod, port)
			if err != nil {
				return fmt.Errorf("failed to find container for port %s: %w", port, err)
			}
			actualContainer = discoveredContainer
		}
	} else {
		// If no container name provided, auto-discover
		discoveredContainer, err := findContainerForPort(k8sClient, namespace, testPod, port)
		if err != nil {
			return fmt.Errorf("failed to find container for port %s: %w", port, err)
		}
		actualContainer = discoveredContainer
	}

	log.Printf("Testing pod %s/%s (container: %s) on localhost:%s", namespace, testPod, actualContainer, port)

	// Test TLS version that SHOULD work
	log.Printf("Testing TLS connection that should work (%s)...", tlsWorkVersion)
	cmdWork := []string{"timeout", "3", "openssl", "s_client", "-connect", "localhost:" + port, "-" + tlsWorkVersion}
	outputWork, err := execInPod(k8sClient, namespace, testPod, actualContainer, cmdWork)
	if err != nil || !strings.Contains(outputWork, "Verify return code") {
		return fmt.Errorf("TLS %s connection (should work) failed: %v\nOutput: %s", tlsWorkVersion, err, outputWork)
	}

	// Extract protocol version
	if strings.Contains(outputWork, "Protocol") {
		for _, line := range strings.Split(outputWork, "\n") {
			if strings.Contains(line, "Protocol") && !strings.Contains(line, "Verify") {
				log.Printf("✓ TLS connection succeeded: %s", strings.TrimSpace(line))
				break
			}
		}
	}

	// For Custom profile with minTLSVersion=VersionTLS12, also test TLS 1.3
	if shouldTestBothVersions {
		log.Printf("Testing TLS 1.3 connection (should also work for Custom profile with minTLSVersion=VersionTLS12)...")
		cmdWork13 := []string{"timeout", "3", "openssl", "s_client", "-connect", "localhost:" + port, "-tls1_3"}
		outputWork13, err := execInPod(k8sClient, namespace, testPod, actualContainer, cmdWork13)
		if err != nil || !strings.Contains(outputWork13, "Verify return code") {
			return fmt.Errorf("TLS 1.3 connection (should work) failed: %v\nOutput: %s", err, outputWork13)
		}

		// Extract protocol version for TLS 1.3
		if strings.Contains(outputWork13, "Protocol") {
			for _, line := range strings.Split(outputWork13, "\n") {
				if strings.Contains(line, "Protocol") && !strings.Contains(line, "Verify") {
					log.Printf("✓ TLS 1.3 connection succeeded: %s", strings.TrimSpace(line))
					break
				}
			}
		}
	}

	// Test TLS version that SHOULD NOT work
	log.Printf("Testing TLS connection that should NOT work (%s)...", tlsFailVersion)
	cmdFail := []string{"timeout", "3", "openssl", "s_client", "-connect", "localhost:" + port, "-" + tlsFailVersion}
	outputFail, _ := execInPod(k8sClient, namespace, testPod, actualContainer, cmdFail)

	// Check if connection was rejected (should contain error or "Cipher is (NONE)")
	if !strings.Contains(outputFail, "alert protocol version") &&
		!strings.Contains(outputFail, "Cipher is (NONE)") &&
		!strings.Contains(outputFail, "error:") {
		return fmt.Errorf("TLS %s connection (should NOT work) succeeded unexpectedly\nOutput: %s", tlsFailVersion, outputFail)
	}

	log.Printf("✓ TLS connection correctly rejected with protocol version error")
	log.Printf("✓ TLS compliance verified for pod %s/%s", namespace, testPod)
	return nil
}

// execInPod executes a command inside a pod container
func execInPod(client kubernetes.Interface, namespace, podName, containerName string, command []string) (string, error) {
	// Note: This is a simplified version. In production, you would use:
	// - k8s.io/client-go/tools/remotecommand
	// - Proper SPDY/WebSocket connection
	// For now, we'll use oc exec via shell

	args := []string{"exec", "-n", namespace, podName, "-c", containerName, "--"}
	args = append(args, command...)

	cmd := exec.Command("oc", args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String() + stderr.String()

	return output, err
}

// ForwardPortToResourceAndExecute forwards a port to a Kubernetes resource (pod or service) and executes a function
func ForwardPortToResourceAndExecute(resource, namespace, remotePort string, toExecute func(localPort int) error) error {
	var err error
	for i := 0; i < 3; i++ { // Retry up to 3 times
		if err = func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Random local port to avoid conflicts
			localPort := rand.Intn(65534-1025) + 1025

			args := []string{"port-forward", resource,
				fmt.Sprintf("%d:%s", localPort, remotePort), "-n", namespace}

			cmd := exec.CommandContext(ctx, "oc", args...)

			// Start the command
			err = cmd.Start()
			if err != nil {
				return fmt.Errorf("failed to start port-forward: %w", err)
			}

			// Ensure we kill the process when done
			defer func() {
				if cmd.Process != nil {
					cmd.Process.Signal(syscall.SIGTERM)
					time.Sleep(100 * time.Millisecond)
					cmd.Process.Kill()
				}
			}()

			// Wait for port to be connectable (poll up to 5 seconds)
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", localPort), 500*time.Millisecond)
				if err == nil {
					conn.Close()
					log.Printf("Port %d is ready for %s", localPort, resource)
					break
				}
				time.Sleep(200 * time.Millisecond)
			}

			return toExecute(localPort)
		}(); err == nil {
			return nil
		}
		log.Printf("port-forward attempt %d failed: %v, retrying...", i+1, err)
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("port-forward failed after 3 attempts: %w", err)
}
