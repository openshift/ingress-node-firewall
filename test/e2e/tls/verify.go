package tls

import (
	"context"
	"fmt"
	"time"

	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
)

// Assertion Helpers

// assertTLSSupported verifies that TLS connection succeeds and returns error if not
func assertTLSSupported(cs *testclient.ClientSet, ctx context.Context, operatorNS, tlsVersion string) error {
	success, output := TestTLSConnection(cs, ctx, operatorNS, tlsVersion)
	if !success {
		return fmt.Errorf("TLS %s connection failed when it should succeed. Output: %s", tlsVersion, output)
	}
	LogStep(fmt.Sprintf("  TLS %s connection succeeded as expected", tlsVersion))
	return nil
}

// assertTLSNotSupported verifies that TLS connection fails and returns error if it succeeds
func assertTLSNotSupported(cs *testclient.ClientSet, ctx context.Context, operatorNS, tlsVersion string) error {
	success, output := TestTLSConnection(cs, ctx, operatorNS, tlsVersion)
	if success {
		return fmt.Errorf("TLS %s connection succeeded when it should fail. Output: %s", tlsVersion, output)
	}
	LogStep(fmt.Sprintf("  TLS %s connection failed as expected", tlsVersion))
	return nil
}

// verifyDaemonSetTLSArgs is a wrapper with clearer error messages and constants
func verifyDaemonSetTLSArgs(cs *testclient.ClientSet, ctx context.Context, operatorNS string, expectedArgs, missingArgs []string) error {
	if err := VerifyDaemonSetArgs(cs, ctx, operatorNS, DaemonSetName, expectedArgs, missingArgs); err != nil {
		return fmt.Errorf("DaemonSet TLS args verification failed: %v", err)
	}
	LogStep("  DaemonSet TLS args verified")
	return nil
}

// Scenario Helper Functions - Shared logic across all 4 test scenarios

// applyProfileChange checks if profile is already set, applies if needed
// Returns true if restart is needed (profile was changed)
func applyProfileChange(profileName string, checkFn func() (bool, error), applyFn func() error) (bool, error) {
	isAlreadySet, err := checkFn()
	if err != nil {
		return false, fmt.Errorf("failed to check current profile: %v", err)
	}

	if isAlreadySet {
		LogStep(fmt.Sprintf("Step 0: Cluster already in %s configuration, skipping", profileName))
		return false, nil
	}

	LogStep(fmt.Sprintf("Step 0: Applying %s profile", profileName))
	if err := applyFn(); err != nil {
		return false, fmt.Errorf("failed to apply %s profile: %v", profileName, err)
	}

	return true, nil
}

// waitForInfrastructure waits for infrastructure readiness
// clusterWide=true: waits for MCPs, operators, nodes (cluster-wide TLS changes)
// clusterWide=false: waits only for operator pods (operator-level changes)
func waitForInfrastructure(cs *testclient.ClientSet, ctx context.Context, operatorNS string, clusterWide bool) error {
	if clusterWide {
		LogStep("Step 1: Waiting for operator to apply configuration (cluster-wide)")
		return WaitForOperatorRestart(cs, ctx, operatorNS)
	}
	return WaitForOperatorPodsOnly(cs, ctx, operatorNS)
}

// runTLSTest tests TLS connection with assertion
func runTLSTest(cs *testclient.ClientSet, ctx context.Context, operatorNS, stepNum, tlsVersion string, shouldSucceed bool) error {
	expectation := "should succeed"
	if !shouldSucceed {
		expectation = "should FAIL"
	}

	LogStep(fmt.Sprintf("Step %s: Test TLS %s connection (%s)", stepNum, tlsVersion, expectation))

	if shouldSucceed {
		return assertTLSSupported(cs, ctx, operatorNS, tlsVersion)
	}
	return assertTLSNotSupported(cs, ctx, operatorNS, tlsVersion)
}

// verifyTLSArgsForProfile verifies DaemonSet TLS args based on profile type
func verifyTLSArgsForProfile(cs *testclient.ClientSet, ctx context.Context, operatorNS, profileType string) error {
	var stepLabel string
	var expectedArgs, missingArgs []string

	switch profileType {
	case "baseline":
		stepLabel = "Verify --tls-min-version is missing and --tls-cipher-suites is present"
		expectedArgs = []string{"--tls-cipher-suites"}
		missingArgs = []string{"--tls-min-version"}

	case "modern-legacy":
		stepLabel = "Verify --tls-min-version is missing and --tls-cipher-suites is present"
		expectedArgs = []string{"--tls-cipher-suites"}
		missingArgs = []string{"--tls-min-version"}

	case "strict":
		stepLabel = "Verify --tls-min-version is set to VersionTLS13 and --tls-cipher-suites is present"
		expectedArgs = []string{"--tls-min-version=VersionTLS13", "--tls-cipher-suites"}
		missingArgs = []string{}

	case "custom":
		stepLabel = "Verify --tls-min-version and --tls-cipher-suites set correctly"
		expectedArgs = []string{"--tls-min-version", "--tls-cipher-suites"}
		missingArgs = []string{}

	default:
		return fmt.Errorf("unknown profile type: %s", profileType)
	}

	LogStep(fmt.Sprintf("Step 3: %s", stepLabel))
	return verifyDaemonSetTLSArgs(cs, ctx, operatorNS, expectedArgs, missingArgs)
}

// Test Scenario Verification Functions

// VerifyBaselineConfiguration verifies baseline TLS configuration
// Requirements:
//   - Baseline (tlsAdherence: LegacyAdheringComponentsOnly or empty with no tlsSecurityProfile set)
//     1. Check if already in baseline, restore if needed (triggers MCP updates, node reboots)
//     2. Wait for operator restart (only if profile was changed)
//     2a. Force fresh pod restart (only if profile was changed)
//     3. Create scanner pod (AFTER infrastructure is stable)
//     4. Verify --tls-min-version and --tls-cipher-suites CLI args are missing from DaemonSet kube-rbac-proxy
//     5. Test: openssl s_client -tls1_2 → should succeed
//     6. Cleanup scanner pod
func VerifyBaselineConfiguration(cs *testclient.ClientSet, ctx context.Context, operatorNS string) error {
	LogStep("Scenario 1: Baseline TLS Configuration")

	// Step 0: Apply profile change (or skip if already set)
	needsRestart, err := applyProfileChange("baseline", IsBaselineProfile, RestoreBaselineProfile)
	if err != nil {
		return err
	}

	// Step 1: Wait for infrastructure (if changed)
	if needsRestart {
		if err := waitForInfrastructure(cs, ctx, operatorNS, true); err != nil {
			return err
		}
		LogStep("Step 1a: Deleting all pods to get fresh restart after baseline profile change")
		if err := ForceOperatorPodRestart(cs, ctx, operatorNS); err != nil {
			return err
		}
	} else {
		LogStep("Step 1: Skipping operator restart wait (profile unchanged)")
	}

	// Step 2: Setup scanner
	LogStep("Step 2: Setting up TLS scanner pod (after infrastructure stable)")
	if err := SetupSharedScanner(cs, ctx, operatorNS); err != nil {
		return err
	}
	defer func() {
		LogStep("Cleaning up scanner pod")
		CleanupSharedScanner(cs, ctx)
	}()

	// Step 3: Verify args
	if err := verifyTLSArgsForProfile(cs, ctx, operatorNS, "baseline"); err != nil {
		return err
	}

	// Step 4: Test TLS 1.2 (should succeed)
	return runTLSTest(cs, ctx, operatorNS, "4", "1.2", true)
}

// VerifyModernLegacyAdherence verifies Modern TLS with LegacyAdheringComponentsOnly
func VerifyModernLegacyAdherence(cs *testclient.ClientSet, ctx context.Context, operatorNS string) error {
	LogStep("Scenario 2: Modern TLS Profile with LegacyAdheringComponentsOnly")

	// Step 0: Apply profile change (or skip if already set)
	needsRestart, err := applyProfileChange("Modern + LegacyAdheringComponentsOnly", IsModernLegacyProfile, ApplyModernProfileLegacy)
	if err != nil {
		return err
	}

	// Step 1: Wait for infrastructure (if changed)
	if needsRestart {
		if err := waitForInfrastructure(cs, ctx, operatorNS, true); err != nil {
			return err
		}
		LogStep("Step 1a: Deleting all pods to get fresh restart after TLS profile change")
		if err := ForceOperatorPodRestart(cs, ctx, operatorNS); err != nil {
			return err
		}
	} else {
		LogStep("Step 1: Skipping operator restart wait (profile unchanged)")
	}

	// Step 2: Setup scanner
	LogStep("Step 2: Setting up TLS scanner pod (after infrastructure stable)")
	if err := SetupSharedScanner(cs, ctx, operatorNS); err != nil {
		return err
	}
	defer func() {
		LogStep("Cleaning up scanner pod")
		CleanupSharedScanner(cs, ctx)
	}()

	// Step 3: Verify args with retry (race condition prevention)
	LogStep("Step 3: Verify --tls-min-version is missing and --tls-cipher-suites is present")
	LogStep("Waiting for DaemonSet to update with LegacyAdheringComponentsOnly TLS arguments...")
	var verifyErr error
	for i := 0; i < 6; i++ {
		verifyErr = verifyTLSArgsForProfile(cs, ctx, operatorNS, "modern-legacy")
		if verifyErr == nil {
			break
		}
		LogStep(fmt.Sprintf("  DaemonSet args not yet updated, retrying in 10s... (attempt %d/6)", i+1))
		time.Sleep(10 * time.Second)
	}
	if verifyErr != nil {
		return verifyErr
	}

	// Step 4: Test TLS 1.2 with retry
	LogStep("Step 4: Test TLS 1.2 connection (should succeed)")
	var tlsErr error
	for i := 0; i < 5; i++ {
		tlsErr = assertTLSSupported(cs, ctx, operatorNS, "1.2")
		if tlsErr == nil {
			break
		}
		if i < 4 {
			LogStep(fmt.Sprintf("  TLS 1.2 connection failed, retrying in 10s... (attempt %d/5)", i+1))
			time.Sleep(10 * time.Second)
		}
	}
	return tlsErr
}

// VerifyStrictAdherence verifies StrictAllComponents adherence
func VerifyStrictAdherence(cs *testclient.ClientSet, ctx context.Context, operatorNS string) error {
	LogStep("Scenario 3: Update tlsAdherence to StrictAllComponents")

	// Step 0: Update adherence to strict (operator-level only, not cluster-wide)
	LogStep("Step 0: Updating tlsAdherence to StrictAllComponents")
	if err := UpdateAdherenceToStrict(); err != nil {
		return err
	}

	// Step 1: Wait for operator pods only (not cluster-wide)
	if err := waitForInfrastructure(cs, ctx, operatorNS, false); err != nil {
		return err
	}

	LogStep("Step 1a: Deleting all pods to get fresh restart after StrictAllComponents change")
	if err := ForceOperatorPodRestart(cs, ctx, operatorNS); err != nil {
		return err
	}

	// Step 2: Setup scanner
	LogStep("Step 2: Setting up TLS scanner pod (after infrastructure stable)")
	if err := SetupSharedScanner(cs, ctx, operatorNS); err != nil {
		return err
	}
	defer func() {
		LogStep("Cleaning up scanner pod")
		CleanupSharedScanner(cs, ctx)
	}()

	// Step 3: Verify args with retry
	LogStep("Step 3: Verify --tls-min-version is set to VersionTLS13 and --tls-cipher-suites is present")
	LogStep("Waiting for DaemonSet to update with StrictAllComponents TLS arguments...")
	var verifyErr error
	for i := 0; i < 6; i++ {
		verifyErr = verifyTLSArgsForProfile(cs, ctx, operatorNS, "strict")
		if verifyErr == nil {
			break
		}
		LogStep(fmt.Sprintf("  DaemonSet args not yet updated, retrying in 10s... (attempt %d/6)", i+1))
		time.Sleep(10 * time.Second)
	}
	if verifyErr != nil {
		return verifyErr
	}

	// Step 4: Test TLS 1.2 should FAIL with retry
	LogStep("Step 4: Test TLS 1.2 connection (should FAIL)")
	var tls12Err error
	for i := 0; i < 5; i++ {
		tls12Err = assertTLSNotSupported(cs, ctx, operatorNS, "1.2")
		if tls12Err == nil {
			break
		}
		if i < 4 {
			LogStep(fmt.Sprintf("  TLS 1.2 rejection test failed, retrying in 10s... (attempt %d/5)", i+1))
			time.Sleep(10 * time.Second)
		}
	}
	if tls12Err != nil {
		return tls12Err
	}

	// Step 5: Test TLS 1.3 should succeed with retry
	LogStep("Step 5: Test TLS 1.3 connection (should succeed)")
	var tls13Err error
	for i := 0; i < 5; i++ {
		tls13Err = assertTLSSupported(cs, ctx, operatorNS, "1.3")
		if tls13Err == nil {
			break
		}
		if i < 4 {
			LogStep(fmt.Sprintf("  TLS 1.3 connection failed, retrying in 10s... (attempt %d/5)", i+1))
			time.Sleep(10 * time.Second)
		}
	}
	return tls13Err
}

// VerifyCustomConfiguration verifies custom TLS profile
func VerifyCustomConfiguration(cs *testclient.ClientSet, ctx context.Context, operatorNS string) error {
	LogStep("Scenario 4: Custom TLS Profile")

	// Step 0: Apply custom TLS profile (cluster-wide change)
	LogStep("Step 0: Apply custom TLS profile (minTLSVersion=VersionTLS12, custom ciphers)")
	if err := ApplyCustomProfile(); err != nil {
		return err
	}

	// Step 1: Wait for cluster-wide infrastructure
	if err := waitForInfrastructure(cs, ctx, operatorNS, true); err != nil {
		return err
	}

	LogStep("Step 1a: Deleting all pods to get fresh restart after Custom profile change")
	if err := ForceOperatorPodRestart(cs, ctx, operatorNS); err != nil {
		return err
	}

	// Step 2: Setup scanner
	LogStep("Step 2: Setting up TLS scanner pod (after infrastructure stable)")
	if err := SetupSharedScanner(cs, ctx, operatorNS); err != nil {
		return err
	}
	defer func() {
		LogStep("Cleaning up scanner pod")
		CleanupSharedScanner(cs, ctx)
	}()

	// Step 3: Verify args with retry
	LogStep("Step 3: Verify --tls-min-version and --tls-cipher-suites set correctly")
	LogStep("Waiting for DaemonSet to update with Custom profile TLS arguments...")
	var verifyErr error
	for i := 0; i < 6; i++ {
		verifyErr = verifyTLSArgsForProfile(cs, ctx, operatorNS, "custom")
		if verifyErr == nil {
			break
		}
		LogStep(fmt.Sprintf("  DaemonSet args not yet updated, retrying in 10s... (attempt %d/6)", i+1))
		time.Sleep(10 * time.Second)
	}
	if verifyErr != nil {
		return verifyErr
	}

	// Step 4: Test TLS 1.2 should succeed with retry
	LogStep("Step 4: Test TLS 1.2 connection (should succeed)")
	var tlsErr error
	for i := 0; i < 5; i++ {
		tlsErr = assertTLSSupported(cs, ctx, operatorNS, "1.2")
		if tlsErr == nil {
			break
		}
		if i < 4 {
			LogStep(fmt.Sprintf("  TLS 1.2 connection failed, retrying in 10s... (attempt %d/5)", i+1))
			time.Sleep(10 * time.Second)
		}
	}
	return tlsErr
}
