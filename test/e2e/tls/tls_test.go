//go:build e2etests
// +build e2etests

package tls

import (
	"testing"

	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
)

// TestEnableTLSAdherence tests the feature gate enablement
// This test will actually patch the cluster's feature gate
func TestEnableTLSAdherence(t *testing.T) {
	client := testclient.New("")
	if client == nil {
		t.Fatal("Failed to create test client")
	}

	t.Log("=== Testing TLSAdherence Feature Gate Enablement ===")

	err := EnableTLSAdherence(client)
	if err != nil {
		t.Fatalf("Failed to enable TLSAdherence: %v", err)
	}

	t.Log("✓ TLSAdherence feature gate enabled successfully!")
	t.Log("✓ All cluster validation steps passed")
}
