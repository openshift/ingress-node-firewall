package nodefwloader

import (
	"os"
	"os/user"
	"testing"
)

func TestAddOrUpdateRules(t *testing.T) {
	// FIXME: This test can race with the tests in ebpf/ebpfsyncer_test.go due to "Deleting all XDP pins". This
	// test here might delete the pins while the other tests are running.
	// Skip this test unless someone wants to run it explicitly. This test here can also probably be dropped completely
	// after the below if index issue (see FIXME below) is fixed. The ebpfsyncer tests test the same code just from
	// a higher level.
	t.Skip()
	beforeEach(t)
	defer afterEach(t)
	// Get eBPF keys for and rules for tc0.
	key0a, _ := BuildEBPFKey(100, "10.0.0.0/8")
	key0b, _ := BuildEBPFKey(100, "192.0.2.0/24")
	rule0 := BpfRulesValSt{
		Rules: [100]BpfRuleTypeSt{
			{
				RuleId: 10,
				Action: 1,
			},
		},
	}
	// Get eBPF keys for and rules for tc1.
	key1a, _ := BuildEBPFKey(100, "10.0.0.0/8")
	key1b, _ := BuildEBPFKey(100, "10.0.0.0/16")
	rule1 := BpfRulesValSt{
		Rules: [100]BpfRuleTypeSt{
			{
				RuleId: 10,
				Action: 1,
			},
		},
	}
	// Get eBPF keys for and rules for tc2.

	key2a, _ := BuildEBPFKey(100, "10.0.0.0/8")
	key2b, _ := BuildEBPFKey(101, "10.0.0.0/8")
	rule2 := BpfRulesValSt{
		Rules: [100]BpfRuleTypeSt{
			{
				RuleId: 10,
				Action: 1,
			},
		},
	}

	tcs := []struct {
		inputRules map[BpfLpmIpKeySt]BpfRulesValSt
	}{
		{
			inputRules: map[BpfLpmIpKeySt]BpfRulesValSt{
				key0a: rule0,
				key0b: rule0,
			},
		},
		{
			inputRules: map[BpfLpmIpKeySt]BpfRulesValSt{
				key1a: rule1,
				key1b: rule1,
			},
		},
		{
			inputRules: map[BpfLpmIpKeySt]BpfRulesValSt{
				key2a: rule2,
				key2b: rule2,
			},
		},
	}

	for i, tc := range tcs {
		cleanup(t)
		infc, err := NewIngNodeFwController()
		if err != nil {
			t.Fatalf("TestIngressNodeFirewallTableMapUpdate(%d): Failed to create nodefw controller instance, err: %q", i, err)
		}
		if err := infc.addOrUpdateRules(tc.inputRules); err != nil {
			t.Fatalf("TestIngressNodeFirewallTableMapUpdate(%d): Adding rules failed with err: %q", i, err)
		}
		resultRules, err := infc.GetBPFMapContentForTest()
		if err != nil {
			t.Fatalf("Could not get BPF map content, err: %q", err)
		}
		t.Logf("TestIngressNodeFirewallTableMapUpdate(%d): Got result rules %v", i, resultRules)
		if len(resultRules) != len(tc.inputRules) {
			t.Fatalf("TestIngressNodeFirewallTableMapUpdate(%d): Unexpected result - length mismatch. Expected keys are %v but got %v",
				i, tc.inputRules, resultRules)
		}
		for expectedKey := range tc.inputRules {
			if _, ok := resultRules[expectedKey]; !ok {
				t.Fatalf("TestIngressNodeFirewallTableMapUpdate(%d): Could not find expected key %v in result %v",
					i, expectedKey, resultRules)
			}
		}
	}
}

func beforeEach(t *testing.T) {
	// First, check if the user is root; skip otherwise.
	t.Log("Checking if this test runs with sufficiently high privileges")
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Unable to get current user: %s", err)
	}
	if currentUser.Uid != "0" {
		t.Skipf("Skipping this test due to insufficient privileges")
	}

	cleanup(t)
}

func afterEach(t *testing.T) {
	cleanup(t)
}

func cleanup(t *testing.T) {
	t.Log("Deleting all XDP pins")
	err := os.RemoveAll("/sys/fs/bpf/xdp_ingress_node_firewall_process")
	if err != nil {
		t.Log(err)
	}
}
