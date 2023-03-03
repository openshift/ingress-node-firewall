package icmp

import (
	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
	"github.com/openshift/ingress-node-firewall/test/e2e/exec"

	ingressnodefwiov1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

func IsConnectivityOK(client *testclient.ClientSet, protocol ingressnodefwiov1alpha1.IngressNodeFirewallRuleProtocolType,
	fromPod *corev1.Pod, targetIP string) bool {
	var stdErr string
	var err error

	_, stdErr, err = PingFromPod(client, protocol, fromPod, targetIP)

	if stdErr != "" || err != nil {
		return false
	}
	return true
}

func PingFromPod(client *testclient.ClientSet, proto ingressnodefwiov1alpha1.IngressNodeFirewallRuleProtocolType,
	sourcePod *corev1.Pod, targetIP string) (string, string, error) {

	switch proto {
	case ingressnodefwiov1alpha1.ProtocolTypeICMP:
		return pingV4(client, sourcePod, targetIP)
	case ingressnodefwiov1alpha1.ProtocolTypeICMP6:
		return pingV6(client, sourcePod, targetIP)
	default:
		panic("Unexpected protocol")
	}
}

func pingV4(client *testclient.ClientSet, sourcePod *corev1.Pod, targetIP string) (string, string, error) {
	return ping(client, sourcePod, targetIP, false)
}

func pingV6(client *testclient.ClientSet, sourcePod *corev1.Pod, targetIP string) (string, string, error) {
	return ping(client, sourcePod, targetIP, true)
}

func ping(client *testclient.ClientSet, sourcePod *corev1.Pod, targetIP string, isV6 bool) (string, string, error) {
	if isV6 {
		return exec.RunExecCommand(client, sourcePod, "ping", "-6", "-c", "1", "-W", "1", targetIP)
	}
	return exec.RunExecCommand(client, sourcePod, "ping", "-4", "-c", "1", "-W", "1", targetIP)
}
