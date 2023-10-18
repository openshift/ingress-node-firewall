package transport

import (
	"fmt"
	"log"
	"strings"
	"time"

	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
	"github.com/openshift/ingress-node-firewall/test/e2e/exec"
	"github.com/openshift/ingress-node-firewall/test/e2e/images"
	"github.com/openshift/ingress-node-firewall/test/e2e/pods"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func GetAndEnsureRunningClient(client *testclient.ClientSet, podName, namespace string, label, affinity, antiAffinity map[string]string,
	retryInterval, timeout time.Duration) (*corev1.Pod, func(), error) {

	pod := getClient(podName, namespace, label, affinity, antiAffinity)
	pod, err := pods.EnsureRunning(client, pod, namespace, retryInterval, timeout)
	if err != nil {
		return nil, nil, err
	}
	return pod, func() {
		if err = pods.EnsureDeleted(client, pod, timeout); err != nil {
			panic(err)
		}
	}, nil
}

func getClient(clientPodName, namespace string, labels, affinity, antiAffinity map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clientPodName,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			Affinity: &corev1.Affinity{
				PodAffinity: &corev1.PodAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
						{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: affinity,
							},
							TopologyKey: "kubernetes.io/hostname",
						},
					},
				},
				PodAntiAffinity: &corev1.PodAntiAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
						{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: antiAffinity,
							},
							TopologyKey: "kubernetes.io/hostname",
						},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:    "client",
					Image:   images.NetcatImage(),
					Command: []string{"/bin/sh", "-c", "sleep INF"},
					Resources: corev1.ResourceRequirements{
						Requests: map[corev1.ResourceName]resource.Quantity{corev1.ResourceMemory: resource.MustParse("256Mi")},
						Limits:   map[corev1.ResourceName]resource.Quantity{corev1.ResourceMemory: resource.MustParse("512Mi")},
					},
				},
			},
		}}
}

func GetAndEnsureRunningTransportServer(client *testclient.ClientSet, podName, namespace string, labels, affinity, antiAffinity map[string]string,
	retryInterval, timeout time.Duration) (*corev1.Pod, func(), error) {

	pod := getServer(podName, namespace, labels, affinity, antiAffinity)
	pod, err := pods.EnsureRunning(client, pod, namespace, retryInterval, timeout)
	if err != nil {
		return nil, nil, err
	}
	return pod, func() {
		if err = pods.EnsureDeleted(client, pod, timeout); err != nil {
			panic(err)
		}
	}, nil
}

func getServer(serverPodName, namespace string, labels, affinity, antiAffinity map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serverPodName,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			Affinity: &corev1.Affinity{
				PodAffinity: &corev1.PodAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
						{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: affinity,
							},
							TopologyKey: "kubernetes.io/hostname",
						},
					},
				},
				PodAntiAffinity: &corev1.PodAntiAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
						{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: antiAffinity,
							},
							TopologyKey: "kubernetes.io/hostname",
						},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:    "server",
					Image:   images.NetcatImage(),
					Command: []string{"/bin/sh", "-c", "sleep INF"},
					Resources: corev1.ResourceRequirements{
						Requests: map[corev1.ResourceName]resource.Quantity{corev1.ResourceMemory: resource.MustParse("256Mi")},
						Limits:   map[corev1.ResourceName]resource.Quantity{corev1.ResourceMemory: resource.MustParse("512Mi")},
					},
				},
			},
		}}
}

func StartServerForProtocol(client *testclient.ClientSet, protocol ingressnodefwv1alpha1.IngressNodeFirewallRuleProtocolType,
	pod *corev1.Pod, port string) chan string {
	serverOutput := make(chan string)
	var command []string
	timeoutMessage1 := "command terminated with exit code 124" // 124 is timeout exit code
	timeoutMessage2 := "command terminated with exit code 143" // 143 is timeout exit code

	switch protocol {
	case ingressnodefwv1alpha1.ProtocolTypeICMP, ingressnodefwv1alpha1.ProtocolTypeICMP6:
		// no-op. Server not needed for ICMP or ICMPv6
		return nil
	// netcat, by default, will end when one connection is successful, but when no connection is expected, we use timeout to
	// terminate netcat. Test cases, in either case will be blocked until it ends because it expects its stdout and that
	// is only accomplished when netcat ends.
	case ingressnodefwv1alpha1.ProtocolTypeTCP:
		command = []string{"timeout", "1s", "ncat", "--listen", "--source-port", port, "--verbose"}
	case ingressnodefwv1alpha1.ProtocolTypeUDP:
		command = []string{"timeout", "1s", "ncat", "--udp", "--listen", "--source-port", port, "--verbose"}
	case ingressnodefwv1alpha1.ProtocolTypeSCTP:
		command = []string{"timeout", "1s", "ncat", "--sctp", "--listen", "--source-port", port, "--verbose"}
	default:
		panic("Unimplemented protocol")
	}

	go func() {
		stdOut, _, err := exec.RunExecCommand(client, pod, command...)
		if err != nil && !strings.Contains(err.Error(), timeoutMessage1) && !strings.Contains(err.Error(), timeoutMessage2) {
			log.Printf("StartServerForProtocol: starting server failed: %v", err)
		}
		serverOutput <- stdOut
		close(serverOutput)
	}()

	// wait for server to start
	time.Sleep(time.Millisecond * 50)
	return serverOutput
}

func ConnectToPortFromPod(client *testclient.ClientSet, proto ingressnodefwv1alpha1.IngressNodeFirewallRuleProtocolType, v6 bool,
	sourcePod *corev1.Pod, sourceIP, destinationIP, destinationPort string) (string, string, error) {
	switch proto {
	case ingressnodefwv1alpha1.ProtocolTypeTCP:
		if v6 {
			return ncClientTCPV6(client, sourcePod, sourceIP, destinationIP, destinationPort)
		}
		return ncClientTCPV4(client, sourcePod, sourceIP, destinationIP, destinationPort)
	case ingressnodefwv1alpha1.ProtocolTypeUDP:
		if v6 {
			return ncClientUDPV6(client, sourcePod, sourceIP, destinationIP, destinationPort)
		}
		return ncClientUDPV4(client, sourcePod, sourceIP, destinationIP, destinationPort)
	case ingressnodefwv1alpha1.ProtocolTypeSCTP:
		if v6 {
			return ncClientSCTPV6(client, sourcePod, sourceIP, destinationIP, destinationPort)
		}
		return ncClientSCTPV4(client, sourcePod, sourceIP, destinationIP, destinationPort)
	default:
		panic("Unsupported protocol")
	}
}

func ncClientTCPV4(client *testclient.ClientSet, sourcePod *corev1.Pod, sourceIP, destinationIP, dPort string) (string, string, error) {
	return ncClientTransport(client, sourcePod, sourceIP, destinationIP, dPort, "-4")
}

func ncClientTCPV6(client *testclient.ClientSet, sourcePod *corev1.Pod, sourceIP, destinationIP, dPort string) (string, string, error) {
	return ncClientTransport(client, sourcePod, sourceIP, destinationIP, dPort, "-6")
}

func ncClientUDPV4(client *testclient.ClientSet, sourcePod *corev1.Pod, sourceIP, destinationIP, dPort string) (string, string, error) {
	return ncClientTransport(client, sourcePod, sourceIP, destinationIP, dPort, "--udp", "-4")
}

func ncClientUDPV6(client *testclient.ClientSet, sourcePod *corev1.Pod, sourceIP, destinationIP, dPort string) (string, string, error) {
	return ncClientTransport(client, sourcePod, sourceIP, destinationIP, dPort, "--udp", "-6")
}

func ncClientSCTPV4(client *testclient.ClientSet, sourcePod *corev1.Pod, sourceIP, destinationIP, dPort string) (string, string, error) {
	return ncClientTransport(client, sourcePod, sourceIP, destinationIP, dPort, "--sctp", "-4")
}

func ncClientSCTPV6(client *testclient.ClientSet, sourcePod *corev1.Pod, sourceIP, destinationIP, dPort string) (string, string, error) {
	return ncClientTransport(client, sourcePod, sourceIP, destinationIP, dPort, "--sctp", "-6")
}

func ncClientTransport(client *testclient.ClientSet, sourcePod *corev1.Pod, sourceIP, destinationIP, dPort string, additionalFlag ...string) (string, string, error) {
	command := []string{"sh", "-c", fmt.Sprintf("ncat %s --wait 1 %s %s --verbose", strings.Join(additionalFlag, " "), destinationIP, dPort)}
	return exec.RunExecCommandWithStdin(client, sourcePod, sourceIP, command...)
}
