package transport

import (
	"fmt"
	"log"
	"strconv"
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
		if err = pods.EnsureDeleted(client, pod, retryInterval, timeout); err != nil {
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
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{"NET_RAW"},
						},
					},
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
		if err = pods.EnsureDeleted(client, pod, retryInterval, timeout); err != nil {
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
					// NET_RAW lets SniffFragments open an AF_PACKET socket here to see
					// what actually made it past the firewall.
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{"NET_RAW"},
						},
					},
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

// fragmentDatagramBytes is comfortably above the 1500 byte MTU used by the pod
// network, so the kernel has to split the datagram into three fragments.
const fragmentDatagramBytes = 3000

// fragmentDatagramCount datagrams are sent, spaced apart, so that a sniffer which
// took a moment to bind still catches the later ones. A single datagram would let a
// slow start look identical to a packet the firewall dropped.
const fragmentDatagramCount = 3

// fragmentSenderScript sends one oversized UDP datagram and lets the kernel
// fragment it.
//
// Hand-rolling fragments with a raw socket does not work here, and hping3 (used by
// an earlier version of this helper) could not have worked either: conntrack's
// nf_defrag hook reassembles fragments as they pass through the sending node, so
// anything crafted inside the pod arrives at the destination as a single packet.
// Letting the sender's own IP stack fragment an oversized datagram produces
// fragments after that hook, which is also what real traffic looks like.
//
// Only UDP is offered. TCP never fragments - it segments to the MSS instead - and
// the firewall rejects fragments in ip_extract_l4info() before it looks at the L4
// protocol at all, so UDP exercises the whole code path.
//
// It prints "sent" on success so the caller can tell a real send apart from a
// python failure: an assertion that a packet was dropped must not pass just
// because nothing was ever transmitted.
const fragmentSenderScript = `
import socket, sys, time

family, dst, dport, size, count = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
af = socket.AF_INET6 if family == "v6" else socket.AF_INET
s = socket.socket(af, socket.SOCK_DGRAM)
for i in range(count):
    s.sendto(b"A" * size, (dst, dport))
    if i + 1 < count:
        time.sleep(0.4)
s.close()
print("sent")
`

// SendFragmentedPacket sends a fragmented UDP datagram from sourcePod towards
// destinationIP. It reports an error if the datagram could not be transmitted; a
// successful send says nothing about whether the firewall let it through, which
// the caller must determine separately (for example from daemon drop events).
func SendFragmentedPacket(client *testclient.ClientSet, v6 bool, sourcePod *corev1.Pod,
	destinationIP, destinationPort string) error {
	family := "v4"
	if v6 {
		family = "v6"
	}

	stdout, stderr, err := exec.RunExecCommand(client, sourcePod, "python3", "-c", fragmentSenderScript,
		family, destinationIP, destinationPort, strconv.Itoa(fragmentDatagramBytes),
		strconv.Itoa(fragmentDatagramCount))
	if err != nil {
		return fmt.Errorf("failed to send %s fragments to %s:%s: %v (stderr: %s)",
			family, destinationIP, destinationPort, err, stderr)
	}
	if !strings.Contains(stdout, "sent") {
		return fmt.Errorf("fragment sender produced no confirmation for %s to %s:%s (stdout: %q, stderr: %q)",
			family, destinationIP, destinationPort, stdout, stderr)
	}
	log.Printf("sent %s fragments to %s:%s", family, destinationIP, destinationPort)
	return nil
}

// fragmentSniffDuration bounds the sniffer so a packet that never arrives fails the
// test instead of hanging it. It has to outlast the spread of datagrams that
// SendFragmentedPacket emits, plus the time the sniffer takes to bind.
const fragmentSniffDuration = 6 * time.Second

// fragmentSniffCollectTimeout caps how long the caller waits for the sniffer's answer.
// RunExecCommand streams with context.Background(), so a wedged SPDY connection never
// returns on its own and would otherwise hang the spec until the suite timeout.
const fragmentSniffCollectTimeout = fragmentSniffDuration + 30*time.Second

// fragmentSnifferScript counts IP fragments arriving from a given source on the pod's
// own interface. PACKET_OUTGOING frames are skipped so the pod's own replies are not
// counted as arrivals.
//
// For IPv6 it looks for a Fragment header (next header 44) directly after the fixed
// header, which is what a sending kernel produces.
const fragmentSnifferScript = `
import socket, struct, sys, time

family, want_src, dur = sys.argv[1], sys.argv[2], float(sys.argv[3])
PACKET_OUTGOING = 4
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
s.bind(("eth0", 0))
s.settimeout(dur)
end = time.time() + dur
n = 0
while time.time() < end:
    try:
        f, a = s.recvfrom(65535)
    except socket.timeout:
        break
    if a[2] == PACKET_OUTGOING:
        continue
    et = struct.unpack("!H", f[12:14])[0]
    if family == "v4" and et == 0x0800 and len(f) >= 34:
        if struct.unpack("!H", f[20:22])[0] & 0x3FFF and socket.inet_ntoa(f[26:30]) == want_src:
            n += 1
    elif family == "v6" and et == 0x86DD and len(f) >= 54:
        if f[20] == 44 and socket.inet_ntop(socket.AF_INET6, f[22:38]) == want_src:
            n += 1
print("frags=%d" % n)
`

// SniffFragments starts an AF_PACKET sniffer inside pod and returns a collect function.
// The caller sends its traffic, then calls collect to get the number of IP fragments
// from sourceIP that reached the pod. collect returns -1 if the sniffer did not report
// in time, which fails both "fragments arrived" and "no fragments arrived" rather than
// letting a broken sniffer satisfy either one.
//
// This observes what the firewall actually did. XDP_DROP happens on the node interface,
// upstream of the pod's veth, so any fragment counted here is one the firewall let
// through. Drop events cannot answer this: bpf_perf_event_output only carries the first
// MAX_EVENT_DATA (256) bytes of a packet, so on a cluster whose MTU leaves every
// fragment above that, a correctly dropped fragment still produces no usable event.
func SniffFragments(client *testclient.ClientSet, pod *corev1.Pod, v6 bool, sourceIP string) func() int {
	family := "v4"
	if v6 {
		family = "v6"
	}

	// Buffered so the goroutine can always finish its send and exit, even when collect
	// has already given up waiting. An unbuffered channel would leak it for the rest of
	// the suite.
	out := make(chan int, 1)
	go func() {
		stdout, stderr, err := exec.RunExecCommand(client, pod, "python3", "-c", fragmentSnifferScript,
			family, sourceIP, strconv.Itoa(int(fragmentSniffDuration.Seconds())))
		if err != nil {
			log.Printf("fragment sniffer in pod %s failed: %v (stderr: %s)", pod.Name, err, stderr)
			out <- -1
			return
		}
		var count int
		if _, err := fmt.Sscanf(strings.TrimSpace(stdout), "frags=%d", &count); err != nil {
			log.Printf("fragment sniffer in pod %s gave unparsable output %q (stderr: %q)", pod.Name, stdout, stderr)
			out <- -1
			return
		}
		log.Printf("%s saw %d inbound %s fragments from %s", pod.Name, count, family, sourceIP)
		out <- count
	}()

	// let the socket open before the caller starts sending
	time.Sleep(time.Second)

	return func() int {
		select {
		case count := <-out:
			return count
		case <-time.After(fragmentSniffCollectTimeout):
			log.Printf("fragment sniffer in pod %s did not report within %s", pod.Name, fragmentSniffCollectTimeout)
			return -1
		}
	}
}
