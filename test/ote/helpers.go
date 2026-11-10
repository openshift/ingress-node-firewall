package ote

import (
	"context"
	"embed"
	"fmt"
	"os"
	"strings"
	"time"

	o "github.com/onsi/gomega"

	e2e "github.com/openshift/ingress-node-firewall/test/e2e"
)

//go:embed testdata/*.yaml
var testdataFS embed.FS

const (
	opNamespace = "openshift-ingress-node-firewall"
)

// applyTemplateFile reads a YAML template from embedded testdata, performs parameter
// substitution, writes to a temp file, and applies via oc apply.
func applyTemplateFile(ctx context.Context, oc *e2e.OCClient, templateName string, params map[string]string) error {
	content, err := testdataFS.ReadFile("testdata/" + templateName)
	if err != nil {
		return fmt.Errorf("reading template %s: %v", templateName, err)
	}

	yaml := string(content)
	for k, v := range params {
		yaml = strings.ReplaceAll(yaml, "{{"+k+"}}", v)
	}

	tmpFile, err := os.CreateTemp("", "infw-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(yaml); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	_, err = oc.Run(ctx, "apply", "-f", tmpFile.Name())
	return err
}

// applyRawTemplateFile applies a YAML file from embedded testdata without parameter substitution.
func applyRawTemplateFile(ctx context.Context, oc *e2e.OCClient, templateName string) error {
	return applyTemplateFile(ctx, oc, templateName, nil)
}

// getWorkerNodes returns a list of schedulable worker node names.
func getWorkerNodes(ctx context.Context, oc *e2e.OCClient) []string {
	output, err := oc.Run(ctx, "get", "nodes", "-l", "node-role.kubernetes.io/worker",
		"--field-selector=spec.unschedulable!=true",
		"-o=jsonpath={.items[*].metadata.name}")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get worker nodes")
	if output == "" {
		return nil
	}
	return strings.Fields(output)
}

// getMasterNode returns the name of a master/control-plane node.
func getMasterNode(ctx context.Context, oc *e2e.OCClient) string {
	output, err := oc.Run(ctx, "get", "nodes", "-l", "node-role.kubernetes.io/master",
		"-o=jsonpath={.items[0].metadata.name}")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get master node")
	if output == "" {
		output, err = oc.Run(ctx, "get", "nodes", "-l", "node-role.kubernetes.io/control-plane",
			"-o=jsonpath={.items[0].metadata.name}")
		o.Expect(err).NotTo(o.HaveOccurred(), "failed to get control-plane node")
	}
	return output
}

// getNodeIPs returns (ipv6, ipv4) InternalIP addresses for the node.
// For single-stack clusters, the missing address family is returned as empty string.
func getNodeIPs(ctx context.Context, oc *e2e.OCClient, nodeName string) (string, string) {
	output, err := oc.Run(ctx, "get", "node", nodeName,
		`-o=jsonpath={.status.addresses[?(@.type=="InternalIP")].address}`)
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get node IPs for %s", nodeName)

	ips := strings.Fields(output)
	var ipv4, ipv6 string
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			ipv6 = ip
		} else {
			ipv4 = ip
		}
	}
	return ipv6, ipv4
}

// checkIPStackType returns "ipv4single", "ipv6single", or "dualstack".
func checkIPStackType(ctx context.Context, oc *e2e.OCClient) string {
	output, err := oc.Run(ctx, "get", "network.config/cluster",
		"-o=jsonpath={.status.clusterNetwork[*].cidr}")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get cluster network CIDRs")

	cidrs := strings.Fields(output)
	hasV4 := false
	hasV6 := false
	for _, cidr := range cidrs {
		if strings.Contains(cidr, ":") {
			hasV6 = true
		} else {
			hasV4 = true
		}
	}

	switch {
	case hasV4 && hasV6:
		return "dualstack"
	case hasV6:
		return "ipv6single"
	default:
		return "ipv4single"
	}
}

// getPrimaryNIC returns the primary network interface name on cluster nodes.
func getPrimaryNIC(ctx context.Context, oc *e2e.OCClient) string {
	workers := getWorkerNodes(ctx, oc)
	o.Expect(len(workers)).NotTo(o.BeZero(), "no worker nodes found")

	output, err := oc.Run(ctx, "debug", "node/"+workers[0], "--",
		"chroot", "/host", "bash", "-c",
		"nmcli -t -f DEVICE,TYPE connection show --active | grep ethernet | head -1 | cut -d: -f1")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get primary NIC")
	return strings.TrimSpace(output)
}

// createPodOnNode creates a hello pod on a specific node.
func createPodOnNode(ctx context.Context, oc *e2e.OCClient, name, namespace, nodeName string) {
	err := applyTemplateFile(ctx, oc, "pod-on-node.yaml", map[string]string{
		"NAME":      name,
		"NAMESPACE": namespace,
		"NODENAME":  nodeName,
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to create pod %s", name)
	waitForPodReady(ctx, oc, namespace, name)
}

// waitForPodReady polls until the pod is in Running phase.
func waitForPodReady(ctx context.Context, oc *e2e.OCClient, namespace, name string) {
	o.Eventually(func() string {
		phase, _ := oc.Run(ctx, "get", "pod", name, "-n", namespace, "-o=jsonpath={.status.phase}")
		return phase
	}, 3*time.Minute, 5*time.Second).Should(o.Equal("Running"), "pod %s/%s not ready", namespace, name)
}

// waitForPodWithLabelReady polls until at least one pod with the label is Running.
func waitForPodWithLabelReady(ctx context.Context, oc *e2e.OCClient, namespace, label string) {
	o.Eventually(func() bool {
		output, err := oc.Run(ctx, "get", "pods", "-n", namespace, "-l", label,
			"-o=jsonpath={.items[*].status.phase}")
		if err != nil {
			return false
		}
		phases := strings.Fields(output)
		for _, p := range phases {
			if p == "Running" {
				return true
			}
		}
		return false
	}, 3*time.Minute, 5*time.Second).Should(o.BeTrue(), "no pod with label %s ready in %s", label, namespace)
}

// getPodIPs returns (primaryIP, secondaryIP) for a pod.
// For single-stack clusters, secondaryIP is empty.
func getPodIPs(ctx context.Context, oc *e2e.OCClient, namespace, name string) (string, string) {
	output, err := oc.Run(ctx, "get", "pod", name, "-n", namespace,
		"-o=jsonpath={.status.podIPs[*].ip}")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get pod IPs")
	ips := strings.Fields(output)
	if len(ips) == 0 {
		return "", ""
	}
	if len(ips) == 1 {
		return ips[0], ""
	}
	return ips[0], ips[1]
}

// getPodNodeName returns the node name where the pod is running.
func getPodNodeName(ctx context.Context, oc *e2e.OCClient, namespace, name string) string {
	output, err := oc.Run(ctx, "get", "pod", name, "-n", namespace,
		"-o=jsonpath={.spec.nodeName}")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get pod node name")
	return output
}

// createNodePortService creates a NodePort service and returns the allocated port.
func createNodePortService(ctx context.Context, oc *e2e.OCClient, name, namespace, protocol, selector, ipFamilyPolicy string) string {
	_, err := oc.Run(ctx, "create", "service", "nodeport", name,
		"-n", namespace,
		"--tcp=27017:8080")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to create service %s", name)

	if protocol != "" && protocol != "TCP" {
		_, err = oc.Run(ctx, "patch", "service", name, "-n", namespace,
			"--type=json",
			`-p=[{"op":"replace","path":"/spec/ports/0/protocol","value":"`+protocol+`"}]`)
		o.Expect(err).NotTo(o.HaveOccurred())
	}

	if selector != "" {
		_, err = oc.Run(ctx, "patch", "service", name, "-n", namespace,
			"--type=json",
			`-p=[{"op":"replace","path":"/spec/selector","value":{"name":"`+selector+`"}}]`)
		o.Expect(err).NotTo(o.HaveOccurred())
	}

	if ipFamilyPolicy != "" {
		_, err = oc.Run(ctx, "patch", "service", name, "-n", namespace,
			"--type=merge",
			`-p={"spec":{"ipFamilyPolicy":"`+ipFamilyPolicy+`"}}`)
		o.Expect(err).NotTo(o.HaveOccurred())
	}

	nodePort, err := oc.Run(ctx, "get", "service", name, "-n", namespace,
		"-o=jsonpath={.spec.ports[0].nodePort}")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get nodePort")
	return nodePort
}

// createINFWConfig creates an IngressNodeFirewallConfig CR.
func createINFWConfig(ctx context.Context, oc *e2e.OCClient) {
	err := applyTemplateFile(ctx, oc, "infw-config.yaml", map[string]string{
		"NAMESPACE": opNamespace,
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to create INFW config")
	waitForINFWDaemonsReady(ctx, oc)
}

// deleteINFWConfig deletes the IngressNodeFirewallConfig CR.
func deleteINFWConfig(ctx context.Context, oc *e2e.OCClient) {
	_, err := oc.Run(ctx, "delete", "IngressNodeFirewallConfig", "ingressnodefirewallconfig",
		"-n", opNamespace, "--ignore-not-found=true")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to delete INFW config")
}

// deleteINFWCR deletes an IngressNodeFirewall CR. Pass "--all" to delete all.
func deleteINFWCR(ctx context.Context, oc *e2e.OCClient, crName string) {
	_, err := oc.Run(ctx, "delete", "IngressNodeFirewall", crName, "--ignore-not-found=true")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to delete INFW CR %s", crName)
}

// waitForINFWDaemonsReady waits until all INFW daemon pods are Running.
func waitForINFWDaemonsReady(ctx context.Context, oc *e2e.OCClient) {
	waitForPodWithLabelReady(ctx, oc, opNamespace, "app=ingress-node-firewall-daemon")
}

// restartINFWDaemons deletes all INFW daemon pods and waits for them to be recreated.
func restartINFWDaemons(ctx context.Context, oc *e2e.OCClient) {
	_, err := oc.Run(ctx, "delete", "pod", "-l=app=ingress-node-firewall-daemon",
		"-n", opNamespace)
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to restart INFW daemons")
	waitForINFWDaemonsReady(ctx, oc)
}

// getINFWDaemonForNode returns the INFW daemon pod name on a specific node.
func getINFWDaemonForNode(ctx context.Context, oc *e2e.OCClient, nodeName string) string {
	output, err := oc.Run(ctx, "get", "pods", "-n", opNamespace,
		"-l=app=ingress-node-firewall-daemon",
		"--field-selector=spec.nodeName="+nodeName,
		"-o=jsonpath={.items[0].metadata.name}")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get INFW daemon for node %s", nodeName)
	o.Expect(output).NotTo(o.BeEmpty(), "no INFW daemon found on node %s", nodeName)
	return output
}

// checkDropEvents verifies that INFW daemon event logs contain "ruleId 1 action Drop".
func checkDropEvents(ctx context.Context, oc *e2e.OCClient, daemonPod string) {
	output, err := oc.Run(ctx, "logs", "-n", opNamespace, daemonPod, "-c", "events")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get daemon event logs")
	o.Expect(output).To(o.ContainSubstring("ruleId 1 action Drop"), "expected Drop events in daemon logs")
}

// checkDropEventsWithPort verifies Drop events contain the expected destination port.
func checkDropEventsWithPort(ctx context.Context, oc *e2e.OCClient, daemonPod, dstPort string) {
	output, err := oc.Run(ctx, "logs", "-n", opNamespace, daemonPod, "-c", "events")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get daemon event logs")
	o.Expect(output).To(o.ContainSubstring("ruleId 1 action Drop"), "expected Drop events")
	o.Expect(output).To(o.ContainSubstring("dstPort "+dstPort), "expected dstPort %s in events", dstPort)
}

// curlNodePortPass verifies that a NodePort is reachable from one node to another.
func curlNodePortPass(ctx context.Context, oc *e2e.OCClient, fromNode, toNode, nodePort string) {
	_, toNodeIPv4 := getNodeIPs(ctx, oc, toNode)
	targetIP := toNodeIPv4
	if targetIP == "" {
		targetIP, _ = getNodeIPs(ctx, oc, toNode)
	}
	o.Eventually(func() error {
		_, err := debugNodeWithChroot(ctx, oc, fromNode, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
			"--connect-timeout", "5",
			fmt.Sprintf("http://%s:%s", targetIP, nodePort))
		return err
	}, 2*time.Minute, 10*time.Second).Should(o.Succeed(), "NodePort %s should be reachable from %s to %s", nodePort, fromNode, toNode)
}

// curlNodePortFail verifies that a NodePort is NOT reachable.
func curlNodePortFail(ctx context.Context, oc *e2e.OCClient, fromNode, toNode, nodePort string) {
	_, toNodeIPv4 := getNodeIPs(ctx, oc, toNode)
	targetIP := toNodeIPv4
	if targetIP == "" {
		targetIP, _ = getNodeIPs(ctx, oc, toNode)
	}
	o.Consistently(func() error {
		_, err := debugNodeWithChroot(ctx, oc, fromNode, "curl", "-s", "-o", "/dev/null",
			"--connect-timeout", "5", "--max-time", "5",
			fmt.Sprintf("http://%s:%s", targetIP, nodePort))
		return err
	}, 30*time.Second, 10*time.Second).Should(o.HaveOccurred(), "NodePort %s should NOT be reachable from %s to %s", nodePort, fromNode, toNode)
}

// curlPod2PodPass verifies that one pod can reach another on port 8080.
func curlPod2PodPass(ctx context.Context, oc *e2e.OCClient, nsSrc, podSrc, nsDst, podDst string) {
	podIP, _ := getPodIPs(ctx, oc, nsDst, podDst)
	o.Eventually(func() error {
		_, err := oc.Run(ctx, "exec", podSrc, "-n", nsSrc, "--",
			"curl", "-s", "-o", "/dev/null", "--connect-timeout", "5",
			fmt.Sprintf("http://%s:8080", podIP))
		return err
	}, 2*time.Minute, 10*time.Second).Should(o.Succeed(), "pod %s/%s should reach %s/%s", nsSrc, podSrc, nsDst, podDst)
}

// curlPod2PodFail verifies that one pod cannot reach another on port 8080.
func curlPod2PodFail(ctx context.Context, oc *e2e.OCClient, nsSrc, podSrc, nsDst, podDst string) {
	podIP, _ := getPodIPs(ctx, oc, nsDst, podDst)
	o.Consistently(func() error {
		_, err := oc.Run(ctx, "exec", podSrc, "-n", nsSrc, "--",
			"curl", "-s", "-o", "/dev/null",
			"--connect-timeout", "5", "--max-time", "5",
			fmt.Sprintf("http://%s:8080", podIP))
		return err
	}, 30*time.Second, 10*time.Second).Should(o.HaveOccurred(), "pod %s/%s should NOT reach %s/%s", nsSrc, podSrc, nsDst, podDst)
}

// debugNode runs a command on a node via oc debug.
func debugNode(ctx context.Context, oc *e2e.OCClient, nodeName string, cmd ...string) (string, error) {
	args := append([]string{"debug", "node/" + nodeName, "--"}, cmd...)
	return oc.Run(ctx, args...)
}

// debugNodeWithChroot runs a command on a node via oc debug with chroot /host.
func debugNodeWithChroot(ctx context.Context, oc *e2e.OCClient, nodeName string, cmd ...string) (string, error) {
	chrootCmd := append([]string{"chroot", "/host"}, cmd...)
	args := append([]string{"debug", "node/" + nodeName, "--"}, chrootCmd...)
	return oc.Run(ctx, args...)
}

// execInPod runs a command inside a specific pod.
func execInPod(ctx context.Context, oc *e2e.OCClient, namespace, podName, command string) (string, error) {
	return oc.Run(ctx, "exec", "-n", namespace, podName, "--", "bash", "-c", command)
}

// createNamespace creates a new namespace and returns its name.
func createNamespace(ctx context.Context, oc *e2e.OCClient, name string) {
	_, err := oc.Run(ctx, "create", "namespace", name)
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to create namespace %s", name)
}

// deleteNamespace deletes a namespace.
func deleteNamespace(ctx context.Context, oc *e2e.OCClient, name string) {
	_, _ = oc.Run(ctx, "delete", "namespace", name, "--wait=false", "--ignore-not-found=true")
}

// setNamespacePrivileged labels a namespace with privileged PSA enforcement.
func setNamespacePrivileged(ctx context.Context, oc *e2e.OCClient, namespace string) {
	_, err := oc.Run(ctx, "label", "namespace", namespace,
		"pod-security.kubernetes.io/enforce=privileged",
		"pod-security.kubernetes.io/audit=privileged",
		"pod-security.kubernetes.io/warn=privileged",
		"--overwrite")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to set namespace %s as privileged", namespace)
}

// createUDPListenerPod creates a UDP listener pod in the given namespace.
func createUDPListenerPod(ctx context.Context, oc *e2e.OCClient, namespace string) {
	err := applyTemplateFile(ctx, oc, "udp-listener.yaml", map[string]string{
		"NAMESPACE": namespace,
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to create UDP listener pod")
	waitForPodWithLabelReady(ctx, oc, namespace, "name=udp-pod")
}

// exposeUDPPod creates a NodePort service for the UDP pod and returns the NodePort.
func exposeUDPPod(ctx context.Context, oc *e2e.OCClient, podName, namespace string) string {
	_, err := oc.Run(ctx, "expose", "pod", podName, "-n", namespace,
		"--type=NodePort", "--port=8080", "--protocol=UDP")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to expose UDP pod")

	nodePort, err := oc.Run(ctx, "get", "service", podName, "-n", namespace,
		"-o=jsonpath={.spec.ports[0].nodePort}")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get UDP service nodePort")
	return nodePort
}

// prepareSCTPModule applies a MachineConfig to load the SCTP kernel module on workers.
// If the MachineConfig already exists, this is a no-op.
func prepareSCTPModule(ctx context.Context, oc *e2e.OCClient) {
	_, err := oc.Run(ctx, "get", "machineconfig", "load-sctp-module")
	if err == nil {
		return
	}
	err = applyRawTemplateFile(ctx, oc, "sctp-module.yaml")
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to apply SCTP module MachineConfig")

	o.Eventually(func() string {
		output, _ := oc.Run(ctx, "get", "mcp/worker", "-o=jsonpath={.status.conditions[?(@.type==\"Updated\")].status}")
		return output
	}, 30*time.Minute, 30*time.Second).Should(o.Equal("True"), "MachineConfigPool worker not updated after SCTP module install")
}

// createSCTPClient creates an SCTP client pod on a specific node.
func createSCTPClient(ctx context.Context, oc *e2e.OCClient, namespace, nodeName string) {
	err := applyTemplateFile(ctx, oc, "sctp-client.yaml", map[string]string{
		"NAMESPACE": namespace,
		"NODENAME":  nodeName,
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to create SCTP client pod")
	waitForPodWithLabelReady(ctx, oc, namespace, "name=sctpclient")
}

// createSCTPServer creates an SCTP server pod on a specific node.
func createSCTPServer(ctx context.Context, oc *e2e.OCClient, namespace, nodeName string) {
	err := applyTemplateFile(ctx, oc, "sctp-server.yaml", map[string]string{
		"NAMESPACE": namespace,
		"NODENAME":  nodeName,
	})
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to create SCTP server pod")
	waitForPodWithLabelReady(ctx, oc, namespace, "name=sctpserver")
}

// startSCTPServerListener starts an ncat SCTP listener in the server pod in the background.
func startSCTPServerListener(ctx context.Context, oc *e2e.OCClient, namespace, podName, port string) {
	_, _ = execInPod(ctx, oc, namespace, podName,
		"nohup /usr/bin/ncat -l "+port+" --sctp > /tmp/sctp.log 2>&1 &")
	time.Sleep(5 * time.Second)

	output, err := execInPod(ctx, oc, namespace, podName, "ps aux | grep 'ncat.*sctp' | grep -v grep || true")
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(output).To(o.ContainSubstring("ncat"),
		"SCTP server process not started")
}

// sendSCTPTraffic sends SCTP traffic from client to server. Returns error if traffic is blocked.
func sendSCTPTraffic(ctx context.Context, oc *e2e.OCClient, namespace, clientPod, serverIP, port string) error {
	cmd := fmt.Sprintf("echo 'test traffic' | timeout 10 ncat -v %s %s --sctp", serverIP, port)
	_, err := execInPod(ctx, oc, namespace, clientPod, cmd)
	return err
}

// verifySCTPServerReceived checks that the SCTP server process terminated after receiving traffic.
func verifySCTPServerReceived(ctx context.Context, oc *e2e.OCClient, namespace, podName, port string) {
	time.Sleep(5 * time.Second)
	output, err := execInPod(ctx, oc, namespace, podName, "ps aux | grep 'ncat.*sctp' | grep -v grep || true")
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(output).NotTo(o.ContainSubstring("ncat"),
		"SCTP server process should have terminated after receiving traffic")
}

// portRange returns "port-(port+5)" string for INFW rule evaluation.
func portRange(port string) string {
	var intVal int
	_, err := fmt.Sscanf(port, "%d", &intVal)
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to parse port %s", port)
	return fmt.Sprintf("%d-%d", intVal, intVal+5)
}
