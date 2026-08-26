package ote

import (
	"context"
	"fmt"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	e2e "github.com/openshift/ingress-node-firewall/test/e2e"
)

var _ = g.Describe("[sig-network][JIRA:Networking] ingress-node-firewall", func() {
	var (
		oc     *e2e.OCClient
		ctx    context.Context
		cancel context.CancelFunc
	)

	g.BeforeEach(func() {
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Minute)
		oc = e2e.NewOCClient("")
		g.DeferCleanup(func() {
			if cancel != nil {
				cancel()
			}
		})
	})

	g.It("[OTP][LEVEL0][Serial] 61481-Ingress Node Firewall Operator Installation", func() {
		g.By("Checking Ingress Node Firewall operator installation")

		output, err := oc.Get(ctx, "namespace", opNamespace, "")
		o.Expect(err).NotTo(o.HaveOccurred(), "Operator namespace should exist")
		o.Expect(output).To(o.ContainSubstring(opNamespace))

		g.By("Verifying CRDs are installed")
		crdOutput, err := oc.Run(ctx, "get", "crd")
		o.Expect(err).NotTo(o.HaveOccurred())

		expectedCRDs := []string{
			"ingressnodefirewallconfigs.ingressnodefirewall.openshift.io",
			"ingressnodefirewallnodestates.ingressnodefirewall.openshift.io",
			"ingressnodefirewalls.ingressnodefirewall.openshift.io",
		}
		for _, crd := range expectedCRDs {
			o.Expect(crdOutput).To(o.ContainSubstring(crd), "CRD %s should be installed", crd)
		}

		g.By("Verifying operator deployment is running")
		deploymentOutput, err := oc.Run(ctx, "get", "deployment", "-n", opNamespace,
			"-o=jsonpath={.items[*].metadata.name}")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(deploymentOutput).NotTo(o.BeEmpty())

		_, err = oc.Run(ctx, "wait", "deployment/ingress-node-firewall-controller-manager",
			"-n", opNamespace, "--for=condition=Available", "--timeout=5m")
		o.Expect(err).NotTo(o.HaveOccurred(), "Operator deployment should be available")
	})

	g.It("[OTP][WRS][V-BR.53][Serial] 54714-Check Ingress Firewall Allow/Deny functionality for TCP via Nodeport svc",
		g.Label("Disruptive"), g.Label("Baremetal"), func() {

			workers := getWorkerNodes(ctx, oc)
			o.Expect(len(workers)).To(o.BeNumerically(">=", 2), "need at least 2 worker nodes")

			ipStackType := checkIPStackType(ctx, oc)
			o.Expect(ipStackType).NotTo(o.BeEmpty())

			ns := fmt.Sprintf("e2e-infw-54714-%d", time.Now().UnixNano()%10000)
			createNamespace(ctx, oc, ns)
			g.DeferCleanup(func() { deleteNamespace(ctx, oc, ns) })

			g.By("Create hello pod and TCP NodePort service")
			createPodOnNode(ctx, oc, "hello-pod1", ns, workers[0])

			var ipFamilyPolicy string
			if ipStackType == "dualstack" {
				ipFamilyPolicy = "RequireDualStack"
			} else {
				ipFamilyPolicy = "SingleStack"
			}
			nodePort := createNodePortService(ctx, oc, "test-service", ns, "TCP", "hello-pod", ipFamilyPolicy)
			nodePortRange := portRange(nodePort)

			g.By("Verify NodePort is reachable before applying firewall rule")
			curlNodePortPass(ctx, oc, workers[1], workers[0], nodePort)

			g.By("Create INFW config and daemons")
			createINFWConfig(ctx, oc)
			g.DeferCleanup(func() { deleteINFWConfig(ctx, oc) })

			primaryInf := getPrimaryNIC(ctx, oc)
			nodeIPv6, nodeIPv4 := getNodeIPs(ctx, oc, workers[1])

			g.By("Create INFW CR to block TCP traffic")
			if ipStackType == "dualstack" {
				err := applyTemplateFile(ctx, oc, "infw-multiple-cidr.yaml", map[string]string{
					"NAME":          "infw-block-nport-tcp",
					"PRIMARY_INF":   primaryInf,
					"SRC_CIDR1":     nodeIPv6 + "/128",
					"SRC_CIDR2":     nodeIPv4 + "/32",
					"PROTOCOL_1":    "TCP",
					"PROTOCOLTYPE1": "tcp",
					"RANGE_1":       nodePortRange,
					"ACTION_1":      "Deny",
					"PROTOCOL_2":    "TCP",
					"PROTOCOLTYPE2": "tcp",
					"RANGE_2":       nodePortRange,
					"ACTION_2":      "Allow",
				})
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				srcCIDR := nodeIPv4 + "/32"
				if ipStackType == "ipv6single" {
					srcCIDR = nodeIPv6 + "/128"
				}
				err := applyTemplateFile(ctx, oc, "infw.yaml", map[string]string{
					"NAME":          "infw-block-nport-tcp",
					"PRIMARY_INF":   primaryInf,
					"SRC_CIDR1":     srcCIDR,
					"PROTOCOL_1":    "TCP",
					"PROTOCOLTYPE1": "tcp",
					"RANGE_1":       nodePortRange,
					"ACTION_1":      "Deny",
					"PROTOCOL_2":    "TCP",
					"PROTOCOLTYPE2": "tcp",
					"ACTION_2":      "Allow",
				})
				o.Expect(err).NotTo(o.HaveOccurred())
			}
			g.DeferCleanup(func() { deleteINFWCR(ctx, oc, "--all") })

			g.By("Verify NodePort is blocked")
			curlNodePortFail(ctx, oc, workers[1], workers[0], nodePort)

			g.By("Verify Drop events logged")
			infwDaemon := getINFWDaemonForNode(ctx, oc, workers[0])
			checkDropEvents(ctx, oc, infwDaemon)

			g.By("Remove rules, restart daemons, apply Allow rule")
			deleteINFWCR(ctx, oc, "--all")
			restartINFWDaemons(ctx, oc)

			if ipStackType == "dualstack" {
				err := applyTemplateFile(ctx, oc, "infw-multiple-cidr.yaml", map[string]string{
					"NAME":          "infw-block-nport-tcp",
					"PRIMARY_INF":   primaryInf,
					"SRC_CIDR1":     nodeIPv6 + "/128",
					"SRC_CIDR2":     nodeIPv4 + "/32",
					"PROTOCOL_1":    "TCP",
					"PROTOCOLTYPE1": "tcp",
					"RANGE_1":       nodePortRange,
					"ACTION_1":      "Allow",
					"PROTOCOL_2":    "TCP",
					"PROTOCOLTYPE2": "tcp",
					"RANGE_2":       nodePortRange,
					"ACTION_2":      "Allow",
				})
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				srcCIDR := nodeIPv4 + "/32"
				if ipStackType == "ipv6single" {
					srcCIDR = nodeIPv6 + "/128"
				}
				err := applyTemplateFile(ctx, oc, "infw.yaml", map[string]string{
					"NAME":          "infw-block-nport-tcp",
					"PRIMARY_INF":   primaryInf,
					"SRC_CIDR1":     srcCIDR,
					"PROTOCOL_1":    "TCP",
					"PROTOCOLTYPE1": "tcp",
					"RANGE_1":       nodePortRange,
					"ACTION_1":      "Allow",
					"PROTOCOL_2":    "TCP",
					"PROTOCOLTYPE2": "tcp",
					"ACTION_2":      "Allow",
				})
				o.Expect(err).NotTo(o.HaveOccurred())
			}

			g.By("Verify NodePort is reachable again")
			curlNodePortPass(ctx, oc, workers[1], workers[0], nodePort)

			g.By("Delete INFW deployment and daemonset, verify traffic still works")
			_, err := oc.Run(ctx, "delete", "deployment", "ingress-node-firewall-controller-manager",
				"-n", opNamespace)
			o.Expect(err).NotTo(o.HaveOccurred())
			_, err = oc.Run(ctx, "delete", "ds", "ingress-node-firewall-daemon",
				"-n", opNamespace)
			o.Expect(err).NotTo(o.HaveOccurred())

			curlNodePortPass(ctx, oc, workers[1], workers[0], nodePort)
		})

	g.It("[OTP][WRS][V-BR.53][Serial] 54992-Check Ingress Firewall Allow/Deny functionality for UDP via Nodeport svc",
		g.Label("Baremetal"), func() {

			workers := getWorkerNodes(ctx, oc)
			o.Expect(len(workers)).To(o.BeNumerically(">=", 2), "need at least 2 worker nodes")

			ipStackType := checkIPStackType(ctx, oc)
			o.Expect(ipStackType).NotTo(o.BeEmpty())

			ns := fmt.Sprintf("e2e-infw-54992-%d", time.Now().UnixNano()%10000)
			createNamespace(ctx, oc, ns)
			g.DeferCleanup(func() { deleteNamespace(ctx, oc, ns) })

			g.By("Create UDP listener pod and expose as NodePort")
			createUDPListenerPod(ctx, oc, ns)
			udpPodName := "udp-pod"
			nodePort := exposeUDPPod(ctx, oc, udpPodName, ns)
			nodePortRange := portRange(nodePort)

			podNodeName := getPodNodeName(ctx, oc, ns, udpPodName)
			masterNode := getMasterNode(ctx, oc)
			_, podNodeIPv4 := getNodeIPs(ctx, oc, podNodeName)

			g.By("Create INFW config")
			createINFWConfig(ctx, oc)
			g.DeferCleanup(func() { deleteINFWConfig(ctx, oc) })

			primaryInf := getPrimaryNIC(ctx, oc)
			masterIPv6, masterIPv4 := getNodeIPs(ctx, oc, masterNode)

			g.By("Create INFW CR to block UDP traffic")
			if ipStackType == "dualstack" {
				err := applyTemplateFile(ctx, oc, "infw-multiple-cidr.yaml", map[string]string{
					"NAME":          "infw-block-nport-udp",
					"PRIMARY_INF":   primaryInf,
					"SRC_CIDR1":     masterIPv6 + "/128",
					"SRC_CIDR2":     masterIPv4 + "/32",
					"PROTOCOL_1":    "UDP",
					"PROTOCOLTYPE1": "udp",
					"RANGE_1":       nodePortRange,
					"ACTION_1":      "Deny",
					"PROTOCOL_2":    "UDP",
					"PROTOCOLTYPE2": "udp",
					"RANGE_2":       nodePortRange,
					"ACTION_2":      "Allow",
				})
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				srcCIDR := masterIPv4 + "/32"
				if ipStackType == "ipv6single" {
					srcCIDR = masterIPv6 + "/128"
				}
				err := applyTemplateFile(ctx, oc, "infw.yaml", map[string]string{
					"NAME":          "infw-block-nport-udp",
					"PRIMARY_INF":   primaryInf,
					"SRC_CIDR1":     srcCIDR,
					"PROTOCOL_1":    "UDP",
					"PROTOCOLTYPE1": "udp",
					"RANGE_1":       nodePortRange,
					"ACTION_1":      "Deny",
					"PROTOCOL_2":    "UDP",
					"PROTOCOLTYPE2": "udp",
					"ACTION_2":      "Allow",
				})
				o.Expect(err).NotTo(o.HaveOccurred())
			}
			g.DeferCleanup(func() { deleteINFWCR(ctx, oc, "--all") })

			g.By("Send UDP packet from master to pod node - expect Deny")
			cmd := fmt.Sprintf("echo -n hello >/dev/udp/%s/%s", podNodeIPv4, nodePort)
			debugNode(ctx, oc, masterNode, "bash", "-c", cmd)

			g.By("Verify Drop events")
			infwDaemon := getINFWDaemonForNode(ctx, oc, podNodeName)
			checkDropEvents(ctx, oc, infwDaemon)

			g.By("Remove rules, restart daemons, apply Allow rule")
			deleteINFWCR(ctx, oc, "--all")
			restartINFWDaemons(ctx, oc)

			if ipStackType == "dualstack" {
				err := applyTemplateFile(ctx, oc, "infw-multiple-cidr.yaml", map[string]string{
					"NAME":          "infw-block-nport-udp",
					"PRIMARY_INF":   primaryInf,
					"SRC_CIDR1":     masterIPv6 + "/128",
					"SRC_CIDR2":     masterIPv4 + "/32",
					"PROTOCOL_1":    "UDP",
					"PROTOCOLTYPE1": "udp",
					"RANGE_1":       nodePortRange,
					"ACTION_1":      "Allow",
					"PROTOCOL_2":    "UDP",
					"PROTOCOLTYPE2": "udp",
					"RANGE_2":       nodePortRange,
					"ACTION_2":      "Allow",
				})
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				srcCIDR := masterIPv4 + "/32"
				if ipStackType == "ipv6single" {
					srcCIDR = masterIPv6 + "/128"
				}
				err := applyTemplateFile(ctx, oc, "infw.yaml", map[string]string{
					"NAME":          "infw-block-nport-udp",
					"PRIMARY_INF":   primaryInf,
					"SRC_CIDR1":     srcCIDR,
					"PROTOCOL_1":    "UDP",
					"PROTOCOLTYPE1": "udp",
					"RANGE_1":       nodePortRange,
					"ACTION_1":      "Allow",
					"PROTOCOL_2":    "UDP",
					"PROTOCOLTYPE2": "udp",
					"ACTION_2":      "Allow",
				})
				o.Expect(err).NotTo(o.HaveOccurred())
			}

			g.By("Send UDP packet again - expect Allow")
			cmd = fmt.Sprintf("echo -n hello >/dev/udp/%s/%s", podNodeIPv4, nodePort)
			debugNode(ctx, oc, masterNode, "bash", "-c", cmd)

			infwDaemon = getINFWDaemonForNode(ctx, oc, podNodeName)
			_, err := oc.Run(ctx, "logs", "-n", opNamespace, infwDaemon, "-c", "events")
			o.Expect(err).NotTo(o.HaveOccurred())
		})

	g.It("[OTP][WRS][V-BR.53][Serial] 55411-Check Ingress Firewall Allow/Deny functionality for ICMP", func() {

			ipStackType := checkIPStackType(ctx, oc)
			o.Expect(ipStackType).NotTo(o.BeEmpty())
			if ipStackType == "dualstack" {
				g.Skip("This case requires single stack cluster")
			}

			workers := getWorkerNodes(ctx, oc)
			o.Expect(len(workers)).To(o.BeNumerically(">=", 2), "need at least 2 worker nodes")

			ns1 := fmt.Sprintf("e2e-infw-55411-a-%d", time.Now().UnixNano()%10000)
			createNamespace(ctx, oc, ns1)
			g.DeferCleanup(func() { deleteNamespace(ctx, oc, ns1) })

			ns2 := fmt.Sprintf("e2e-infw-55411-b-%d", time.Now().UnixNano()%10000)
			createNamespace(ctx, oc, ns2)
			g.DeferCleanup(func() { deleteNamespace(ctx, oc, ns2) })

			g.By("Create hello pods on different nodes in different namespaces")
			createPodOnNode(ctx, oc, "hello-pod", ns1, workers[0])
			createPodOnNode(ctx, oc, "hello-pod", ns2, workers[1])

			hellopodIPns1, _ := getPodIPs(ctx, oc, ns1, "hello-pod")
			hellopodIPns2, _ := getPodIPs(ctx, oc, ns2, "hello-pod")

			primaryInf := "genev_sys_6081"

			g.By("Create INFW config")
			createINFWConfig(ctx, oc)
			g.DeferCleanup(func() { deleteINFWConfig(ctx, oc) })

			g.By("Create INFW CR to block ICMP")
			var templateFile, crName string
			srcCIDR := hellopodIPns1
			if ipStackType == "ipv6single" {
				templateFile = "infw-icmpv6.yaml"
				crName = "infw-block-icmpv6"
				srcCIDR += "/128"
			} else {
				templateFile = "infw-icmp.yaml"
				crName = "infw-block-icmp"
				srcCIDR += "/32"
			}
			err := applyTemplateFile(ctx, oc, templateFile, map[string]string{
				"NAME":        crName,
				"PRIMARY_INF": primaryInf,
				"SRC_CIDR":    srcCIDR,
				"ACTION_1":    "Deny",
				"ACTION_2":    "Allow",
			})
			o.Expect(err).NotTo(o.HaveOccurred())
			g.DeferCleanup(func() { deleteINFWCR(ctx, oc, crName) })

			g.By("Verify ping fails with 100% packet loss")
			var pingCmd string
			if ipStackType == "ipv6single" {
				pingCmd = "ping6 -c4 " + hellopodIPns2 + " 2>&1 || true"
			} else {
				pingCmd = "ping -c4 " + hellopodIPns2 + " 2>&1 || true"
			}
			output, _ := oc.Run(ctx, "exec", "-n", ns1, "hello-pod", "--", "/bin/sh", "-c", pingCmd)
			o.Expect(output).To(o.ContainSubstring("100% packet loss"))

			g.By("Verify Drop events")
			infwDaemon := getINFWDaemonForNode(ctx, oc, workers[1])
			checkDropEvents(ctx, oc, infwDaemon)

			g.By("Remove rules, create INFW CR with Allow action")
			deleteINFWCR(ctx, oc, "--all")

			err = applyTemplateFile(ctx, oc, templateFile, map[string]string{
				"NAME":        crName,
				"PRIMARY_INF": primaryInf,
				"SRC_CIDR":    srcCIDR,
				"ACTION_1":    "Allow",
				"ACTION_2":    "Allow",
			})
			o.Expect(err).NotTo(o.HaveOccurred())

			g.By("Verify ping succeeds")
			output, _ = oc.Run(ctx, "exec", "-n", ns1, "hello-pod", "--", "/bin/sh", "-c", pingCmd)
			o.Expect(output).NotTo(o.ContainSubstring("100% packet loss"))
		})

	g.It("[OTP][WRS][V-BR.53][Serial] 55410-Check Ingress Firewall Allow/Deny functionality for SCTP", func() {

			workers := getWorkerNodes(ctx, oc)
			o.Expect(len(workers)).To(o.BeNumerically(">=", 2), "need at least 2 worker nodes")

			g.By("Install SCTP kernel module")
			prepareSCTPModule(ctx, oc)

			ipStackType := checkIPStackType(ctx, oc)
			o.Expect(ipStackType).NotTo(o.BeEmpty())

			ns := fmt.Sprintf("e2e-infw-55410-%d", time.Now().UnixNano()%10000)
			createNamespace(ctx, oc, ns)
			g.DeferCleanup(func() { deleteNamespace(ctx, oc, ns) })
			setNamespacePrivileged(ctx, oc, ns)

			g.By("Create SCTP client and server pods on different nodes")
			createSCTPClient(ctx, oc, ns, workers[0])
			createSCTPServer(ctx, oc, ns, workers[1])

			nodePort := "30102"
			nodePortRange := portRange(nodePort)

			g.By("Create INFW config")
			createINFWConfig(ctx, oc)
			g.DeferCleanup(func() { deleteINFWConfig(ctx, oc) })

			primaryInf := "genev_sys_6081"

			sctpClientIP1, sctpClientIP2 := getPodIPs(ctx, oc, ns, "sctpclient")
			sctpServerIP1, _ := getPodIPs(ctx, oc, ns, "sctpserver")

			g.By("Create INFW CR with Allow action for SCTP")
			if ipStackType == "dualstack" {
				err := applyTemplateFile(ctx, oc, "infw-multiple-cidr.yaml", map[string]string{
					"NAME":          "infw-block-sctp",
					"PRIMARY_INF":   primaryInf,
					"SRC_CIDR1":     sctpClientIP2 + "/32",
					"SRC_CIDR2":     sctpClientIP1 + "/128",
					"PROTOCOL_1":    "SCTP",
					"PROTOCOLTYPE1": "sctp",
					"RANGE_1":       nodePortRange,
					"ACTION_1":      "Allow",
					"PROTOCOL_2":    "SCTP",
					"PROTOCOLTYPE2": "sctp",
					"RANGE_2":       nodePortRange,
					"ACTION_2":      "Allow",
				})
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				srcCIDR := sctpClientIP1 + "/32"
				if ipStackType == "ipv6single" {
					srcCIDR = sctpClientIP1 + "/128"
				}
				err := applyTemplateFile(ctx, oc, "infw.yaml", map[string]string{
					"NAME":          "infw-block-sctp",
					"PRIMARY_INF":   primaryInf,
					"SRC_CIDR1":     srcCIDR,
					"PROTOCOL_1":    "SCTP",
					"PROTOCOLTYPE1": "sctp",
					"RANGE_1":       nodePortRange,
					"ACTION_1":      "Allow",
					"PROTOCOL_2":    "SCTP",
					"PROTOCOLTYPE2": "sctp",
					"ACTION_2":      "Allow",
				})
				o.Expect(err).NotTo(o.HaveOccurred())
			}
			g.DeferCleanup(func() { deleteINFWCR(ctx, oc, "--all") })

			g.By("Start SCTP server and send traffic - expect Allow")
			startSCTPServerListener(ctx, oc, ns, "sctpserver", "30102")
			err := sendSCTPTraffic(ctx, oc, ns, "sctpclient", sctpServerIP1, "30102")
			o.Expect(err).NotTo(o.HaveOccurred(), "SCTP traffic should pass with Allow rule")
			verifySCTPServerReceived(ctx, oc, ns, "sctpserver", "30102")

			g.By("Remove rules, restart daemons, apply Deny rule")
			deleteINFWCR(ctx, oc, "--all")
			restartINFWDaemons(ctx, oc)

			if ipStackType == "dualstack" {
				err = applyTemplateFile(ctx, oc, "infw-multiple-cidr.yaml", map[string]string{
					"NAME":          "infw-block-sctp",
					"PRIMARY_INF":   primaryInf,
					"SRC_CIDR1":     sctpClientIP2 + "/32",
					"SRC_CIDR2":     sctpClientIP1 + "/128",
					"PROTOCOL_1":    "SCTP",
					"PROTOCOLTYPE1": "sctp",
					"RANGE_1":       nodePortRange,
					"ACTION_1":      "Deny",
					"PROTOCOL_2":    "SCTP",
					"PROTOCOLTYPE2": "sctp",
					"RANGE_2":       nodePortRange,
					"ACTION_2":      "Allow",
				})
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				srcCIDR := sctpClientIP1 + "/32"
				if ipStackType == "ipv6single" {
					srcCIDR = sctpClientIP1 + "/128"
				}
				err = applyTemplateFile(ctx, oc, "infw.yaml", map[string]string{
					"NAME":          "infw-block-sctp",
					"PRIMARY_INF":   primaryInf,
					"SRC_CIDR1":     srcCIDR,
					"PROTOCOL_1":    "SCTP",
					"PROTOCOLTYPE1": "sctp",
					"RANGE_1":       nodePortRange,
					"ACTION_1":      "Deny",
					"PROTOCOL_2":    "SCTP",
					"PROTOCOLTYPE2": "sctp",
					"ACTION_2":      "Allow",
				})
				o.Expect(err).NotTo(o.HaveOccurred())
			}

			g.By("Start SCTP server and send traffic - expect Deny")
			startSCTPServerListener(ctx, oc, ns, "sctpserver", "30102")
			err = sendSCTPTraffic(ctx, oc, ns, "sctpclient", sctpServerIP1, "30102")
			o.Expect(err).To(o.HaveOccurred(), "SCTP traffic should be denied")

			g.By("Verify Drop events")
			podNodeName := getPodNodeName(ctx, oc, ns, "sctpserver")
			infwDaemon := getINFWDaemonForNode(ctx, oc, podNodeName)
			checkDropEvents(ctx, oc, infwDaemon)
		})

	g.It("[OTP][Serial] 54973-Make sure events and metrics are logged for ingress-node-firewall-daemon", func() {

			workers := getWorkerNodes(ctx, oc)
			o.Expect(len(workers)).NotTo(o.BeZero(), "need at least 1 worker node")

			g.By("Create INFW config")
			createINFWConfig(ctx, oc)
			g.DeferCleanup(func() { deleteINFWConfig(ctx, oc) })

			g.By("Check metrics endpoint on daemon pod")
			infwDaemon := getINFWDaemonForNode(ctx, oc, workers[0])
			output, err := execInPod(ctx, oc, opNamespace, infwDaemon, "curl -s http://127.0.0.1:39401/metrics")
			o.Expect(err).NotTo(o.HaveOccurred(), "failed to query metrics endpoint")
			o.Expect(output).To(o.ContainSubstring("ingressnodefirewall"), "metrics should contain ingressnodefirewall")
		})

	g.It("[OTP][Serial] 55414-Check multiple CIDRs with multiple rules functionality with Ingress Firewall Node Operator", func() {

			ipStackType := checkIPStackType(ctx, oc)
			o.Expect(ipStackType).NotTo(o.BeEmpty())
			if ipStackType == "dualstack" {
				g.Skip("This case requires single stack cluster")
			}

			workers := getWorkerNodes(ctx, oc)
			o.Expect(len(workers)).To(o.BeNumerically(">=", 2), "need at least 2 worker nodes")

			g.By("Install SCTP kernel module")
			prepareSCTPModule(ctx, oc)

			ns := fmt.Sprintf("e2e-infw-55414-%d", time.Now().UnixNano()%10000)
			createNamespace(ctx, oc, ns)
			g.DeferCleanup(func() { deleteNamespace(ctx, oc, ns) })
			setNamespacePrivileged(ctx, oc, ns)

			g.By("Create SCTP client and server pods")
			createSCTPClient(ctx, oc, ns, workers[0])
			createSCTPServer(ctx, oc, ns, workers[1])

			g.By("Create hello pods for TCP traffic testing")
			createPodOnNode(ctx, oc, "hello-pod-client", ns, workers[0])
			createPodOnNode(ctx, oc, "hello-pod-server", ns, workers[1])

			nodePortSCTP := "30102"
			portRangeSCTP := portRange(nodePortSCTP)
			portRangeTCP := "8080-8081"

			g.By("Create INFW config")
			createINFWConfig(ctx, oc)
			g.DeferCleanup(func() { deleteINFWConfig(ctx, oc) })

			primaryInf := "genev_sys_6081"
			sctpClientIP, _ := getPodIPs(ctx, oc, ns, "sctpclient")
			sctpServerIP, _ := getPodIPs(ctx, oc, ns, "sctpserver")
			helloPodClientIP, _ := getPodIPs(ctx, oc, ns, "hello-pod-client")

			g.By("Create INFW CR with Allow for both SCTP and TCP")
			srcCIDR1 := sctpClientIP + "/32"
			srcCIDR2 := helloPodClientIP + "/32"
			if ipStackType == "ipv6single" {
				srcCIDR1 = sctpClientIP + "/128"
				srcCIDR2 = helloPodClientIP + "/128"
			}
			err := applyTemplateFile(ctx, oc, "infw-multiple-cidr.yaml", map[string]string{
				"NAME":          "infw-allow-sctp-tcp",
				"PRIMARY_INF":   primaryInf,
				"SRC_CIDR1":     srcCIDR1,
				"SRC_CIDR2":     srcCIDR2,
				"PROTOCOL_1":    "SCTP",
				"PROTOCOLTYPE1": "sctp",
				"RANGE_1":       portRangeSCTP,
				"ACTION_1":      "Allow",
				"PROTOCOL_2":    "TCP",
				"PROTOCOLTYPE2": "tcp",
				"RANGE_2":       portRangeTCP,
				"ACTION_2":      "Allow",
			})
			o.Expect(err).NotTo(o.HaveOccurred())
			g.DeferCleanup(func() { deleteINFWCR(ctx, oc, "--all") })

			g.By("Verify SCTP traffic passes with Allow")
			startSCTPServerListener(ctx, oc, ns, "sctpserver", "30102")
			err = sendSCTPTraffic(ctx, oc, ns, "sctpclient", sctpServerIP, "30102")
			o.Expect(err).NotTo(o.HaveOccurred(), "SCTP traffic should pass")

			g.By("Verify TCP traffic passes with Allow")
			curlPod2PodPass(ctx, oc, ns, "hello-pod-client", ns, "hello-pod-server")

			g.By("Delete Allow CR, create Deny CR")
			deleteINFWCR(ctx, oc, "--all")

			err = applyTemplateFile(ctx, oc, "infw-multiple-cidr.yaml", map[string]string{
				"NAME":          "infw-block-sctp-tcp",
				"PRIMARY_INF":   primaryInf,
				"SRC_CIDR1":     srcCIDR1,
				"SRC_CIDR2":     srcCIDR2,
				"PROTOCOL_1":    "SCTP",
				"PROTOCOLTYPE1": "sctp",
				"RANGE_1":       portRangeSCTP,
				"ACTION_1":      "Deny",
				"PROTOCOL_2":    "TCP",
				"PROTOCOLTYPE2": "tcp",
				"RANGE_2":       portRangeTCP,
				"ACTION_2":      "Deny",
			})
			o.Expect(err).NotTo(o.HaveOccurred())

			g.By("Verify SCTP traffic is blocked")
			startSCTPServerListener(ctx, oc, ns, "sctpserver", "30102")
			err = sendSCTPTraffic(ctx, oc, ns, "sctpclient", sctpServerIP, "30102")
			o.Expect(err).To(o.HaveOccurred(), "SCTP traffic should be denied")

			g.By("Verify TCP traffic is blocked")
			curlPod2PodFail(ctx, oc, ns, "hello-pod-client", ns, "hello-pod-server")
		})

	g.It("[OTP][Serial] 73844-Check Ingress Node Firewall functionality for blocking SSH traffic", func() {

			ipStackType := checkIPStackType(ctx, oc)
			o.Expect(ipStackType).NotTo(o.BeEmpty())
			if ipStackType == "dualstack" {
				g.Skip("This case requires single stack cluster IPv4/IPv6")
			}

			workers := getWorkerNodes(ctx, oc)
			o.Expect(len(workers)).To(o.BeNumerically(">=", 2), "need at least 2 worker nodes")

			g.By("Create INFW config")
			createINFWConfig(ctx, oc)
			g.DeferCleanup(func() { deleteINFWConfig(ctx, oc) })

			primaryInf := getPrimaryNIC(ctx, oc)

			g.By("Create INFW CR blocking SSH port 22")
			srcCIDR := "0.0.0.0/0"
			if ipStackType == "ipv6single" {
				srcCIDR = "::/0"
			}
			err := applyTemplateFile(ctx, oc, "infw.yaml", map[string]string{
				"NAME":          "infw-block-ssh",
				"PRIMARY_INF":   primaryInf,
				"SRC_CIDR1":     srcCIDR,
				"PROTOCOL_1":    "TCP",
				"PROTOCOLTYPE1": "tcp",
				"RANGE_1":       "22",
				"ACTION_1":      "Deny",
				"PROTOCOL_2":    "TCP",
				"PROTOCOLTYPE2": "tcp",
				"ACTION_2":      "Allow",
			})
			o.Expect(err).NotTo(o.HaveOccurred())
			g.DeferCleanup(func() { deleteINFWCR(ctx, oc, "infw-block-ssh") })

			g.By("Attempt SSH from master to worker - expect timeout")
			masterNode := getMasterNode(ctx, oc)
			sshCmd := "ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no core@" + workers[0] + " 2>&1 || true"
			sshOutput, _ := debugNodeWithChroot(ctx, oc, masterNode, "/bin/bash", "-c", sshCmd)
			o.Expect(strings.Contains(sshOutput, "Connection timed out")).Should(o.BeTrue(),
				"SSH should timeout due to firewall rule")

			g.By("Verify Drop events with dstPort 22")
			infwDaemon := getINFWDaemonForNode(ctx, oc, workers[0])
			checkDropEventsWithPort(ctx, oc, infwDaemon, "22")
		})
})
