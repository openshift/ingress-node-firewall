package consts

const (
	// IngressNodeFirewallOperatorDeploymentName contains the name of the IngressNodeFirewall Operator deployment
	IngressNodeFirewallOperatorDeploymentName = "ingress-node-firewall-controller-manager"
	// IngressNodeFirewallOperatorDeploymentLabel contains the label of the IngressNodeFirewall Operator deployment
	IngressNodeFirewallOperatorDeploymentLabel = "controller-manager"
	// IngressNodeFirewallConfigCRDName contains the name of the IngressNodeFirewall Config CRD
	IngressNodeFirewallConfigCRDName = "ingressnodefirewallconfigs.ingressnodefirewall.openshift.io"
	// IngressNodeFirewallRulesCRDName contains the name of the IngressNodeFirewall Rules CRD
	IngressNodeFirewallRulesCRDName = "ingressnodefirewalls.ingressnodefirewall.openshift.io"
	// IngressNodeFirewallNodeStateCRDName contains the name of the IngressNodeFirewall NodeState CRD
	IngressNodeFirewallNodeStateCRDName = "ingressnodefirewallnodestates.ingressnodefirewall.openshift.io"
	// IngressNodeFirewallDaemonsetName contains the name of the IngressNodeFirewall daemonset
	IngressNodeFirewallDaemonsetName = "ingress-node-firewall-daemon"
	// DefaultOperatorNameSpace is the default operator namespace
	DefaultOperatorNameSpace = "ingress-node-firewall-system"
	// IngressNodeFirewallConfigCRFile configuration yaml file
	IngressNodeFirewallConfigCRFile = "ingress-node-firewall-config.yaml"
	// IngressNodeFirewallEventsLogFile eBPF events logs file
	IngressNodeFirewallEventsLogFile = "/tmp/ingress_node_firewall_events.log"
)
