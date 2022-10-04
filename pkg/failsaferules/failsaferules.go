package failsaferules

var MAX_INGRESS_RULES = 100

type TransportProtoFailSafeRule struct {
	serviceName string
	port        uint16
}

var tcp = []TransportProtoFailSafeRule{
	{
		"Kubernetes API",
		6443,
	},
	{
		"ETCD",
		2380,
	},
	{
		"ETCD",
		2379,
	},
	{
		"SSH",
		22,
	},
	{
		"Kubelet",
		10250,
	},
	{
		"kube-scheduler",
		10259,
	},
	{
		"kube-controller-manager",
		10257,
	},
}

var udp = []TransportProtoFailSafeRule{
	{
		"DHCP",
		68,
	},
}

func GetTCP() []TransportProtoFailSafeRule {
	return tcp
}

func GetUDP() []TransportProtoFailSafeRule {
	return udp
}

func (t TransportProtoFailSafeRule) GetServiceName() string {
	return t.serviceName
}

func (t TransportProtoFailSafeRule) GetPort() uint16 {
	return t.port
}
