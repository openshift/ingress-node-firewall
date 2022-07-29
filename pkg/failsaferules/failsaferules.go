package failsaferules

const eBPFMaxIngressRules = 100

var MAX_INGRESS_RULES = eBPFMaxIngressRules - len(tcp) - len(udp)

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
