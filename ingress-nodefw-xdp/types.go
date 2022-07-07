package nodefw

type bpfLpmIpKeySt struct {
	PrefixLen uint32
	U         struct {
		Ip4Data [4]int8
		_       [12]byte
	}
}

type eventHdrSt struct {
	IfId   uint16
	RuleId uint16
	Action int8
	Fill   int8
}

type ruleStatisticsSt struct {
	Packets int64
	Bytes   int64
}

type ruleTypeSt struct {
	RuleId   uint32
	Protocol int8
	_        [3]byte
	SrcAddrU struct {
		Ip4SrcAddr uint32
		_          [12]byte
	}
	SrcMaskU struct {
		Ip4SrcMask uint32
		_          [12]byte
	}
	DstPorts [100]uint16
	IcmpType int8
	IcmpCode int8
	Action   int8
	_        [1]byte
}

type rulesValSt struct {
	NumRules uint32
	Rules    [0]ruleTypeSt
}

