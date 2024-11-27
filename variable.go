package gomwan

import "net"

type LoadBalancingType int

const (
	// Random load balancing
	Random                           LoadBalancingType = iota // Select the egress WAN based on the random number modulo the number of WAN cards
	AccessibilityPrimaryAndSecondary                          // Determine the egress WAN network card based on target reachability
	// Destination                                               // Determine the egress WAN network card based on the destination IP address
	// DestinationSource                                         // Determine the egress WAN network card based on the destination IP address and source IP address
	// Source                                                    // Determine the egress WAN network card based on the source IP address
	Weight // Determine the egress WAN network card based on the Weight of the traffic
)

type InterfaceType int

const (
	WAN InterfaceType = iota
	LAN
)

type Interface struct {
	Name          string
	InfType       InterfaceType
	IP            net.IP
	Mask          net.IPMask
	Gateway       net.IP
	InitialWeight float32
}

type Interfaces []Interface

func (ifs Interfaces) Len() int {
	return len(ifs)
}

func (ifs Interfaces) Less(i, j int) bool {
	return ifs[i].Name < ifs[j].Name
}

func (ifs Interfaces) Swap(i, j int) {
	ifs[i], ifs[j] = ifs[j], ifs[i]
}

func (ifs Interfaces) FindWans() Interfaces {
	var wans Interfaces
	for _, inf := range ifs {
		if inf.InfType == WAN {
			wans = append(wans, inf)
		}
	}
	if len(wans) == 0 {
		return wans
	}
	return wans
}

func (ifs Interfaces) FindLans() Interfaces {
	var lans Interfaces
	for _, inf := range ifs {
		if inf.InfType == LAN {
			lans = append(lans, inf)
		}
	}
	if len(lans) == 0 {
		return lans
	}
	return lans
}

type Variable struct {
	Interfaces         Interfaces
	LoadBalancingType  LoadBalancingType
	MustBeReachableIps []net.IP
}

var (
	// BuiltInReachableIps is a list of IP addresses that must be reachable
	builtInReachableIps = []net.IP{
		net.IPv4(8, 8, 8, 8),
		net.IPv4(8, 8, 4, 4),
		net.IPv4(1, 1, 1, 1),
		net.IPv4(223, 5, 5, 5),
		net.IPv4(223, 6, 6, 6),
	}
)

func NewVariable(interfaces Interfaces, lb LoadBalancingType, must []net.IP) (*Variable, error) {
	if len(interfaces) == 0 {
		return nil, ErrEmptyInterfaces
	}
	if interfaces.FindWans().Len() == 0 {
		return nil, ErrNoWans
	}
	if err := CheckWanWeight(interfaces.FindWans()); err != nil {
		return nil, err
	}
	if lb == AccessibilityPrimaryAndSecondary && len(must) == 0 {
		return nil, ErrNoMustBeReachableIps
	}
	// if lb == Destination && len(dest) == 0 {
	// 	return nil, ErrDestinationIps
	// }
	// if lb == DestinationSource && (len(dest) == 0 || len(source) == 0) {
	// 	return nil, ErrDestinationSourceIps
	// }
	// if lb == Source && len(source) == 0 {
	// 	return nil, ErrSourceIps
	// }
	// if interfaces.FindLans().Len() == 0 {
	// 	return nil, ErrNoLans
	// }
	return &Variable{
		Interfaces:         interfaces,
		LoadBalancingType:  lb,
		MustBeReachableIps: must,
	}, nil
}
