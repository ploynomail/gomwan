package gomwan

import (
	"fmt"
	"net"
)

type LoadBalancingType int

const (
	// Random load balancing
	Random                           LoadBalancingType = iota // Select the egress WAN based on the random number modulo the number of WAN cards
	Weight                                                    // Determine the egress WAN network card based on the Weight of the traffic
	AccessibilityPrimaryAndSecondary                          // Determine the egress WAN network card based on target reachability
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
	Primary       bool
}

type Interfaces []*Interface

func (inf *Interface) String() string {
	return inf.Name + " " + inf.IP.String() + "/" + inf.Mask.String() + " " + inf.Gateway.String() + " " + fmt.Sprintf("%f", inf.InitialWeight)
}

func (ifs Interfaces) Len() int {
	return len(ifs)
}

func (ifs Interfaces) Less(i, j int) bool {
	return ifs[i].Name < ifs[j].Name
}

func (ifs Interfaces) Swap(i, j int) {
	ifs[i], ifs[j] = ifs[j], ifs[i]
}

func (ifs Interfaces) Names() []string {
	var names []string
	for _, inf := range ifs {
		names = append(names, inf.Name)
	}
	return names
}

func (ifs Interfaces) FindByName(name string) *Interface {
	for _, inf := range ifs {
		if inf.Name == name {
			return inf
		}
	}
	return nil
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
	OtherAllowNetworks []net.IPNet
	AllowProtocols     []int
}

func NewVariable(interfaces Interfaces, lb LoadBalancingType, must []net.IP, allowNet []net.IPNet, allowProto []int) (*Variable, error) {
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
		if len(interfaces.FindWans()) != 2 {
			return nil, ErrAccessibilityPrimaryAndSecondaryMustBeTwoWans
		}
		return nil, ErrNoMustBeReachableIps
	} else if lb == AccessibilityPrimaryAndSecondary && len(must) != 0 {
		findPrimary := false
		for _, ifs := range interfaces {
			if ifs.Primary && ifs.InfType == WAN {
				findPrimary = true
				ifs.InitialWeight = 1
			} else {
				ifs.InitialWeight = 0
			}
		}
		if !findPrimary {
			return nil, ErrAccessibilityPrimaryAndSecondaryMustBePrimary
		}
	}
	return &Variable{
		Interfaces:         interfaces,
		LoadBalancingType:  lb,
		MustBeReachableIps: must,
		OtherAllowNetworks: allowNet,
		AllowProtocols:     allowProto,
	}, nil
}
