package main

import (
	"net"

	"github.com/ploynomail/gomwan"
)

func main() {
	variable, err := gomwan.NewVariable(
		gomwan.Interfaces{
			{
				Name:          "eth1",
				InitialWeight: 0.2,
				InfType:       gomwan.WAN,
				IP:            net.ParseIP("192.168.22.224"),
				Mask:          net.CIDRMask(23, 32),
			},
			{
				Name:          "eth3",
				InitialWeight: 0.8,
				InfType:       gomwan.WAN,
				IP:            net.ParseIP("192.168.1.100"),
				Mask:          net.CIDRMask(24, 32),
			},
			{
				Name:    "eth5",
				InfType: gomwan.LAN,
				IP:      net.ParseIP("192.168.2.0"),
				Mask:    net.CIDRMask(24, 32),
			},
		}, gomwan.Weight, []net.IP{},
	)
	if err != nil {
		panic(err)
	}
	mwan, err := gomwan.NewMWan(variable)
	if err != nil {
		panic(err)
	}

	if err := mwan.AfreshRules(); err != nil {
		panic(err)
	}
}
