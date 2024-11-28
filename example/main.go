package main

import (
	"context"
	"fmt"
	"net"
	"time"

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
				Gateway:       net.ParseIP("192.168.22.1"),
				Primary:       false,
			},
			{
				Name:          "eth3",
				InitialWeight: 0.8,
				InfType:       gomwan.WAN,
				IP:            net.ParseIP("192.168.1.100"),
				Mask:          net.CIDRMask(24, 32),
				Gateway:       net.ParseIP("192.168.1.1"),
				Primary:       true,
			},
			{
				Name:    "eth5",
				InfType: gomwan.LAN,
				IP:      net.ParseIP("192.168.2.0"),
				Mask:    net.CIDRMask(24, 32),
			},
		}, gomwan.AccessibilityPrimaryAndSecondary, []net.IP{
			net.ParseIP("192.168.23.73"),
		},
	)
	if err != nil {
		fmt.Println("variable", err)
	}
	mwan, err := gomwan.NewMWan(nil)
	if err != nil {
		fmt.Println("new mwan", err)
	}
	mwan.SetVariable(variable)
	if err := mwan.TriggerChagne(); err != nil {
		fmt.Println("trigger change", err)
	}
	ctx, cancelFunc := context.WithCancel(context.Background())
	go mwan.TicketMainTain(ctx)
	time.Sleep(60 * time.Second)

	variable, err = gomwan.NewVariable(
		gomwan.Interfaces{
			{
				Name:          "eth1",
				InitialWeight: 0.2,
				InfType:       gomwan.WAN,
				IP:            net.ParseIP("192.168.22.224"),
				Mask:          net.CIDRMask(23, 32),
				Gateway:       net.ParseIP("192.168.22.1"),
				Primary:       false,
			},
			{
				Name:          "eth3",
				InitialWeight: 0.8,
				InfType:       gomwan.WAN,
				IP:            net.ParseIP("192.168.1.100"),
				Mask:          net.CIDRMask(24, 32),
				Gateway:       net.ParseIP("192.168.1.1"),
				Primary:       true,
			},
			{
				Name:    "eth5",
				InfType: gomwan.LAN,
				IP:      net.ParseIP("192.168.2.0"),
				Mask:    net.CIDRMask(24, 32),
			},
		}, gomwan.Weight, []net.IP{
			net.ParseIP("192.168.23.73"),
		},
	)
	if err != nil {
		fmt.Println("variable", err)
	}
	mwan.SetVariable(variable)
	if err := mwan.TriggerChagne(); err != nil {
		fmt.Println("trigger change", err)
	}
	time.Sleep(60 * time.Second)
	cancelFunc()
	if err := mwan.Destory(); err != nil {
		panic(err)
	}
}
