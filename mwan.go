package gomwan

import (
	"net"

	"github.com/google/nftables"
)

var MWanTableName = "mwan"

type MWan struct {
	Interfaces         Interfaces
	LoadBalancingType  LoadBalancingType
	MustBeReachableIps []net.IP
	DestinationIps     []net.IP
	SourceIps          []net.IP
	Conn               *nftables.Conn
}

func NewMWan(variable *Variable) (*MWan, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, err
	}
	return &MWan{
		Interfaces:         variable.Interfaces,
		LoadBalancingType:  variable.LoadBalancingType,
		MustBeReachableIps: variable.MustBeReachableIps,
		Conn:               conn,
	}, nil
}

func (n *MWan) Close() error {
	return n.Conn.CloseLasting()
}

func (n *MWan) Clean() error {
	if err := n.DelTable(); err != nil {
		return err
	}
	n.Conn.AddTable(n.GetTable())
	n.Conn.AddChain(n.GetFilterChain())
	n.Conn.AddChain(n.GetInputPublicChain())
	n.Conn.AddChain(n.GetLocalSysChain())
	n.Conn.AddChain(n.GetOutputChain())
	n.Conn.AddChain(n.GetPostroutingChain())
	n.Conn.AddChain(n.GetSnatPostroutingChain())
	if err := n.Conn.Flush(); err != nil {
		return err
	}
	return nil
}

func (n *MWan) DelTable() error {
	if t, err := FilterTable(n.Conn, MWanTableName); err != nil {
		return err
	} else if t != nil {
		n.Conn.DelTable(t)
	}
	return nil
}

// AfreshRules will clean all rules and add new rules.
func (n *MWan) AfreshRules() error {
	if err := n.Clean(); err != nil {
		return err
	}
	if err := n.OutputRules(); err != nil {
		return err
	}
	if err := n.POSTROUTINGRules(); err != nil {
		return err
	}
	if err := n.SNatPostroutingRules(); err != nil {
		return err
	}
	if err := n.LocalSysRules(); err != nil {
		return err
	}
	if err := n.InputPublicRules(); err != nil {
		return err
	}
	if err := n.FilterRules(); err != nil {
		return err
	}
	if err := n.Conn.Flush(); err != nil {
		return err
	}
	return nil
}
