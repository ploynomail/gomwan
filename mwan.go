package gomwan

import (
	"context"
	"log"
	"net"
	"sort"
	"time"

	"github.com/google/nftables"
	"github.com/ti-mo/conntrack"
)

var MWanTableName = "mwan"

type MWan struct {
	Interfaces         Interfaces
	LoadBalancingType  LoadBalancingType
	MustBeReachableIps []net.IP
	DestinationIps     []net.IP
	SourceIps          []net.IP
	OtherAllowNetworks []net.IPNet
	AllowProtocols     []int
	Conn               *nftables.Conn
}

func NewMWan(conn *nftables.Conn) (*MWan, error) {
	var err error
	if conn == nil {
		conn, err = nftables.New()
		if err != nil {
			return nil, err
		}
	}
	return &MWan{
		Conn: conn,
	}, nil
}

func (n *MWan) SetVariable(variable *Variable) {
	n.Interfaces = variable.Interfaces
	n.LoadBalancingType = variable.LoadBalancingType
	n.MustBeReachableIps = variable.MustBeReachableIps
	n.OtherAllowNetworks = variable.OtherAllowNetworks
	n.AllowProtocols = variable.AllowProtocols

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
func (n *MWan) AfreshRules() (err error) {
	defer func() {
		if err != nil {
			n.Clean()
		}
	}()

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

func (n *MWan) AfreshIpRule() (err error) {
	defer func() {
		if err != nil {
			n.Clean()
		}
	}()
	initial := 100
	wans := n.Interfaces.FindWans()
	sort.Sort(wans)
	for i := range wans {
		if err := delConfictRule(uint32(initial+i), initial+i); err != nil {
			return err
		}
		if err := addRule(uint32(initial+i), initial+i); err != nil {
			return err
		}
	}
	return nil
}

func (n *MWan) DestoryIpRule() error {
	initial := 100
	wans := n.Interfaces.FindWans()
	for i := range wans {
		if err := delRule(uint32(initial+i), initial+i); err != nil {
			return err
		}
	}
	return nil
}

func (n *MWan) MaintainIpRoute() error {
	initial := 100
	wans := n.Interfaces.FindWans()
	for i := range wans {
		if r, err := findDefaultRouteInTable(initial + i); err != nil || r == nil {
			if err := addDefaultRouteInTable(initial+i, wans[i].Name, wans[i].Gateway.String()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n *MWan) DestoryIpRoute() error {
	initial := 100
	wans := n.Interfaces.FindWans()
	for i := range wans {
		if err := delDefaultRouteInTable(initial + i); err != nil {
			return err
		}
	}
	return nil
}

func (n *MWan) TriggerChagne() (err error) {
	defer func() {
		if err != nil {
			n.Clean()
			n.Destory()
		}
		n.Close()
	}()
	if err := n.AfreshIpRule(); err != nil {
		return err
	}
	n.MaintainIpRoute()
	if err := n.AfreshRules(); err != nil {
		return err
	}

	return nil
}

func (n *MWan) Destory() (err error) {
	defer func() {
		if err != nil {
			n.Clean()
		}
		n.Close()
	}()
	if err := n.DestoryIpRoute(); err != nil {
		return err
	}
	if err := n.DestoryIpRule(); err != nil {
		return err
	}
	if err := n.Clean(); err != nil {
		return err
	}
	return nil
}

func (n *MWan) TicketMainTain(ctx context.Context) {
	timer := time.NewTicker(1 * time.Second)
	primaryFail := false
	for {
		select {
		case <-timer.C:
			n.MaintainIpRoute()
			if n.LoadBalancingType == AccessibilityPrimaryAndSecondary {
				reachabilityCheck := NewReachabilityCheck(n.Interfaces.FindWans().Names(), n.MustBeReachableIps)
				weightChange := false
				results := reachabilityCheck.IsReachable()
				for _, result := range results {
					ifs := n.Interfaces.FindByName(result.InfName)
					if ifs.Primary && result.MustBeReachableLost > 0 {
						ifs.InitialWeight = 0
						primaryFail = true
						weightChange = true
					} else if ifs.Primary && result.MustBeReachableLost == 0 {
						ifs.InitialWeight = 1
						primaryFail = false
						weightChange = true
					}
					if !ifs.Primary && result.MustBeReachableLost == 0 && primaryFail {
						ifs.InitialWeight = 1
					} else if !ifs.Primary && !primaryFail {
						ifs.InitialWeight = 0
					}
				}
				if weightChange {
					n.TriggerChagne()

				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (n *MWan) FlushConntrack() error {
	c, err := conntrack.Dial(nil)
	if err != nil {
		log.Fatal(err)
	}
	return c.Flush()
}
