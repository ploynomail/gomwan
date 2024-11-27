package gomwan

import (
	"net"
	"sort"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func (n *MWan) OutputRules() error {
	var rules []*nftables.Rule = make([]*nftables.Rule, 0)
	table := n.GetTable()
	chains := n.GetOutputChain()
	// ct state {established,related} meta mark set ct mark counter accept;
	{
		aSet := GetAnAnonymousSet(
			n.GetTable(), nftables.TypeCTState,
		)
		aSet.Interval = false
		n.Conn.AddSet(aSet, []nftables.SetElement{
			{
				Key: binaryutil.PutInt32(int32(expr.CtStateBitESTABLISHED)),
			},
			{
				Key: binaryutil.PutInt32(int32(expr.CtStateBitRELATED)),
			},
		})
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            0,
				},
				&expr.Lookup{
					SourceRegister: 1,
					DestRegister:   0,
					IsDestRegSet:   false,
					Invert:         false,
					SetID:          aSet.ID,
				},
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            3,
				},
				&expr.Meta{
					Key:            3,
					SourceRegister: true,
					Register:       1,
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}

		rules = append(rules, rule)
	}
	// # 负载均衡
	// # meta mark eq 0 ct state new meta mark set numgen random mod 2 map { 0: 100, 1: 101 } counter;
	if n.LoadBalancingType == Random {
		aSet := GetAnAnonymousSet(n.GetTable(), nftables.TypeInteger)
		aSet.DataType = nftables.TypeMark
		aSet.IsMap = true
		aSet.Interval = false
		elements := []nftables.SetElement{}
		wanIfs := n.Interfaces.FindWans()
		sort.Sort(wanIfs)
		for i := range wanIfs.Len() {
			element := nftables.SetElement{
				Key: binaryutil.PutInt32(int32(i)),
				Val: binaryutil.PutInt32(int32(i) + 100),
			}
			elements = append(elements, element)
		}
		n.Conn.AddSet(aSet, elements)
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:            3,
					SourceRegister: false,
					Register:       1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(0),
				},
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            0,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(int32(expr.CtStateBitNEW)),
				},
				&expr.Numgen{
					Register: 1,
					Modulus:  uint32(n.Interfaces.FindWans().Len()),
					Type:     unix.NFT_NG_RANDOM,
					Offset:   0,
				},
				&expr.Lookup{
					SourceRegister: 1,
					DestRegister:   1,
					IsDestRegSet:   true,
					SetID:          aSet.ID,
					Invert:         false,
				},
				&expr.Meta{
					Key:            3,
					SourceRegister: true,
					Register:       1,
				},
			},
		}
		rules = append(rules, rule)
	}
	if n.LoadBalancingType == Weight {
		aSet := GetAnAnonymousSet(n.GetTable(), nftables.TypeInteger)
		aSet.DataType = nftables.TypeMark
		aSet.IsMap = true
		aSet.Interval = true
		elements := []nftables.SetElement{}
		initialW := 0
		for i, wan := range n.Interfaces.FindWans() {
			s1 := initialW
			s2 := s1 + int(wan.InitialWeight*100)
			initialW = s2
			element := []nftables.SetElement{
				{
					Key: binaryutil.PutInt32(int32(s1)),
					Val: binaryutil.PutInt32(int32(i) + 100),
				}, {
					Key:         binaryutil.PutInt32(int32(s2)),
					IntervalEnd: true,
				},
			}
			elements = append(elements, element...)
		}
		n.Conn.AddSet(aSet, elements)
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:            3,
					SourceRegister: false,
					Register:       1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(0),
				},
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            0,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(int32(expr.CtStateBitNEW)),
				},
				&expr.Numgen{
					Register: 1,
					Modulus:  uint32(100),
					Type:     unix.NFT_NG_RANDOM,
					Offset:   uint32(0),
				},
				&expr.Lookup{
					SourceRegister: 1,
					DestRegister:   2,
					IsDestRegSet:   true,
					SetID:          aSet.ID,
					Invert:         false,
				},
				&expr.Meta{
					Key:            3,
					SourceRegister: true,
					Register:       2,
				},
				&expr.Log{
					Level: 4,
				},
			},
		}
		rules = append(rules, rule)
	}
	// ip daddr 127.0.0.1/8 ct state new meta mark set 50 counter; # 放过所有lo地址
	{
		startIP, endIp, _ := GetStartAndEndIp("127.0.0.1/8")

		aSet := GetAnAnonymousSet(
			n.GetTable(), nftables.TypeIPAddr,
		)
		aSet.Interval = true
		n.Conn.AddSet(aSet, []nftables.SetElement{
			{
				Key:         incrementIP(endIp).To4(),
				IntervalEnd: true,
			},
			{
				Key: startIP.To4(),
			},
			{
				Key:         []byte{0, 0, 0, 0},
				IntervalEnd: true,
			},
		})
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				// 匹配ip头部的目的ip字段
				&expr.Payload{
					OperationType:  expr.PayloadLoad,
					Base:           expr.PayloadBaseNetworkHeader,
					DestRegister:   1,
					SourceRegister: 0,
					Offset:         16,
					Len:            4,
				},
				&expr.Lookup{
					SourceRegister: 1,
					DestRegister:   0,
					SetID:          aSet.ID,
				},
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            0,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(int32(expr.CtStateBitNEW)),
				},
				&expr.Immediate{
					Register: 1,
					Data:     []byte{0x32},
				},
				&expr.Meta{
					Key:            3,
					SourceRegister: true,
					Register:       1,
				},
			},
		}
		rules = append(rules, rule)
	}
	// ip daddr 192.168.2.0/24 ct state new meta mark set 50 counter; # 放过所有LAN地址
	{
		aSet := GetAnAnonymousSet(
			n.GetTable(), nftables.TypeIPAddr,
		)
		aSet.Interval = true
		var elements = []nftables.SetElement{}
		for _, lan := range n.Interfaces.FindLans() {
			ipstr := ipMaskTOCRDI(net.IPNet{
				IP:   lan.IP,
				Mask: lan.Mask,
			})
			startIP, endIp, _ := GetStartAndEndIp(ipstr)
			elements = append(elements, []nftables.SetElement{
				{
					Key: startIP.To4(),
				},
				{
					Key:         incrementIP(endIp).To4(),
					IntervalEnd: true,
				},
			}...)
		}
		elements = append(elements, []nftables.SetElement{
			{
				Key:         []byte{0, 0, 0, 9},
				IntervalEnd: true,
			},
		}...)
		n.Conn.AddSet(aSet, elements)
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				// 匹配ip头部的目的ip字段
				&expr.Payload{
					OperationType:  expr.PayloadLoad,
					Base:           expr.PayloadBaseNetworkHeader,
					DestRegister:   1,
					SourceRegister: 0,
					Offset:         16,
					Len:            4,
				},
				&expr.Lookup{
					SourceRegister: 1,
					DestRegister:   0,
					SetID:          aSet.ID,
				},
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            0,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(int32(expr.CtStateBitNEW)),
				},
				&expr.Immediate{
					Register: 1,
					Data:     []byte{0x32},
				},
				&expr.Meta{
					Key:            3,
					SourceRegister: true,
					Register:       1,
				},
			},
		}
		rules = append(rules, rule)
	}
	// ct mark set meta mark;
	{
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Meta{Key: 3, SourceRegister: false, Register: 1},
				&expr.Ct{Register: 1, SourceRegister: true, Key: 3},
			},
		}
		rules = append(rules, rule)
	}
	for _, rule := range rules {
		n.Conn.AddRule(rule)
	}
	return nil
}

func (n *MWan) POSTROUTINGRules() error {
	var rules []*nftables.Rule = make([]*nftables.Rule, 0)
	table := n.GetTable()
	chains := n.GetPostroutingChain()
	// ct mark set meta mark
	{
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Meta{Key: 3, SourceRegister: false, Register: 1},
				&expr.Ct{Register: 1, SourceRegister: true, Key: 3},
			},
		}
		rules = append(rules, rule)
	}
	// meta mark > 0x00000032 jump snat_postrouting
	{
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Meta{Key: 3, SourceRegister: false, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpGt,
					Register: 1,
					Data:     binaryutil.PutInt32(50),
				},
				&expr.Verdict{
					Kind:  expr.VerdictJump,
					Chain: "mwan_snat_postrouting",
				},
			},
		}
		rules = append(rules, rule)
	}
	// meta mark 0x00000032 accept
	{
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Meta{Key: 3, SourceRegister: false, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(50),
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		}
		rules = append(rules, rule)
	}
	// log counter packets 0 bytes 0 drop
	{
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Log{
					Level: 4,
					Flags: 0,
				},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		}
		rules = append(rules, rule)
	}
	for _, rule := range rules {
		n.Conn.AddRule(rule)
	}
	return nil
}

func (n *MWan) SNatPostroutingRules() error {
	wanifs := n.Interfaces.FindWans()
	sort.Sort(wanifs)
	var rules []*nftables.Rule = make([]*nftables.Rule, 0)
	table := n.GetTable()
	chains := n.GetSnatPostroutingChain()
	// meta mark 0x00000064 snat to 192.168.22.224
	// meta mark 0x00000065 snat to 192.168.1.100
	{
		for i, wan := range wanifs {
			rule := &nftables.Rule{
				Table: table,
				Chain: chains,
				Exprs: []expr.Any{
					&expr.Meta{Key: 3, SourceRegister: false, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     binaryutil.PutInt32(int32(100 + i)),
					},
					&expr.Immediate{
						Register: 1,
						Data:     net.ParseIP(wan.IP.String()).To4(),
					},
					&expr.NAT{
						Type:        expr.NATTypeSourceNAT,
						Family:      unix.NFPROTO_IPV4,
						RegAddrMin:  1,
						RegAddrMax:  1,
						RegProtoMin: 0,
						RegProtoMax: 0,
						Random:      false, FullyRandom: false, Persistent: false, Prefix: false,
					},
				},
			}
			rules = append(rules, rule)
		}
	}
	// log counter packets 382 bytes 26646 drop
	{
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Log{
					Level: 4,
					Flags: 0,
				},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		}
		rules = append(rules, rule)
	}

	for _, rule := range rules {
		n.Conn.AddRule(rule)
	}
	return nil
}

func (n *MWan) LocalSysRules() error {
	table := n.GetTable()
	chains := n.GetLocalSysChain()
	var rules []*nftables.Rule = make([]*nftables.Rule, 0)
	// ct state {established,related} counter accept
	{
		aSet := GetAnAnonymousSet(
			n.GetTable(), nftables.TypeCTState,
		)
		aSet.Interval = false
		n.Conn.AddSet(aSet, []nftables.SetElement{
			{
				Key: binaryutil.PutInt32(int32(expr.CtStateBitESTABLISHED)),
			},
			{
				Key: binaryutil.PutInt32(int32(expr.CtStateBitRELATED)),
			},
		})
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            0,
				},
				&expr.Lookup{
					SourceRegister: 1,
					DestRegister:   0,
					IsDestRegSet:   false,
					Invert:         false,
					SetID:          aSet.ID,
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}

		rules = append(rules, rule)
	}
	// ct state invalid counter drop
	{

		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            0,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(int32(expr.CtStateBitINVALID)),
				},
				&expr.Verdict{
					Kind: expr.VerdictDrop,
				},
			},
		}

		rules = append(rules, rule)
	}
	// ct state new counter accept;
	{
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            0,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(int32(expr.CtStateBitNEW)),
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}

		rules = append(rules, rule)
	}
	for _, rule := range rules {
		n.Conn.AddRule(rule)
	}
	return nil
}

func (n *MWan) InputPublicRules() error {
	table := n.GetTable()
	chains := n.GetInputPublicChain()
	var rules []*nftables.Rule = make([]*nftables.Rule, 0)
	{
		aSet := GetAnAnonymousSet(
			n.GetTable(), nftables.TypeCTState,
		)
		aSet.Interval = false
		n.Conn.AddSet(aSet, []nftables.SetElement{
			{
				Key: binaryutil.PutInt32(int32(expr.CtStateBitESTABLISHED)),
			},
			{
				Key: binaryutil.PutInt32(int32(expr.CtStateBitRELATED)),
			},
		})
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            0,
				},
				&expr.Lookup{
					SourceRegister: 1,
					DestRegister:   0,
					IsDestRegSet:   false,
					Invert:         false,
					SetID:          aSet.ID,
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}

		rules = append(rules, rule)
	}
	// ct state invalid counter drop
	{

		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            0,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(int32(expr.CtStateBitINVALID)),
				},
				&expr.Verdict{
					Kind: expr.VerdictDrop,
				},
			},
		}

		rules = append(rules, rule)
	}
	// ct state new counter accept;
	{
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            0,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(int32(expr.CtStateBitNEW)),
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}

		rules = append(rules, rule)
	}
	for _, rule := range rules {
		n.Conn.AddRule(rule)
	}
	return nil
}

func (n *MWan) FilterRules() error {
	table := n.GetTable()
	chains := n.GetFilterChain()
	wanifs := n.Interfaces.FindWans()
	lanifs := n.Interfaces.FindLans()
	sort.Sort(wanifs)
	var rules []*nftables.Rule = make([]*nftables.Rule, 0)
	// iif lo accept;
	{
		loInf, err := net.InterfaceByName("lo")
		if err != nil {
			return err
		}
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Meta{Key: 4, SourceRegister: false, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(int32(loInf.Index)),
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}
		rules = append(rules, rule)
	}
	// iifname eth1 jump my_input_public;
	// iifname eth3 jump my_input_public;
	{
		for _, wan := range wanifs {
			Inf, err := net.InterfaceByName(wan.Name)
			if err != nil {
				continue
			}
			rule := &nftables.Rule{
				Table: table,
				Chain: chains,
				Exprs: []expr.Any{
					&expr.Meta{Key: 4, SourceRegister: false, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     binaryutil.PutInt32(int32(Inf.Index)),
					},
					&expr.Verdict{
						Kind:  expr.VerdictJump,
						Chain: "mwan_input_public",
					},
				},
			}
			rules = append(rules, rule)
		}
	}
	// iifname eth5 ip daddr 192.168.2.0/24 jump local_sys;
	{
		for _, lan := range lanifs {
			Inf, err := net.InterfaceByName(lan.Name)
			if err != nil {
				continue
			}
			rule := &nftables.Rule{
				Table: table,
				Chain: chains,
				Exprs: []expr.Any{
					&expr.Meta{Key: 4, SourceRegister: false, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     binaryutil.PutInt32(int32(Inf.Index)),
					},
					&expr.Payload{
						OperationType:  expr.PayloadLoad,
						Base:           expr.PayloadBaseNetworkHeader,
						DestRegister:   1,
						SourceRegister: 0,
						Offset:         16,
						Len:            4,
					},
					// &expr.Cmp{
					// 	Op:       expr.CmpOpEq,
					// 	Register: 1,
					// 	Data:     net.ParseIP(lan.IP.String()).To4(),
					// },
					&expr.Verdict{
						Kind:  expr.VerdictJump,
						Chain: "mwan_local_sys",
					},
				},
			}
			rules = append(rules, rule)
		}
	}
	// meta mark set ct mark;
	{
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            3,
				},
				&expr.Meta{
					Key:            3,
					SourceRegister: true,
					Register:       1,
				},
			},
		}
		rules = append(rules, rule)
	}
	// # 负载均衡
	// # ct state new meta mark set numgen random mod 10 map { 0-4: 100, 5-9: 101 } comment "Without Queue monitor..."
	// # ct state new meta mark set numgen random mod 2 map { 0: 100, 1: 101 } comment "Without Queue monitor..."
	if n.LoadBalancingType == Random {
		aSet := GetAnAnonymousSet(n.GetTable(), nftables.TypeInteger)
		aSet.DataType = nftables.TypeMark
		aSet.IsMap = true
		aSet.Interval = false
		elements := []nftables.SetElement{}
		wanIfs := n.Interfaces.FindWans()
		sort.Sort(wanIfs)
		for i := range wanIfs.Len() {
			element := nftables.SetElement{
				Key: binaryutil.PutInt32(int32(i)),
				Val: binaryutil.PutInt32(int32(i) + 100),
			}
			elements = append(elements, element)
		}
		n.Conn.AddSet(aSet, elements)
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:            3,
					SourceRegister: false,
					Register:       1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(0),
				},
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            0,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(int32(expr.CtStateBitNEW)),
				},
				&expr.Numgen{
					Register: 1,
					Modulus:  uint32(n.Interfaces.FindWans().Len()),
					Type:     unix.NFT_NG_RANDOM,
				},
				&expr.Lookup{
					SourceRegister: 1,
					DestRegister:   1,
					IsDestRegSet:   true,
					SetID:          aSet.ID,
					Invert:         false,
				},
				&expr.Meta{
					Key:            3,
					SourceRegister: true,
					Register:       1,
				},
			},
		}
		rules = append(rules, rule)
	}
	if n.LoadBalancingType == Weight {
		aSet := GetAnAnonymousSet(n.GetTable(), nftables.TypeInteger)
		aSet.DataType = nftables.TypeMark
		aSet.IsMap = true
		aSet.Interval = true
		elements := []nftables.SetElement{}
		initialW := 0
		for i, wan := range n.Interfaces.FindWans() {
			s1 := initialW
			s2 := s1 + int(wan.InitialWeight*100)
			initialW = s2
			element := []nftables.SetElement{
				{
					Key: binaryutil.PutInt32(int32(s1)),
					Val: binaryutil.PutInt32(int32(i) + 100),
				}, {
					Key:         binaryutil.PutInt32(int32(s2)),
					IntervalEnd: true,
				},
			}
			elements = append(elements, element...)
		}
		n.Conn.AddSet(aSet, elements)
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:            3,
					SourceRegister: false,
					Register:       1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(0),
				},
				&expr.Ct{
					Register:       1,
					SourceRegister: false,
					Key:            0,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.PutInt32(int32(expr.CtStateBitNEW)),
				},
				&expr.Numgen{
					Register: 1,
					Modulus:  uint32(100),
					Type:     unix.NFT_NG_RANDOM,
				},
				&expr.Lookup{
					SourceRegister: 1,
					DestRegister:   1,
					IsDestRegSet:   true,
					SetID:          aSet.ID,
					Invert:         false,
				},
				&expr.Meta{
					Key:            3,
					SourceRegister: true,
					Register:       1,
				},
			},
		}
		rules = append(rules, rule)
	}
	// ct mark set meta mark;
	{
		rule := &nftables.Rule{
			Table: table,
			Chain: chains,
			Exprs: []expr.Any{
				&expr.Meta{Key: 3, SourceRegister: false, Register: 1},
				&expr.Ct{Register: 1, SourceRegister: true, Key: 3},
			},
		}
		rules = append(rules, rule)
	}
	for _, rule := range rules {
		n.Conn.AddRule(rule)
	}
	return nil
}
