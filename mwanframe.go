package gomwan

import "github.com/google/nftables"

var Accept = nftables.ChainPolicyAccept

// table ip mangle {}
func (n *MWan) GetTable() *nftables.Table {
	return &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   MWanTableName,
	}
}

//   chain my_filter {
//     type filter hook prerouting priority -150; policy accept;
//   }

func (n *MWan) GetFilterChain() *nftables.Chain {
	return &nftables.Chain{
		Name:     "mwan_filter",
		Table:    n.GetTable(),
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(-151),
		Policy:   &Accept,
	}
}

//   chain my_input_public {
//   }

func (n *MWan) GetInputPublicChain() *nftables.Chain {
	return &nftables.Chain{
		Name:  "mwan_input_public",
		Table: n.GetTable(),
	}
}

//   chain local_sys {
//   }

func (n *MWan) GetLocalSysChain() *nftables.Chain {
	return &nftables.Chain{
		Name:  "mwan_local_sys",
		Table: n.GetTable(),
	}
}

//   chain OUTPUT {
//     type route hook output priority mangle; policy accept;
//   }

func (n *MWan) GetOutputChain() *nftables.Chain {
	return &nftables.Chain{
		Name:     "mwan_output",
		Table:    n.GetTable(),
		Type:     nftables.ChainTypeRoute,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityMangle,
		Policy:   &Accept,
	}
}

//   chain POSTROUTING {
//     type nat hook postrouting priority srcnat; policy accept;
//   }

func (n *MWan) GetPostroutingChain() *nftables.Chain {
	return &nftables.Chain{
		Name:     "mwan_postrouting",
		Table:    n.GetTable(),
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Policy:   &Accept,
	}
}

//   chain snat_postrouting {
//   }

func (n *MWan) GetSnatPostroutingChain() *nftables.Chain {
	return &nftables.Chain{
		Name:  "mwan_snat_postrouting",
		Table: n.GetTable(),
	}
}
