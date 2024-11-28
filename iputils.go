package gomwan

import (
	"net"

	"github.com/vishvananda/netlink"
)

func findRule(mark uint32, table int) ([]netlink.Rule, error) {
	rules, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	var result []netlink.Rule
	for _, rule := range rules {
		if rule.Table == table && rule.Mark == mark {
			result = append(result, rule)
		}
	}
	return result, nil
}

func findConfictRule(mark uint32, table int) ([]netlink.Rule, error) {
	rules, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	var result []netlink.Rule
	for _, rule := range rules {
		if rule.Table == table || rule.Mark == mark {
			result = append(result, rule)
		}
	}
	return result, nil
}

func delConfictRule(mark uint32, table int) error {
	rules, err := findConfictRule(mark, table)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if err := netlink.RuleDel(&rule); err != nil {
			return err
		}
	}
	return nil
}

func addRule(mark uint32, table int) error {
	rule := netlink.NewRule()
	rule.Table = table
	rule.Mark = mark
	if err := netlink.RuleAdd(rule); err != nil {
		return err
	}
	return nil
}

func delRule(mark uint32, table int) error {
	rules, err := findRule(mark, table)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if err := netlink.RuleDel(&rule); err != nil {
			return err
		}
	}
	return nil
}

func findDefaultRouteInTable(table int) (*netlink.Route, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	defalutDest := net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)}
	for _, route := range routes {
		if route.Table == table && route.Dst.String() == defalutDest.String() {
			return &route, nil
		}
	}
	return nil, nil
}

func addDefaultRouteInTable(table int, dev, gw string) error {
	ifcIndex, err := net.InterfaceByName(dev)
	if err != nil {
		return err
	}
	route := netlink.Route{
		Table:     table,
		Gw:        net.ParseIP(gw),
		LinkIndex: ifcIndex.Index,
	}
	if err := netlink.RouteAdd(&route); err != nil {
		return err
	}
	return nil
}

func delDefaultRouteInTable(table int) error {
	route, err := findDefaultRouteInTable(table)
	if err != nil {
		return err
	}
	if route != nil {
		if err := netlink.RouteDel(route); err != nil {
			return err
		}
	}
	return nil
}
