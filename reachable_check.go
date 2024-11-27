package gomwan

import (
	"net"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

type ReachabilityCheckResult struct {
	InfName             string
	BuiltInLost         int
	MustBeReachableLost int
}

type ReachabilityCheck struct {
	InterfaceName       []string
	MustBeReachableIps  []net.IP
	BuiltInReachableIps []net.IP
}

func NewReachabilityCheck(infNames []string, must, builtin []net.IP) *ReachabilityCheck {
	return &ReachabilityCheck{
		InterfaceName:       infNames,
		BuiltInReachableIps: builtin,
		MustBeReachableIps:  must,
	}
}

func (r *ReachabilityCheck) IsReachable() []ReachabilityCheckResult {
	var reachableResults []ReachabilityCheckResult
	for _, infname := range r.InterfaceName {
		var reachableResult ReachabilityCheckResult = ReachabilityCheckResult{InfName: infname}
		for _, ip := range r.MustBeReachableIps {
			if !r.ping(ip, infname) {
				reachableResult.MustBeReachableLost++
			}
		}
		for _, ip := range r.BuiltInReachableIps {
			if !r.ping(ip, infname) {
				reachableResult.BuiltInLost++
			}
		}
		reachableResults = append(reachableResults, reachableResult)
	}
	return reachableResults
}

func (r *ReachabilityCheck) ping(ip net.IP, infName string) bool {
	pinger, err := probing.NewPinger(ip.String())
	if err != nil {
		return false
	}
	pinger.Interval = 10 * time.Millisecond // 10ms between packets
	pinger.Timeout = 2 * time.Second
	pinger.InterfaceName = infName
	pinger.Count = 3
	err = pinger.Run() // Blocks until finished.
	if err != nil {
		return false
	}
	stats := pinger.Statistics()
	return stats.PacketLoss <= 50
}
