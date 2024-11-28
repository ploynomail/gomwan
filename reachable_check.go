package gomwan

import (
	"fmt"
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
	InterfaceName      []string
	MustBeReachableIps []net.IP
}

func NewReachabilityCheck(infNames []string, must []net.IP) *ReachabilityCheck {
	return &ReachabilityCheck{
		InterfaceName:      infNames,
		MustBeReachableIps: must,
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
		reachableResults = append(reachableResults, reachableResult)
	}
	return reachableResults
}

func (r *ReachabilityCheck) ping(ip net.IP, infName string) bool {
	pinger, err := probing.NewPinger(ip.String())
	if err != nil {
		return false
	}
	pinger.SetPrivileged(true)
	pinger.Interval = 100 * time.Millisecond // 10ms between packets
	pinger.Timeout = 2 * time.Second
	pinger.InterfaceName = infName
	pinger.SetMark(49)
	pinger.Count = 3
	err = pinger.Run() // Blocks until finished.
	if err != nil {
		fmt.Println(err)
		return false
	}
	stats := pinger.Statistics()
	return stats.PacketLoss <= 50
}
