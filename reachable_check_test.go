package gomwan

import (
	"net"
	"testing"
)

func TestNewReachabilityCheck(t *testing.T) {
	result := ReachabilityCheckResult{
		InfName:             "eth0",
		BuiltInLost:         0,
		MustBeReachableLost: 0,
	}
	must := []net.IP{
		net.IPv4(8, 8, 8, 8),
	}
	rc := NewReachabilityCheck([]string{"eth0"}, must)
	reachable := rc.IsReachable()
	if reachable[0] != result {
		t.Errorf("Expected %v, got %v", result, reachable[0])
	}
}
