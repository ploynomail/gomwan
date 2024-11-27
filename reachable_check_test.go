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
	builtin := []net.IP{
		net.IPv4(8, 8, 8, 8),
		net.IPv4(8, 8, 4, 4),
		net.IPv4(1, 1, 1, 1),
		net.IPv4(223, 5, 5, 5),
		net.IPv4(223, 6, 6, 6),
	}
	rc := NewReachabilityCheck([]string{"eth0"}, must, builtin)
	reachable := rc.IsReachable()
	if reachable[0] != result {
		t.Errorf("Expected %v, got %v", result, reachable[0])
	}
}
