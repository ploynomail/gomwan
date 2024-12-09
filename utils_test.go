package gomwan

import (
	"testing"
)

func TestGetStartAndEndIp(t *testing.T) {
	tests := []struct {
		cidr     string
		startIP  string
		endIP    string
		hasError bool
	}{
		{"192.168.1.0/24", "192.168.1.0", "192.168.1.255", false},
		{"10.0.0.0/8", "10.0.0.0", "10.255.255.255", false},
		{"172.16.0.0/12", "172.16.0.0", "172.31.255.255", false},
		{"invalidCIDR", "", "", true},
	}

	for _, tt := range tests {
		startIP, endIP, err := GetStartAndEndIp(tt.cidr)
		if (err != nil) != tt.hasError {
			t.Errorf("GetStartAndEndIp(%s) error = %v, wantErr %v", tt.cidr, err, tt.hasError)
			continue
		}
		if !tt.hasError {
			if startIP.String() != tt.startIP {
				t.Errorf("GetStartAndEndIp(%s) startIP = %v, want %v", tt.cidr, startIP, tt.startIP)
			}
			if endIP.String() != tt.endIP {
				t.Errorf("GetStartAndEndIp(%s) endIP = %v, want %v", tt.cidr, endIP, tt.endIP)
			}
		}
	}
}
