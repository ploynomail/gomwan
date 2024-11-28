package gomwan

import "testing"

func TestFindDefaultRouteInTable(t *testing.T) {
	dr, err := findDefaultRouteInTable(100)
	if err != nil {
		t.Errorf("Expected nil, got %v", err)
	}
	t.Logf("Default route: %v", dr)
}

func TestAddDefaultRouteInTable(t *testing.T) {
	err := addDefaultRouteInTable(100, "eth0", "192.168.22.1")
	if err != nil {
		t.Errorf("Expected nil, got %v", err)
	}
}

func TestDelRule(t *testing.T) {
	err := delDefaultRouteInTable(100)
	if err != nil {
		t.Errorf("Expected nil, got %v", err)
	}
}
