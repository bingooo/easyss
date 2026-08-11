//go:build tsnet
// +build tsnet

package tsnet

import (
	"testing"
)

func TestIsTailscaleTarget(t *testing.T) {
	cfg := Config{
		Enable:       true,
		ExtraSubnets: []string{"192.168.100.0/24"},
	}
	Configure(cfg)

	tests := []struct {
		host string
		want bool
	}{
		{"100.64.0.1", true},
		{"100.100.100.100", true},
		{"100.127.255.254", true},
		{"my-node.ts.net", true},
		{"sub.domain.ts.net", true},
		{"192.168.100.50", true},
		{"192.168.1.1", false},
		{"1.1.1.1", false},
		{"google.com", false},
	}

	for _, tt := range tests {
		got := IsTailscaleTarget(tt.host)
		if got != tt.want {
			t.Errorf("IsTailscaleTarget(%q) = %v; want %v", tt.host, got, tt.want)
		}
	}
}
