package ipfilter

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestAutoConformanceSetup(t *testing.T) {
	controller := caddy.NewTestController("dns", "ipfilter")
	if err := SetupIPFilter(controller); err != nil {
		t.Fatalf("SetupIPFilter: %v", err)
	}

	controller = caddy.NewTestController("dns", "ipfilter unexpected")
	if err := SetupIPFilter(controller); err == nil {
		t.Fatal("ipfilter arguments must be rejected")
	}
}
