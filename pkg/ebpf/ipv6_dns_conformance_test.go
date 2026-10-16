package ebpf

import (
	"os"
	"strings"
	"testing"
)

func TestIPv6EgressProgramIncludesAutoDNSIPCache(t *testing.T) {
	source, err := os.ReadFile("c/tc.v6egress.bpf.c")
	if err != nil {
		t.Fatalf("read IPv6 egress program: %v", err)
	}
	program := string(source)
	required := []string{
		"struct ipcache_key",
		"struct in6_addr ip",
		`SEC("maps") ipcache_map`,
		".type = BPF_MAP_TYPE_LRU_HASH",
		".max_entries = 65536",
		"checkIPCache(",
		"bpf_ktime_get_ns()",
		"ipcache_action = checkIPCache(",
	}
	for _, snippet := range required {
		if !strings.Contains(program, snippet) {
			t.Errorf("IPv6 egress program is missing Auto DNS behavior %q", snippet)
		}
	}
}

func TestIPv6DNSIPCacheChecksExactAndRangePorts(t *testing.T) {
	source, err := os.ReadFile("c/tc.v6egress.bpf.c")
	if err != nil {
		t.Fatalf("read IPv6 egress program: %v", err)
	}
	program := string(source)
	for _, snippet := range []string{
		"dest_port == port_entry->start_port",
		"dest_port > port_entry->start_port",
		"dest_port <= port_entry->end_port",
	} {
		if !strings.Contains(program, snippet) {
			t.Errorf("IPv6 DNS ipcache port matching is missing %q", snippet)
		}
	}
}
