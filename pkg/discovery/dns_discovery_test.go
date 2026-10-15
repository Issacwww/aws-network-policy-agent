package discovery

import (
	"encoding/json"
	"net"
	"testing"
)

func TestDNSIPsForFamilyCombinesServiceCIDRsAndClusterDNS(t *testing.T) {
	userData := &UserData{}
	userData.Coredns.ServiceCIDR = []string{"10.100.0.0/16", "2001:db8:1::/112"}
	userData.Kubernetes.ClusterDNSIP.IPs = []string{"10.100.0.10", "2001:db8:1::a", "invalid"}

	ipv4, err := dnsIPsForFamily(userData, "IPv4")
	if err != nil {
		t.Fatal(err)
	}
	if len(ipv4) != 1 || !ipv4[0].Equal(net.ParseIP("10.100.0.10")) {
		t.Fatalf("IPv4 DNS addresses = %#v, want deduplicated 10.100.0.10", ipv4)
	}

	ipv6, err := dnsIPsForFamily(userData, "ipv6")
	if err != nil {
		t.Fatal(err)
	}
	if len(ipv6) != 1 || !ipv6[0].Equal(net.ParseIP("2001:db8:1::a")) {
		t.Fatalf("IPv6 DNS addresses = %#v, want deduplicated 2001:db8:1::a", ipv6)
	}
}

func TestDNSIPsForFamilyRejectsNoUsableAddress(t *testing.T) {
	userData := &UserData{}
	userData.Kubernetes.ClusterDNSIP.IPs = []string{"invalid", "2001:db8::10"}
	if _, err := dnsIPsForFamily(userData, "ipv4"); err == nil {
		t.Fatal("expected missing IPv4 DNS address to fail")
	}
}

func TestClusterDNSIPAcceptsAutoStringShape(t *testing.T) {
	var clusterDNS ClusterDNSIP
	if err := json.Unmarshal([]byte(`"10.100.0.10"`), &clusterDNS); err != nil {
		t.Fatal(err)
	}
	if len(clusterDNS.IPs) != 1 || clusterDNS.IPs[0] != "10.100.0.10" {
		t.Fatalf("cluster DNS IPs = %#v, want one string value", clusterDNS.IPs)
	}
}
