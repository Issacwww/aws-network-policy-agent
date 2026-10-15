package fwruleprocessor

import "testing"

func TestAutoConformanceSplitDomainRulesAddsOneTrailingDot(t *testing.T) {
	domains, ips := SplitDomainAndIPRules([]EbpfFirewallRules{
		{DomainName: "api.example.com"},
		{DomainName: "*.example.com."},
		{IPCidr: "192.0.2.0/24"},
	})

	if len(domains) != 2 {
		t.Fatalf("domain rules = %#v, want 2", domains)
	}
	if domains[0].DomainName != "api.example.com." {
		t.Fatalf("canonical exact domain = %q, want api.example.com.", domains[0].DomainName)
	}
	if domains[1].DomainName != "*.example.com." {
		t.Fatalf("canonical wildcard domain = %q, want one retained trailing dot", domains[1].DomainName)
	}
	if len(ips) != 1 || ips[0].IPCidr != "192.0.2.0/24" {
		t.Fatalf("IP rules = %#v, want unchanged CIDR rule", ips)
	}
}
