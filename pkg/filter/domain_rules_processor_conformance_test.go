package filter

import (
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	corev1 "k8s.io/api/core/v1"
)

func TestAutoConformanceDomainRuleProcessor(t *testing.T) {
	tcp := corev1.ProtocolTCP
	port80 := int32(80)
	port443 := int32(443)
	priority := utils.PE_PRIORITY*10 + int(utils.ActionAccept)
	input := []fwrp.EbpfFirewallRules{
		{
			DomainName: "shared.example.com.",
			Priority:   priority,
			L4Info:     []policyk8sawsv1.Port{{Protocol: &tcp, Port: &port80}},
		},
		{
			DomainName: "shared.example.com.",
			Priority:   priority,
			L4Info: []policyk8sawsv1.Port{
				{Protocol: &tcp, Port: &port80},
				{Protocol: &tcp, Port: &port443},
			},
		},
		{DomainName: "all.example.com.", Priority: priority},
		{IPCidr: "192.0.2.0/24", Priority: priority},
	}

	want := map[string][]npatypes.L4Rule{
		"shared.example.com.": {
			{L4PortProtocolInfo: policyk8sawsv1.Port{Protocol: &tcp, Port: &port80}, Priority: priority},
			{L4PortProtocolInfo: policyk8sawsv1.Port{Protocol: &tcp, Port: &port443}, Priority: priority},
		},
		"all.example.com.": {
			{L4PortProtocolInfo: policyk8sawsv1.Port{}, Priority: priority},
		},
	}

	gotPE := ComputeDNSProxyRulesFromEbpfFirewallRulesForPE(input)
	gotCPE := ComputeDNSProxyRulesFromEbpfFirewallRulesForCPE(input)
	assertDomainRuleMap(t, gotPE, want)
	assertDomainRuleMap(t, gotCPE, want)
}

func assertDomainRuleMap(
	t *testing.T,
	got map[string][]npatypes.L4Rule,
	want map[string][]npatypes.L4Rule,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("domain count = %d, want %d: %#v", len(got), len(want), got)
	}
	for domain, wantRules := range want {
		gotRules := got[domain]
		if len(gotRules) != len(wantRules) {
			t.Fatalf("%s rule count = %d, want %d: %#v", domain, len(gotRules), len(wantRules), gotRules)
		}
		for index := range wantRules {
			if !gotRules[index].Equal(wantRules[index]) {
				t.Fatalf("%s rule %d = %#v, want %#v", domain, index, gotRules[index], wantRules[index])
			}
		}
	}
}
