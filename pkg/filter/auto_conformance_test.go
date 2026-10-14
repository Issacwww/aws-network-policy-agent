package filter

import (
	"testing"

	policyendpoint "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	corev1 "k8s.io/api/core/v1"
)

func TestAutoConformanceDomainMatchingIsCaseSensitive(t *testing.T) {
	tcp := corev1.ProtocolTCP
	port := int32(443)
	store := New()
	store.SetRules("pod@ns", PolicyEndpointSource, []fwrp.EbpfFirewallRules{{
		DomainName: "API.Example.COM.",
		Priority:   15001,
		L4Info:     []policyendpoint.Port{{Protocol: &tcp, Port: &port}},
	}})

	if _, matched := store.MatchPod("pod@ns", "api.example.com."); matched {
		t.Fatal("Auto matching is case-sensitive; differently cased qname must not match")
	}
	rules, matched := store.MatchPod("pod@ns", "API.Example.COM.")
	if !matched || len(rules) != 1 {
		t.Fatalf("same-case exact match = %#v, %v; want one rule", rules, matched)
	}
}

func TestAutoConformanceControllerMergeAppendsDuplicateRules(t *testing.T) {
	tcp := corev1.ProtocolTCP
	port := int32(443)
	rule := fwrp.EbpfFirewallRules{
		DomainName: "api.example.com.",
		Priority:   15001,
		L4Info:     []policyendpoint.Port{{Protocol: &tcp, Port: &port}},
	}
	store := New()
	store.SetRules("pod@ns", PolicyEndpointSource, []fwrp.EbpfFirewallRules{rule})
	store.SetRules("pod@ns", ClusterPolicyEndpointSource, []fwrp.EbpfFirewallRules{rule})

	rules, matched := store.MatchPod("pod@ns", "api.example.com.")
	if !matched || len(rules) != 2 {
		t.Fatalf("merged duplicate rules = %#v, %v; want Auto append behavior with two entries", rules, matched)
	}

	store.DeleteRules("pod@ns", PolicyEndpointSource)
	rules, matched = store.MatchPod("pod@ns", "api.example.com.")
	if !matched || len(rules) != 1 {
		t.Fatalf("remaining CPE rules = %#v, %v; want one entry after PE deletion", rules, matched)
	}
}

func TestAutoConformanceClusterDomainActionIsNotFilteredByAgent(t *testing.T) {
	store := New()
	store.SetRules("pod@ns", ClusterPolicyEndpointSource, []fwrp.EbpfFirewallRules{{
		DomainName: "api.example.com.",
		Action:     policyendpoint.ClusterNetworkPolicyRuleActionDeny,
		Priority:   100,
	}})

	rules, matched := store.MatchPod("pod@ns", "api.example.com.")
	if !matched || len(rules) != 1 {
		t.Fatalf("cluster domain action was filtered: rules = %#v, matched = %v", rules, matched)
	}
}

func TestAutoConformanceWildcardReturnsMatchedRule(t *testing.T) {
	store := New()
	store.SetRules("pod@ns", PolicyEndpointSource, []fwrp.EbpfFirewallRules{{
		DomainName: "*.example.com.",
		Priority:   15001,
		L4Info:     []policyendpoint.Port{{}},
	}})

	rules, matched := store.MatchPod("pod@ns", "a.b.example.com.")
	if !matched || len(rules) != 1 || !rules[0].Equal(npatypes.L4Rule{
		L4PortProtocolInfo: policyendpoint.Port{},
		Priority:           15001,
	}) {
		t.Fatalf("wildcard match = %#v, %v; want Auto wildcard rule", rules, matched)
	}
	if _, matched := store.MatchPod("pod@ns", "example.com."); matched {
		t.Fatal("wildcard must not match the root domain")
	}
}

func TestAutoConformanceExactRuleWinsOverEarlierWildcard(t *testing.T) {
	store := New([]Rule{
		{DomainName: "*.example.com.", Priority: 100},
		{DomainName: "api.example.com.", Priority: 200},
	})

	result, matched := store.Match("api.example.com.")
	if !matched || result.Rule.Priority != 200 {
		t.Fatalf("match = %#v, %v; want exact rule priority 200", result, matched)
	}
}
