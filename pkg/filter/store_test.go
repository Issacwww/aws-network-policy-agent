package filter

import (
	"testing"

	policyendpoint "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	corev1 "k8s.io/api/core/v1"
)

func TestStoreMatchesPodDomainRules(t *testing.T) {
	tcp := corev1.ProtocolTCP
	port := int32(8080)
	store := New()
	store.SetRules("pod-a@ns-a", ClusterPolicyEndpointSource, []fwrp.EbpfFirewallRules{{
		DomainName: "*.EXAMPLE.com.",
		Action:     policyendpoint.ClusterNetworkPolicyRuleActionAccept,
		Priority:   50,
		L4Info:     []policyendpoint.Port{{Protocol: &tcp, Port: &port}},
	}})
	store.SetPod("10.0.0.10", "pod-a@ns-a")

	podIdentifier, ok := store.PodIdentifier("10.0.0.10")
	if !ok || podIdentifier != "pod-a@ns-a" {
		t.Fatalf("pod lookup = %q, %v", podIdentifier, ok)
	}
	rules, matched := store.MatchPod(podIdentifier, "Api.EXAMPLE.com.")
	if !matched || len(rules) != 1 {
		t.Fatalf("rules = %#v, matched = %v", rules, matched)
	}
	if rules[0].Priority != 50 || rules[0].L4PortProtocolInfo.Port == nil ||
		*rules[0].L4PortProtocolInfo.Port != port {
		t.Fatalf("matched rule = %#v", rules[0])
	}
}

func TestStorePreservesClusterDenyDomainRules(t *testing.T) {
	store := New()
	store.SetRules("pod-a@ns-a", ClusterPolicyEndpointSource, []fwrp.EbpfFirewallRules{{
		DomainName: "api.example.com",
		Action:     policyendpoint.ClusterNetworkPolicyRuleActionDeny,
	}})
	if !store.HasAnyDomainRules("pod-a@ns-a") {
		t.Fatal("Auto preserves non-Accept CPE domain rules")
	}
}
