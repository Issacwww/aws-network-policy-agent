package filter

import (
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

func TestDomainMatchingContract(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		qname   string
		matched bool
	}{
		{name: "exact", pattern: "a.example.com.", qname: "a.example.com.", matched: true},
		{name: "exact does not include child", pattern: "a.example.com.", qname: "x.a.example.com.", matched: false},
		{name: "wildcard includes one label", pattern: "*.a.com.", qname: "x.a.com.", matched: true},
		{name: "wildcard includes multiple labels", pattern: "*.a.com.", qname: "y.x.a.com.", matched: true},
		{name: "wildcard excludes root", pattern: "*.a.com.", qname: "a.com.", matched: false},
		{name: "wildcard excludes suffix lookalike", pattern: "*.a.com.", qname: "xa.com.", matched: false},
		{name: "policy and qname retain case", pattern: "API.Example.COM.", qname: "api.EXAMPLE.com.", matched: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := New([]Rule{{DomainName: tt.pattern}})
			_, matched := f.Match(tt.qname)
			if matched != tt.matched {
				t.Errorf("Match(%q) for policy %q = %v, want %v", tt.qname, tt.pattern, matched, tt.matched)
			}
		})
	}
}

func TestDomainMatchReturnsNumericAndRangePorts(t *testing.T) {
	tcp := corev1.ProtocolTCP
	port80 := int32(80)
	port8000 := int32(8000)
	port8100 := int32(8100)
	rule := Rule{
		DomainName: "API.Example.COM.",
		Ports: []policyk8sawsv1.Port{
			{Protocol: &tcp, Port: &port80},
			{Protocol: &tcp, Port: &port8000, EndPort: &port8100},
		},
		Tier:     "Admin",
		Priority: 25,
		Action:   policyk8sawsv1.ClusterNetworkPolicyRuleActionAccept,
	}

	got, matched := New([]Rule{rule}).Match("API.Example.COM.")
	if !matched {
		t.Fatal("expected exact Auto-compatible domain match")
	}
	if len(got.Rule.Ports) != 2 {
		t.Fatalf("matched port count = %d, want numeric port and port range", len(got.Rule.Ports))
	}
	if got.Rule.Ports[0].Protocol == nil || *got.Rule.Ports[0].Protocol != tcp ||
		got.Rule.Ports[0].Port == nil || *got.Rule.Ports[0].Port != port80 ||
		got.Rule.Ports[0].EndPort != nil {
		t.Errorf("numeric port = %#v, want TCP/80 without EndPort", got.Rule.Ports[0])
	}
	if got.Rule.Ports[1].Protocol == nil || *got.Rule.Ports[1].Protocol != tcp ||
		got.Rule.Ports[1].Port == nil || *got.Rule.Ports[1].Port != port8000 ||
		got.Rule.Ports[1].EndPort == nil || *got.Rule.Ports[1].EndPort != port8100 {
		t.Errorf("port range = %#v, want TCP/8000-8100", got.Rule.Ports[1])
	}
	if got.Rule.Priority != 25 || got.Rule.Tier != "Admin" {
		t.Fatalf("matched metadata = tier %q priority %d, want Admin/25", got.Rule.Tier, got.Rule.Priority)
	}
}
