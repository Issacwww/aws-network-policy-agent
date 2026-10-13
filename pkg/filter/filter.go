package filter

import policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"

type Rule struct {
	DomainName string
	Ports      []policyk8sawsv1.Port
	Action     policyk8sawsv1.ClusterNetworkPolicyRuleAction
	Tier       string
	Priority   int
}

type MatchResult struct {
	Rule Rule
}

type Filter struct{}

func New([]Rule) *Filter {
	return &Filter{}
}

func (f *Filter) Match(string) (MatchResult, bool) {
	return MatchResult{}, false
}
