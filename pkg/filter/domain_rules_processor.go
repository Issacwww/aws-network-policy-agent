package filter

import (
	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
)

// ComputeDNSProxyRulesFromEbpfFirewallRulesForPE reproduces Auto's
// per-controller domain and L4 rule conversion.
func ComputeDNSProxyRulesFromEbpfFirewallRulesForPE(
	firewallRules []fwrp.EbpfFirewallRules,
) map[string][]npatypes.L4Rule {
	domainRules := make(map[string][]npatypes.L4Rule)
	for _, rule := range firewallRules {
		if rule.DomainName == "" {
			continue
		}
		ports := rule.L4Info
		if len(ports) == 0 {
			ports = []policyk8sawsv1.Port{{}}
		}
		for _, port := range ports {
			candidate := npatypes.L4Rule{
				L4PortProtocolInfo: port,
				Priority:           rule.Priority,
			}
			domainRules[rule.DomainName] = appendUnique(
				domainRules[rule.DomainName],
				candidate,
			)
		}
	}
	return domainRules
}

// ComputeDNSProxyRulesFromEbpfFirewallRulesForCPE intentionally has the same
// behavior as the PE converter in Auto.
func ComputeDNSProxyRulesFromEbpfFirewallRulesForCPE(
	firewallRules []fwrp.EbpfFirewallRules,
) map[string][]npatypes.L4Rule {
	return ComputeDNSProxyRulesFromEbpfFirewallRulesForPE(firewallRules)
}
