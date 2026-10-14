package fwruleprocessor

import "testing"

func TestIPCacheCandidateOnlyContributesAllow(t *testing.T) {
	tests := []struct {
		name       string
		candidates []DNSCandidate
		want       DNSVerdict
	}{
		{
			name: "ipcache hit contributes allow",
			candidates: []DNSCandidate{{
				Source: DNSCandidateIPCache, Tier: DNSTierAdmin, Priority: 20, Action: DNSActionAllow, Matched: true,
			}},
			want: DNSVerdictAllow,
		},
		{
			name: "ipcache cannot express deny",
			candidates: []DNSCandidate{{
				Source: DNSCandidateIPCache, Tier: DNSTierAdmin, Priority: 20, Action: DNSActionDrop, Matched: true,
			}},
			want: DNSVerdictNoDecision,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EvaluateDNSCandidates(tt.candidates); got != tt.want {
				t.Errorf("verdict = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDNSTierOrdering(t *testing.T) {
	tests := []struct {
		name       string
		candidates []DNSCandidate
		want       DNSVerdict
	}{
		{
			name: "Admin same priority Deny precedes Accept",
			candidates: []DNSCandidate{
				{Source: DNSCandidateIPCache, Tier: DNSTierAdmin, Priority: 10, Action: DNSActionAllow, Matched: true},
				{Source: DNSCandidateCIDR, Tier: DNSTierAdmin, Priority: 10, Action: DNSActionDrop, Matched: true},
			},
			want: DNSVerdictDrop,
		},
		{
			name: "Admin terminal allow precedes namespace deny",
			candidates: []DNSCandidate{
				{Source: DNSCandidateIPCache, Tier: DNSTierAdmin, Priority: 10, Action: DNSActionAllow, Matched: true},
				{Source: DNSCandidateNamespace, Tier: DNSTierNamespace, Priority: 0, Action: DNSActionDrop, Matched: true},
			},
			want: DNSVerdictAllow,
		},
		{
			name: "namespace deny precedes Baseline allow",
			candidates: []DNSCandidate{
				{Source: DNSCandidateNamespace, Tier: DNSTierNamespace, Priority: 0, Action: DNSActionDrop, Matched: true},
				{Source: DNSCandidateIPCache, Tier: DNSTierBaseline, Priority: 10, Action: DNSActionAllow, Matched: true},
			},
			want: DNSVerdictDrop,
		},
		{
			name: "pod default applies after all policy tiers",
			candidates: []DNSCandidate{
				{Source: DNSCandidateCIDR, Tier: DNSTierPodDefault, Priority: 0, Action: DNSActionDrop, Matched: true},
			},
			want: DNSVerdictDrop,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EvaluateDNSCandidates(tt.candidates); got != tt.want {
				t.Errorf("verdict = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPriorityEncodingRegressions(t *testing.T) {
	t.Run("Auto p50 domain Accept overrides Admin p10 CIDR Deny after raw priority decode", func(t *testing.T) {
		if got := EncodeDNSPriority(DNSTierAdmin, 10, DNSActionDrop); got != 100 {
			t.Errorf("Admin p10 Deny encoded priority = %d, want 100", got)
		}
		domainPriority := DecodeAutoIPCachePriority(50)
		if domainPriority != 5 {
			t.Fatalf("Auto raw p50 domain priority decodes to %d, want 5", domainPriority)
		}
		got := EvaluateDNSCandidates([]DNSCandidate{
			{Source: DNSCandidateIPCache, Tier: DNSTierAdmin, Priority: domainPriority, Action: DNSActionAllow, Matched: true},
			{Source: DNSCandidateCIDR, Tier: DNSTierAdmin, Priority: 10, Action: DNSActionDrop, Matched: true},
		})
		if got != DNSVerdictAllow {
			t.Errorf("verdict = %v, want ALLOW matching Auto's raw p50 to effective p5 decode", got)
		}
	})

	t.Run("Baseline p10 domain Accept does not override namespace deny-all", func(t *testing.T) {
		if got := EncodeDNSPriority(DNSTierBaseline, 10, DNSActionAllow); got != 20101 {
			t.Errorf("Baseline p10 Accept encoded priority = %d, want 20101", got)
		}
		got := EvaluateDNSCandidates([]DNSCandidate{
			{Source: DNSCandidateIPCache, Tier: DNSTierBaseline, Priority: 10, Action: DNSActionAllow, Matched: true},
			{Source: DNSCandidateNamespace, Tier: DNSTierNamespace, Priority: 0, Action: DNSActionDrop, Matched: true},
		})
		if got != DNSVerdictDrop {
			t.Errorf("verdict = %v, want DROP from namespace NetworkPolicy deny-all", got)
		}
	})
}
