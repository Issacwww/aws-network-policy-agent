package proxymanager

import "testing"

func TestOnlyDomainPolicyPodsAreRedirectedWhenFeatureEnabled(t *testing.T) {
	tests := []struct {
		name      string
		input     SyncInput
		hasDomain bool
		wantAdds  int
	}{
		{
			name:      "domain policy pod",
			input:     SyncInput{FeatureEnabled: true, PodIdentifier: "pod-a@ns-a", HostVeth: "eni-a"},
			hasDomain: true,
			wantAdds:  1,
		},
		{
			name:     "CIDR-only pod",
			input:    SyncInput{FeatureEnabled: true, PodIdentifier: "pod-a@ns-a", HostVeth: "eni-a"},
			wantAdds: 0,
		},
		{
			name:      "feature disabled",
			input:     SyncInput{FeatureEnabled: false, PodIdentifier: "pod-a@ns-a", HostVeth: "eni-a"},
			hasDomain: true,
			wantAdds:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := &fakeDomainRuleStore{hasDomain: tt.hasDomain}
			redirect := &fakeRedirectRuleManager{}
			if err := SyncPod(tt.input, rules, redirect); err != nil {
				t.Fatalf("SyncPod: %v", err)
			}
			if tt.input.FeatureEnabled &&
				(len(rules.queries) != 1 || rules.queries[0] != tt.input.PodIdentifier) {
				t.Errorf("domain-rule queries = %#v, want exactly [%q]", rules.queries, tt.input.PodIdentifier)
			}
			if len(redirect.adds) != tt.wantAdds {
				t.Errorf("redirect add count = %d, want %d", len(redirect.adds), tt.wantAdds)
			}
		})
	}
}

func TestRedirectRunsBeforeKubeProxyDNATAndPreservesDestination(t *testing.T) {
	input := SyncInput{FeatureEnabled: true, PodIdentifier: "domain@ns-a", HostVeth: "eni-domain"}
	redirect := &fakeRedirectRuleManager{}
	if err := SyncPod(input, &fakeDomainRuleStore{hasDomain: true}, redirect); err != nil {
		t.Fatalf("SyncPod: %v", err)
	}
	if len(redirect.adds) != 1 {
		t.Fatalf("redirect add count = %d, want 1", len(redirect.adds))
	}
	got := redirect.adds[0]
	if got.HostVeth != input.HostVeth {
		t.Errorf("redirect host veth = %q, want %q", got.HostVeth, input.HostVeth)
	}
	if !got.PreserveOriginalDestination {
		t.Error("DNS redirect must preserve the original resolver destination")
	}
	if got.HookPriority >= -100 {
		t.Errorf("redirect hook priority = %d, want earlier than kube-proxy DNAT priority -100", got.HookPriority)
	}
}

type fakeDomainRuleStore struct {
	hasDomain bool
	queries   []string
}

func (s *fakeDomainRuleStore) HasAnyDomainRules(podIdentifier string) bool {
	s.queries = append(s.queries, podIdentifier)
	return s.hasDomain
}

type fakeRedirectRuleManager struct {
	adds []RedirectRequest
}

func (m *fakeRedirectRuleManager) Add(request RedirectRequest) error {
	m.adds = append(m.adds, request)
	return nil
}
