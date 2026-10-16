package filter

import (
	"fmt"
	"strings"
	"sync"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
)

var BpfClient ebpf.BpfClient
var IsIPv6 bool

var defaultStore = New()

func DefaultStore() *Filter {
	return defaultStore
}

type PodFilter struct {
	store         *Filter
	podIdentifier string
}

func (f *PodFilter) IsAllowed(domain string) (bool, []npatypes.L4Rule) {
	rules, matched := f.store.MatchPod(f.podIdentifier, domain)
	return matched, rules
}

func SetPolicyEndpointDomains(podIdentifier string, rules []fwrp.EbpfFirewallRules) error {
	defaultStore.SetRules(podIdentifier, PolicyEndpointSource, rules)
	return nil
}

func DeletePolicyEndpointDomains(podIdentifier string) {
	defaultStore.DeleteRules(podIdentifier, PolicyEndpointSource)
}

func HasPolicyEndpointDomains(podIdentifier string) bool {
	defaultStore.mu.RLock()
	defer defaultStore.mu.RUnlock()
	pod := defaultStore.pods[podIdentifier]
	return pod != nil && len(pod.sources[PolicyEndpointSource]) > 0
}

func SetClusterPolicyEndpointDomains(podIdentifier string, rules []fwrp.EbpfFirewallRules) error {
	defaultStore.SetRules(podIdentifier, ClusterPolicyEndpointSource, rules)
	return nil
}

func DeleteClusterPolicyEndpointDomains(podIdentifier string) {
	defaultStore.DeleteRules(podIdentifier, ClusterPolicyEndpointSource)
}

func HasClusterPolicyEndpointDomains(podIdentifier string) bool {
	defaultStore.mu.RLock()
	defer defaultStore.mu.RUnlock()
	pod := defaultStore.pods[podIdentifier]
	return pod != nil && len(pod.sources[ClusterPolicyEndpointSource]) > 0
}

func HasAnyDomainRules(podIdentifier string) bool {
	return defaultStore.HasAnyDomainRules(podIdentifier)
}

func GetIPFilter(podIdentifier string) (*PodFilter, bool) {
	if !defaultStore.HasAnyDomainRules(podIdentifier) {
		return nil, false
	}
	return &PodFilter{store: defaultStore, podIdentifier: podIdentifier}, true
}

func SetPodIPToPodId(podIP, podIdentifier string) {
	defaultStore.SetPod(podIP, podIdentifier)
}

func GetPodId(podIP string) (string, error) {
	podIdentifier, ok := defaultStore.PodIdentifier(podIP)
	if !ok {
		return "", fmt.Errorf("podIP %s not found in local mappings", podIP)
	}
	return podIdentifier, nil
}

func DeletePodIPToPodIdEntry(podIP string) {
	defaultStore.DeletePod(podIP)
}

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

type Source string

const (
	PolicyEndpointSource        Source = "policy-endpoint"
	ClusterPolicyEndpointSource Source = "cluster-policy-endpoint"
)

type Store interface {
	SetRules(string, Source, []fwrp.EbpfFirewallRules)
	DeleteRules(string, Source)
	HasAnyDomainRules(string) bool
	MatchPod(string, string) ([]npatypes.L4Rule, bool)
	SetPod(string, string)
	DeletePod(string)
	PodIdentifier(string) (string, bool)
}

type domainEntry struct {
	name     string
	wildcard bool
	rules    []npatypes.L4Rule
}

type podRules struct {
	sources map[Source][]domainEntry
	merged  []domainEntry
}

type Filter struct {
	mu        sync.RWMutex
	rules     []Rule
	pods      map[string]*podRules
	podByAddr map[string]string
}

func New(ruleSets ...[]Rule) *Filter {
	filter := &Filter{
		pods:      make(map[string]*podRules),
		podByAddr: make(map[string]string),
	}
	if len(ruleSets) > 0 {
		filter.rules = append([]Rule(nil), ruleSets[0]...)
	}
	return filter
}

func (f *Filter) Match(domain string) (MatchResult, bool) {
	name := domain
	for _, rule := range f.rules {
		if !strings.HasPrefix(rule.DomainName, "*.") && rule.DomainName == name {
			return MatchResult{Rule: rule}, true
		}
	}
	for _, rule := range f.rules {
		if strings.HasPrefix(rule.DomainName, "*.") && domainMatches(rule.DomainName, name) {
			return MatchResult{Rule: rule}, true
		}
	}
	return MatchResult{}, false
}

func (f *Filter) SetRules(podIdentifier string, source Source, rules []fwrp.EbpfFirewallRules) {
	entries := compileRules(source, rules)

	f.mu.Lock()
	defer f.mu.Unlock()

	pod := f.pods[podIdentifier]
	if pod == nil {
		pod = &podRules{sources: make(map[Source][]domainEntry)}
		f.pods[podIdentifier] = pod
	}
	if len(entries) == 0 {
		delete(pod.sources, source)
	} else {
		pod.sources[source] = entries
	}
	f.rebuildLocked(podIdentifier, pod)
}

func (f *Filter) DeleteRules(podIdentifier string, source Source) {
	f.mu.Lock()
	defer f.mu.Unlock()

	pod := f.pods[podIdentifier]
	if pod == nil {
		return
	}
	delete(pod.sources, source)
	f.rebuildLocked(podIdentifier, pod)
}

func (f *Filter) HasAnyDomainRules(podIdentifier string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	pod := f.pods[podIdentifier]
	return pod != nil && len(pod.merged) > 0
}

func (f *Filter) MatchPod(podIdentifier, domain string) ([]npatypes.L4Rule, bool) {
	name := domain
	if name == "" {
		return nil, false
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	pod := f.pods[podIdentifier]
	if pod == nil {
		return nil, false
	}

	for _, entry := range pod.merged {
		if !entry.wildcard && entry.name == name {
			return entry.rules, true
		}
	}
	for _, entry := range pod.merged {
		if entry.wildcard && domainMatches(entry.name, name) {
			return entry.rules, true
		}
	}
	return nil, false
}

func (f *Filter) SetPod(podIP, podIdentifier string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.podByAddr[podIP] = podIdentifier
}

func (f *Filter) DeletePod(podIP string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.podByAddr, podIP)
}

func (f *Filter) PodIdentifier(podIP string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	podIdentifier, ok := f.podByAddr[podIP]
	return podIdentifier, ok
}

func (f *Filter) rebuildLocked(podIdentifier string, pod *podRules) {
	if len(pod.sources) == 0 {
		delete(f.pods, podIdentifier)
		return
	}

	byDomain := make(map[string]domainEntry)
	for _, entries := range pod.sources {
		for _, entry := range entries {
			existing, ok := byDomain[entry.name]
			if !ok {
				byDomain[entry.name] = entry
				continue
			}
			existing.rules = append(existing.rules, entry.rules...)
			byDomain[entry.name] = existing
		}
	}

	pod.merged = pod.merged[:0]
	for _, entry := range byDomain {
		pod.merged = append(pod.merged, entry)
	}
}

func compileRules(source Source, rules []fwrp.EbpfFirewallRules) []domainEntry {
	var byDomain map[string][]npatypes.L4Rule
	if source == PolicyEndpointSource {
		byDomain = ComputeDNSProxyRulesFromEbpfFirewallRulesForPE(rules)
	} else {
		byDomain = ComputeDNSProxyRulesFromEbpfFirewallRulesForCPE(rules)
	}

	entries := make([]domainEntry, 0, len(byDomain))
	for name, ruleSet := range byDomain {
		entries = append(entries, domainEntry{
			name:     name,
			wildcard: strings.HasPrefix(name, "*."),
			rules:    ruleSet,
		})
	}
	return entries
}

func appendUnique(existing []npatypes.L4Rule, additions ...npatypes.L4Rule) []npatypes.L4Rule {
	for _, addition := range additions {
		duplicate := false
		for _, current := range existing {
			if current.Equal(addition) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			existing = append(existing, addition)
		}
	}
	return existing
}

func domainMatches(pattern, domain string) bool {
	if pattern == "" || domain == "" {
		return false
	}
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == domain
	}
	suffix := strings.TrimPrefix(pattern, "*.")
	return suffix != "" && domain != suffix && strings.HasSuffix(domain, "."+suffix)
}

var _ Store = (*Filter)(nil)
