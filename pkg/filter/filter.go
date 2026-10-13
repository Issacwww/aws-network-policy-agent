package filter

import (
	"sort"
	"strings"
	"sync"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
)

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
	name := normalizeDomain(domain)
	for _, rule := range f.rules {
		if domainMatches(normalizeDomain(rule.DomainName), name) {
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
	name := normalizeDomain(domain)
	if name == "" {
		return nil, false
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	pod := f.pods[podIdentifier]
	if pod == nil {
		return nil, false
	}

	var matched []npatypes.L4Rule
	for _, entry := range pod.merged {
		if domainMatches(entry.name, name) {
			matched = appendUnique(matched, entry.rules...)
		}
	}
	return matched, len(matched) > 0
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
	for _, source := range []Source{PolicyEndpointSource, ClusterPolicyEndpointSource} {
		for _, entry := range pod.sources[source] {
			existing, ok := byDomain[entry.name]
			if !ok {
				byDomain[entry.name] = entry
				continue
			}
			existing.rules = appendUnique(existing.rules, entry.rules...)
			byDomain[entry.name] = existing
		}
	}

	names := make([]string, 0, len(byDomain))
	for name := range byDomain {
		names = append(names, name)
	}
	sort.Strings(names)

	pod.merged = pod.merged[:0]
	for _, name := range names {
		pod.merged = append(pod.merged, byDomain[name])
	}
}

func compileRules(source Source, rules []fwrp.EbpfFirewallRules) []domainEntry {
	byDomain := make(map[string]domainEntry)
	for _, rule := range rules {
		name := normalizeDomain(rule.DomainName)
		if name == "" {
			continue
		}
		if source == ClusterPolicyEndpointSource &&
			rule.Action != policyk8sawsv1.ClusterNetworkPolicyRuleActionAccept {
			continue
		}

		priority := rule.Priority
		if source == PolicyEndpointSource {
			priority = utils.PE_PRIORITY
		}

		ports := rule.L4Info
		if len(ports) == 0 {
			ports = []policyk8sawsv1.Port{{}}
		}
		entry := byDomain[name]
		entry.name = name
		entry.wildcard = strings.HasPrefix(name, "*.")
		for _, port := range ports {
			entry.rules = appendUnique(entry.rules, npatypes.L4Rule{
				L4PortProtocolInfo: port,
				Priority:           priority,
			})
		}
		byDomain[name] = entry
	}

	names := make([]string, 0, len(byDomain))
	for name := range byDomain {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]domainEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, byDomain[name])
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

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
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
