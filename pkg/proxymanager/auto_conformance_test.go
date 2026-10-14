package proxymanager

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/filter"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
)

func TestAutoConformanceRedirectMatchesEveryDNSDestination(t *testing.T) {
	rules := newNFTRules(
		netip.MustParseAddrPort("169.254.20.10:50052"),
		OSSNftChainPriority,
	)

	for _, protocol := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		expressions := rules.redirectExpressions(protocol, "eni-test")
		for _, expression := range expressions {
			payload, ok := expression.(*expr.Payload)
			if ok && payload.Base == expr.PayloadBaseNetworkHeader && payload.Offset == 16 && payload.Len == 4 {
				t.Fatal("Auto redirects every selected-veth DNS query and must not match the original destination IP")
			}
		}
	}
}

func TestAutoConformanceHookPrioritySelectors(t *testing.T) {
	if AutoNftChainPriority != -100 {
		t.Fatalf("Auto nft priority = %d, want -100", AutoNftChainPriority)
	}
	if OSSNftChainPriority != -110 {
		t.Fatalf("OSS nft priority = %d, want -110", OSSNftChainPriority)
	}
}

func TestAutoConformanceProxyStartsLazilyAndTracksSelectedPods(t *testing.T) {
	rules := filter.New()
	redirects := &recordingRedirects{}
	proxy := &recordingProxy{}
	manager := newManager(
		logger.Get(),
		rules,
		redirects,
		proxy,
		func(types.NamespacedName) (string, error) { return "eni-test", nil },
		func(string) (string, error) { return "10.0.0.10", nil },
		AutoNftChainPriority,
	)
	manager.setupListener = func(netip.AddrPort) error { return nil }
	pod := npatypes.Pod{NamespacedName: types.NamespacedName{Name: "workload-a", Namespace: "default"}}
	podIdentifier := "workload@default"

	if err := manager.SyncPod(pod, podIdentifier); err != nil {
		t.Fatal(err)
	}
	if redirects.initializeCalls != 0 || proxy.startCalls != 0 {
		t.Fatal("proxy setup must remain lazy until a pod has domain rules")
	}

	rules.SetRules(podIdentifier, filter.PolicyEndpointSource, []fwrp.EbpfFirewallRules{{
		DomainName: "example.com.",
		Priority:   15001,
	}})
	if err := manager.SyncPod(pod, podIdentifier); err != nil {
		t.Fatal(err)
	}
	if redirects.initializeCalls != 1 || proxy.startCalls != 1 || len(redirects.adds) != 1 {
		t.Fatalf(
			"startup = init %d start %d adds %d, want 1/1/1",
			redirects.initializeCalls,
			proxy.startCalls,
			len(redirects.adds),
		)
	}
	if err := manager.SyncPod(pod, podIdentifier); err != nil {
		t.Fatal(err)
	}
	if proxy.startCalls != 1 || len(redirects.adds) != 1 {
		t.Fatal("repeated pod sync must be idempotent")
	}

	rules.DeleteRules(podIdentifier, filter.PolicyEndpointSource)
	if err := manager.SyncPod(pod, podIdentifier); err != nil {
		t.Fatal(err)
	}
	if len(redirects.deletes) != 1 || redirects.deletes[0] != "eni-test" {
		t.Fatalf("redirect deletes = %#v, want eni-test", redirects.deletes)
	}
}

func TestAutoConformanceFailedLazyStartMakesRuntimeHealthFail(t *testing.T) {
	rules := filter.New()
	rules.SetRules("workload@default", filter.PolicyEndpointSource, []fwrp.EbpfFirewallRules{{
		DomainName: "example.com.",
	}})
	manager := newManager(
		logger.Get(),
		rules,
		&recordingRedirects{},
		&recordingProxy{startErr: errors.New("injected startup failure")},
		func(types.NamespacedName) (string, error) { return "eni-test", nil },
		func(string) (string, error) { return "10.0.0.10", nil },
		AutoNftChainPriority,
	)
	manager.setupListener = func(netip.AddrPort) error { return nil }
	err := manager.SyncPod(
		npatypes.Pod{NamespacedName: types.NamespacedName{Name: "workload-a", Namespace: "default"}},
		"workload@default",
	)
	if err == nil {
		t.Fatal("expected injected startup failure")
	}
	if err := manager.HealthCheckDNSProxy(); err == nil {
		t.Fatal("runtime health must fail after a lazy startup failure")
	}
}

func TestAutoConformancePodAttributionIsClearedBeforeRedirectDeletion(t *testing.T) {
	rules := filter.New()
	rules.SetPod("10.0.0.10", "workload@default")
	redirects := &recordingRedirects{deleteErr: errors.New("injected nft delete failure")}
	manager := newManager(
		logger.Get(),
		rules,
		redirects,
		&recordingProxy{},
		func(types.NamespacedName) (string, error) { return "eni-test", nil },
		func(string) (string, error) { return "10.0.0.10", nil },
		AutoNftChainPriority,
	)
	pod := types.NamespacedName{Name: "workload-a", Namespace: "default"}
	manager.podVeth[pod.String()] = "eni-test"
	manager.podIP[pod.String()] = "10.0.0.10"

	if err := manager.RemovePod(pod); !errors.Is(err, redirects.deleteErr) {
		t.Fatalf("RemovePod error = %v, want injected nft error", err)
	}
	if _, exists := rules.PodIdentifier("10.0.0.10"); exists {
		t.Fatal("Auto force cleanup removes Pod-IP attribution even when nft deletion fails")
	}
	if _, exists := manager.podIP[pod.String()]; exists {
		t.Fatal("internal Pod-IP attribution must be removed before nft deletion")
	}
	if manager.podVeth[pod.String()] != "eni-test" {
		t.Fatal("veth rule handle must remain available for a deletion retry")
	}

	redirects.deleteErr = nil
	if err := manager.RemovePod(pod); err != nil {
		t.Fatalf("retry RemovePod: %v", err)
	}
	if _, exists := manager.podVeth[pod.String()]; exists {
		t.Fatal("successful retry must remove the veth rule handle")
	}
}

func TestAutoConformancePEAndCPELifecycleKeepsRedirectUntilLastSource(t *testing.T) {
	rules := filter.New()
	redirects := &recordingRedirects{}
	manager := newManager(
		logger.Get(),
		rules,
		redirects,
		&recordingProxy{},
		func(types.NamespacedName) (string, error) { return "eni-test", nil },
		func(string) (string, error) { return "10.0.0.10", nil },
		AutoNftChainPriority,
	)
	manager.setupListener = func(netip.AddrPort) error { return nil }
	pod := npatypes.Pod{NamespacedName: types.NamespacedName{Name: "workload-a", Namespace: "default"}}
	podIdentifier := "workload@default"
	peRule := []fwrp.EbpfFirewallRules{{DomainName: "pe.example.com.", Priority: 15001}}
	cpeRule := []fwrp.EbpfFirewallRules{{DomainName: "cpe.example.com.", Priority: 10}}

	rules.SetRules(podIdentifier, filter.PolicyEndpointSource, peRule)
	rules.SetRules(podIdentifier, filter.ClusterPolicyEndpointSource, cpeRule)
	if err := manager.SyncPod(pod, podIdentifier); err != nil {
		t.Fatal(err)
	}
	if len(redirects.adds) != 1 {
		t.Fatalf("initial redirect adds = %d, want 1", len(redirects.adds))
	}

	rules.DeleteRules(podIdentifier, filter.PolicyEndpointSource)
	if err := manager.SyncPod(pod, podIdentifier); err != nil {
		t.Fatal(err)
	}
	if len(redirects.deletes) != 0 {
		t.Fatal("redirect must remain while CPE domain rules still select the pod")
	}

	rules.SetRules(podIdentifier, filter.ClusterPolicyEndpointSource, []fwrp.EbpfFirewallRules{{
		DomainName: "modified.example.com.",
		Priority:   20,
	}})
	if err := manager.SyncPod(pod, podIdentifier); err != nil {
		t.Fatal(err)
	}
	if len(redirects.adds) != 1 || len(redirects.deletes) != 0 {
		t.Fatal("modifying the remaining source must retain the existing redirect")
	}

	rules.DeleteRules(podIdentifier, filter.ClusterPolicyEndpointSource)
	if err := manager.SyncPod(pod, podIdentifier); err != nil {
		t.Fatal(err)
	}
	if len(redirects.deletes) != 1 || redirects.deletes[0] != "eni-test" {
		t.Fatalf("final redirect deletes = %#v, want eni-test after the last source is removed", redirects.deletes)
	}
}

type recordingRedirects struct {
	initializeCalls int
	adds            []RedirectRequest
	deletes         []string
	deleteErr       error
}

func (r *recordingRedirects) Initialize() error {
	r.initializeCalls++
	return nil
}

func (r *recordingRedirects) Add(request RedirectRequest) error {
	r.adds = append(r.adds, request)
	return nil
}

func (r *recordingRedirects) Delete(hostVeth string) error {
	r.deletes = append(r.deletes, hostVeth)
	return r.deleteErr
}

func (r *recordingRedirects) Cleanup() error { return nil }

type recordingProxy struct {
	startCalls int
	stopCalls  int
	startErr   error
}

func (p *recordingProxy) Start() error {
	p.startCalls++
	return p.startErr
}

func (p *recordingProxy) Stop() error {
	p.stopCalls++
	return nil
}
