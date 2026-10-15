package proxymanager

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/filter"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/google/nftables"
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
	if err := manager.HealthCheckDNSProxy(); err != nil {
		t.Fatalf("health before the first lazy start = %v, want healthy", err)
	}
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

func TestAutoConformanceHealthRetriesThreeTimesAndUsesListenerPortPlusOne(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	healthPort := listener.Addr().(*net.TCPAddr).Port
	if healthPort <= 1 {
		t.Fatalf("unexpected health port %d", healthPort)
	}

	var calls atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Shutdown(context.Background())
	})

	coreDNS := newCoreDNSServer(
		logger.Get(),
		&ebpf.MockBpfClient{},
		false,
		netip.MustParseAddrPort("10.100.0.10:53"),
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(healthPort-1)),
	)
	manager := newManager(
		logger.Get(),
		filter.New(),
		&recordingRedirects{},
		coreDNS,
		func(types.NamespacedName) (string, error) { return "eni-test", nil },
		func(string) (string, error) { return "10.0.0.10", nil },
		AutoNftChainPriority,
	)
	manager.started = true

	if err := manager.HealthCheckDNSProxy(); err != nil {
		t.Fatalf("health retry: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("health attempts = %d, want 3", got)
	}
	if got := coreDNS.healthAddress(); got != listener.Addr().String() {
		t.Fatalf("health address = %q, want %q", got, listener.Addr())
	}
}

func TestAutoConformanceFailedProxyStartCanRetry(t *testing.T) {
	rules := filter.New()
	rules.SetRules("workload@default", filter.PolicyEndpointSource, []fwrp.EbpfFirewallRules{{
		DomainName: "example.com.",
	}})
	redirects := &recordingRedirects{}
	proxy := &recordingProxy{startErr: errors.New("injected startup failure")}
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
	pod := npatypes.Pod{
		NamespacedName: types.NamespacedName{Name: "workload-a", Namespace: "default"},
		PodIP:          "10.0.0.10",
	}

	if err := manager.SyncPod(pod, "workload@default"); err == nil {
		t.Fatal("expected injected startup failure")
	}
	if redirects.initializeCalls != 1 || proxy.startCalls != 1 {
		t.Fatalf("first start = init %d proxy %d, want 1/1", redirects.initializeCalls, proxy.startCalls)
	}

	proxy.startErr = nil
	if err := manager.SyncPod(pod, "workload@default"); err != nil {
		t.Fatalf("retry SyncPod: %v", err)
	}
	if redirects.initializeCalls != 1 || proxy.startCalls != 2 || len(redirects.adds) != 1 {
		t.Fatalf(
			"retry = init %d proxy %d adds %d, want 1/2/1",
			redirects.initializeCalls,
			proxy.startCalls,
			len(redirects.adds),
		)
	}
	if err := manager.HealthCheckDNSProxy(); err != nil {
		t.Fatalf("health after successful retry: %v", err)
	}
}

func TestAutoConformanceIPv6ListenerAndRedirectFamily(t *testing.T) {
	proxyManager, err := New(
		logger.Get(),
		filter.New(),
		&ebpf.MockBpfClient{},
		netip.MustParseAddrPort("[2001:db8::53]:53"),
		true,
		AutoNftChainPriority,
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	manager := proxyManager.(*manager)
	server := manager.proxy.(*coreDNSServer)
	if got := server.listener.String(); got != IPv6ListenerAddress {
		t.Fatalf("IPv6 listener = %q, want %q", got, IPv6ListenerAddress)
	}
	if got := server.healthAddress(); got != "[fd00::53]:50053" {
		t.Fatalf("IPv6 health address = %q, want [fd00::53]:50053", got)
	}

	redirects := manager.redirects.(*nftRules)
	expressions := redirects.redirectExpressions(unix.IPPROTO_UDP, "eni-test")
	var nat *expr.NAT
	for _, expression := range expressions {
		if candidate, ok := expression.(*expr.NAT); ok {
			nat = candidate
			break
		}
	}
	if nat == nil {
		t.Fatal("IPv6 redirect expressions have no DNAT operation")
	}
	if nat.Family != uint32(nftables.TableFamilyIPv6) {
		t.Fatalf("IPv6 DNAT family = %d, want %d", nat.Family, nftables.TableFamilyIPv6)
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

func TestAutoConformanceStopCleansRedirectsAndRunningProxy(t *testing.T) {
	cleanupErr := errors.New("injected nft cleanup failure")
	stopErr := errors.New("injected proxy stop failure")
	redirects := &recordingRedirects{cleanupErr: cleanupErr}
	proxy := &recordingProxy{stopErr: stopErr}
	manager := newManager(
		logger.Get(),
		filter.New(),
		redirects,
		proxy,
		func(types.NamespacedName) (string, error) { return "", nil },
		func(string) (string, error) { return "", nil },
		AutoNftChainPriority,
	)
	manager.started = true

	err := manager.Stop()
	if !errors.Is(err, cleanupErr) || !errors.Is(err, stopErr) {
		t.Fatalf("Stop error = %v, want joined cleanup and proxy errors", err)
	}
	if redirects.cleanupCalls != 1 || proxy.stopCalls != 1 {
		t.Fatalf("stop calls = cleanup %d proxy %d, want 1/1", redirects.cleanupCalls, proxy.stopCalls)
	}
	if manager.started {
		t.Fatal("manager must clear its started state after Stop")
	}
}

type recordingRedirects struct {
	initializeCalls int
	adds            []RedirectRequest
	deletes         []string
	deleteErr       error
	cleanupCalls    int
	cleanupErr      error
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

func (r *recordingRedirects) Cleanup() error {
	r.cleanupCalls++
	return r.cleanupErr
}

type recordingProxy struct {
	startCalls int
	stopCalls  int
	startErr   error
	stopErr    error
}

func (p *recordingProxy) Start() error {
	p.startCalls++
	return p.startErr
}

func (p *recordingProxy) Stop() error {
	p.stopCalls++
	return p.stopErr
}
