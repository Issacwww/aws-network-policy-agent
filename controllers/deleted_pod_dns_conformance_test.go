package controllers

import (
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/filter"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/proxymanager"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"k8s.io/apimachinery/pkg/types"
)

type deletedPodBPFClient struct {
	ebpf.MockBpfClient
	deletedPod  types.NamespacedName
	attachCalls []types.NamespacedName
}

func (m *deletedPodBPFClient) AttacheBPFProbes(
	pod types.NamespacedName,
	podIdentifier string,
	numInterfaces int,
) error {
	m.attachCalls = append(m.attachCalls, pod)
	if pod == m.deletedPod {
		return ebpf.ErrPodDeleted
	}
	return m.MockBpfClient.AttacheBPFProbes(pod, podIdentifier, numInterfaces)
}

type recordingDNSProxy struct {
	syncedPods []types.NamespacedName
}

func (p *recordingDNSProxy) SyncPod(pod npatypes.Pod, podIdentifier string) error {
	p.syncedPods = append(p.syncedPods, pod.NamespacedName)
	return nil
}

func (p *recordingDNSProxy) RemovePod(types.NamespacedName) error { return nil }
func (p *recordingDNSProxy) HealthCheckDNSProxy() error           { return nil }
func (p *recordingDNSProxy) Stop() error                          { return nil }

func TestAutoConformanceDeletedPodSkipsDNSSetupAndContinues(t *testing.T) {
	deletedPod := npatypes.Pod{NamespacedName: types.NamespacedName{Name: "workload-deleted", Namespace: "default"}}
	livePod := npatypes.Pod{NamespacedName: types.NamespacedName{Name: "workload-live", Namespace: "default"}}
	podIdentifier := utils.GetPodIdentifier(deletedPod.Name, deletedPod.Namespace)
	domainRules := []fwrp.EbpfFirewallRules{{DomainName: "example.com."}}

	for _, controller := range []string{"PolicyEndpoint", "ClusterPolicyEndpoint"} {
		t.Run(controller, func(t *testing.T) {
			rules := filter.New()
			bpfClient := &deletedPodBPFClient{deletedPod: deletedPod.NamespacedName}
			proxy := &recordingDNSProxy{}
			dependencies := DNSPolicyDependencies{Filter: rules, Proxy: proxy}

			var err error
			if controller == "PolicyEndpoint" {
				reconciler := NewPolicyEndpointsReconciler(nil, "", bpfClient, false, dependencies)
				err = reconciler.configureeBPFProbes(
					t.Context(), podIdentifier, []npatypes.Pod{deletedPod, livePod}, nil, domainRules,
				)
			} else {
				reconciler := NewClusterPolicyEndpointsReconciler(nil, "", bpfClient, dependencies)
				err = reconciler.configureClusterPolicyBPFProbes(
					podIdentifier, []npatypes.Pod{deletedPod, livePod}, nil, domainRules,
				)
			}
			if err != nil {
				t.Fatalf("configure probes: %v", err)
			}
			if len(bpfClient.attachCalls) != 2 {
				t.Fatalf("attach calls = %#v, want deleted and live pods", bpfClient.attachCalls)
			}
			if len(proxy.syncedPods) != 1 || proxy.syncedPods[0] != livePod.NamespacedName {
				t.Fatalf("DNS sync pods = %#v, want only %s", proxy.syncedPods, livePod.NamespacedName)
			}
		})
	}
}

var _ proxymanager.ProxyManager = (*recordingDNSProxy)(nil)
