package controllers

import (
	"context"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/aws/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/filter"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/proxymanager"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// These tests pin the --enable-dns-policy gate: a nil proxy manager (flag off) keeps the
// pre-DNS-policy handling of domainName entries, a proxy manager (flag on) uses Auto's.

func domainPolicyEndpoint() *policyk8sawsv1.PolicyEndpoint {
	protocolTCP := corev1.ProtocolTCP
	var port443 int32 = 443
	return &policyk8sawsv1.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "domains-abcde", Namespace: "ns"},
		Spec: policyk8sawsv1.PolicyEndpointSpec{
			PodSelector:  &metav1.LabelSelector{},
			PolicyRef:    policyk8sawsv1.PolicyReference{Name: "domains", Namespace: "ns"},
			PodIsolation: []networking.PolicyType{networking.PolicyTypeEgress},
			Egress: []policyk8sawsv1.EndpointInfo{
				{
					DomainName: "aws.com",
					Ports:      []policyk8sawsv1.Port{{Protocol: &protocolTCP, Port: &port443}},
				},
			},
		},
	}
}

func TestDerivePolicyEndpointDomainRules_DNSPolicyFlag(t *testing.T) {
	pe := domainPolicyEndpoint()
	podIdentifier := "client@ns"

	for _, tc := range []struct {
		name               string
		proxyManager       proxymanager.ProxyManager
		wantEgressRules    []fwrp.EbpfFirewallRules
		wantEgressIsolated bool
	}{
		{
			name:               "flag off skips the domain entry and isolates egress",
			proxyManager:       nil,
			wantEgressRules:    nil,
			wantEgressIsolated: true,
		},
		{
			name:         "flag on adds the domain entry as a namespace tier rule",
			proxyManager: &proxymanager.ProxyManagerMock{},
			wantEgressRules: []fwrp.EbpfFirewallRules{{
				Priority:   utils.PE_PRIORITY*10 + 1,
				DomainName: "aws.com",
				L4Info:     pe.Spec.Egress[0].Ports,
			}},
			wantEgressIsolated: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockClient := mock_client.NewMockClient(ctrl)
			mockClient.EXPECT().Get(gomock.Any(), types.NamespacedName{Name: pe.Name, Namespace: pe.Namespace}, gomock.Any()).DoAndReturn(
				func(ctx context.Context, key types.NamespacedName, currentPE *policyk8sawsv1.PolicyEndpoint, opts ...client.GetOption) error {
					*currentPE = *pe
					return nil
				},
			).AnyTimes()

			r := NewPolicyEndpointsReconciler(mockClient, "", &ebpf.MockBpfClient{}, false, tc.proxyManager)
			r.podIdentifierToPolicyEndpointMap.Store(podIdentifier, []string{pe.Name})

			_, egressRules, _, isEgressIsolated, err := r.deriveIngressAndEgressFirewallRules(context.Background(), podIdentifier, pe.Namespace, pe.Name, false)
			assert.NoError(t, err)
			assert.Equal(t, tc.wantEgressRules, egressRules)
			assert.Equal(t, tc.wantEgressIsolated, isEgressIsolated)
		})
	}
}

func TestDeriveClusterPolicyEndpointDomainRules_DNSPolicyFlag(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port443 int32 = 443
	cpe := &policyk8sawsv1.ClusterPolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "guardrail-abcde"},
		Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
			PolicyRef: policyk8sawsv1.ClusterPolicyReference{Name: "guardrail"},
			Tier:      policyk8sawsv1.AdminTier,
			Priority:  20,
			Egress: []policyk8sawsv1.ClusterEndpointInfo{
				{
					Action:     policyk8sawsv1.ClusterNetworkPolicyRuleActionAccept,
					DomainName: "aws.com",
					Ports:      []policyk8sawsv1.Port{{Protocol: &protocolTCP, Port: &port443}},
				},
			},
		},
	}
	podIdentifier := "client@ns"

	for _, tc := range []struct {
		name            string
		proxyManager    proxymanager.ProxyManager
		wantEgressRules []fwrp.EbpfFirewallRules
	}{
		{
			name:            "flag off skips the domain entry",
			proxyManager:    nil,
			wantEgressRules: nil,
		},
		{
			name:         "flag on keeps the domain entry with the policy priority",
			proxyManager: &proxymanager.ProxyManagerMock{},
			wantEgressRules: []fwrp.EbpfFirewallRules{{
				Priority:   20,
				Action:     policyk8sawsv1.ClusterNetworkPolicyRuleActionAccept,
				DomainName: "aws.com",
				L4Info:     cpe.Spec.Egress[0].Ports,
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockClient := mock_client.NewMockClient(ctrl)
			mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error {
					if cpObj, ok := obj.(*policyk8sawsv1.ClusterPolicyEndpoint); ok {
						*cpObj = *cpe
					}
					return nil
				},
			).AnyTimes()

			r := NewClusterPolicyEndpointsReconciler(mockClient, "", &ebpf.MockBpfClient{}, tc.proxyManager)
			r.podIdentifierToClusterPolicyEndpointMap.Store(podIdentifier, []string{cpe.Name})

			_, egressRules, err := r.deriveClusterPolicyIngressAndEgressFirewallRules(context.Background(), podIdentifier, cpe.Name, false)
			assert.NoError(t, err)
			assert.Equal(t, tc.wantEgressRules, egressRules)
		})
	}
}

func TestConfigureBPFProbes_DNSPolicyFlagOffLeavesDomainStoreUntouched(t *testing.T) {
	pod := npatypes.Pod{NamespacedName: types.NamespacedName{Name: "client", Namespace: "ns"}}
	podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
	egressRules := []fwrp.EbpfFirewallRules{{IPCidr: "10.0.0.0/8"}}

	pe := NewPolicyEndpointsReconciler(nil, "", &ebpf.MockBpfClient{}, false, nil)
	assert.NoError(t, pe.configureeBPFProbes(context.Background(), podIdentifier, []npatypes.Pod{pod}, nil, egressRules))
	cpe := NewClusterPolicyEndpointsReconciler(nil, "", &ebpf.MockBpfClient{}, nil)
	assert.NoError(t, cpe.configureClusterPolicyBPFProbes(podIdentifier, []npatypes.Pod{pod}, nil, egressRules))
	cpe.updateClusterPolicyDomainRules(pod, podIdentifier, nil)

	assert.False(t, filter.HasAnyDomainRules(podIdentifier))
}

// recordingRemoveProxy records DNS redirection removals.
type recordingRemoveProxy struct {
	proxymanager.ProxyManagerMock
	removedPods []types.NamespacedName
}

func (p *recordingRemoveProxy) RemoveDNSRedirectionRulesForPod(pod types.NamespacedName, podIdentifier string) error {
	p.removedPods = append(p.removedPods, pod)
	return nil
}

// When the last cluster policy selecting a pod is deleted, OSS takes the "nothing selects this
// identifier" branch; Auto's DNS cleanup must still run there.
func TestCleanupClusterPolicyPod_LastPolicyRemovesDomainRules(t *testing.T) {
	pod := npatypes.Pod{NamespacedName: types.NamespacedName{Name: "client", Namespace: "cleanup-ns"}}
	podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
	t.Cleanup(func() { filter.DeleteClusterPolicyEndpointDomains(podIdentifier) })
	assert.NoError(t, filter.SetClusterPolicyEndpointDomains(podIdentifier, []fwrp.EbpfFirewallRules{{DomainName: "aws.com."}}))

	proxy := &recordingRemoveProxy{}
	r := NewClusterPolicyEndpointsReconciler(nil, "", &ebpf.MockBpfClient{}, proxy)
	assert.NoError(t, r.cleanupClusterPolicyPod(context.Background(), pod, "guardrail-abcde", true))

	assert.False(t, filter.HasClusterPolicyEndpointDomains(podIdentifier))
	assert.Equal(t, []types.NamespacedName{pod.NamespacedName}, proxy.removedPods)
}
