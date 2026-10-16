package controllers

import (
	"context"
	"testing"

	policyendpoint "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/aws/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/golang/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestPolicyEndpointPureDomainRuleIsDerived(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := mock_client.NewMockClient(ctrl)
	reconciler := NewPolicyEndpointsReconciler(mockClient, "", &ebpf.MockBpfClient{}, false)
	reconciler.podIdentifierToPolicyEndpointMap.Store("pod-a@ns-a", []string{"pe-a"})
	pe := policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "pe-a", Namespace: "ns-a"},
		Spec: policyendpoint.PolicyEndpointSpec{
			Egress: []policyendpoint.EndpointInfo{{DomainName: "api.example.com"}},
		},
	}
	mockClient.EXPECT().Get(gomock.Any(), types.NamespacedName{Name: "pe-a", Namespace: "ns-a"}, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ types.NamespacedName, current *policyendpoint.PolicyEndpoint, _ ...client.GetOption) error {
			*current = pe
			return nil
		})

	_, egress, _, _, err := reconciler.deriveIngressAndEgressFirewallRules(
		context.Background(), "pod-a@ns-a", "ns-a", "", false,
	)
	if err != nil {
		t.Fatalf("derive PE domain rule: %v", err)
	}
	if len(egress) != 1 {
		t.Fatalf("derived egress rule count = %d, want 1 domain-only rule", len(egress))
	}
	if egress[0].DomainName != "api.example.com" || egress[0].IPCidr != "" {
		t.Fatalf("derived rule = %#v, want domain-only api.example.com", egress[0])
	}
}

func TestClusterPolicyEndpointPureAcceptDomainRuleIsDerived(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := mock_client.NewMockClient(ctrl)
	reconciler := NewClusterPolicyEndpointsReconciler(mockClient, "", &ebpf.MockBpfClient{})
	reconciler.podIdentifierToClusterPolicyEndpointMap.Store("pod-a@ns-a", []string{"cpe-a"})
	cpe := policyendpoint.ClusterPolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "cpe-a"},
		Spec: policyendpoint.ClusterPolicyEndpointSpec{
			Tier:     policyendpoint.BaselineTier,
			Priority: 25,
			Egress: []policyendpoint.ClusterEndpointInfo{{
				DomainName: "api.example.com",
				Action:     policyendpoint.ClusterNetworkPolicyRuleActionAccept,
			}},
		},
	}
	mockClient.EXPECT().Get(gomock.Any(), types.NamespacedName{Name: "cpe-a"}, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ types.NamespacedName, current *policyendpoint.ClusterPolicyEndpoint, _ ...client.GetOption) error {
			*current = cpe
			return nil
		})

	_, egress, err := reconciler.deriveClusterPolicyIngressAndEgressFirewallRules(
		context.Background(), "pod-a@ns-a", "", false,
	)
	if err != nil {
		t.Fatalf("derive CPE domain rule: %v", err)
	}
	if len(egress) != 1 {
		t.Fatalf("derived egress rule count = %d, want 1 domain-only rule", len(egress))
	}
	if egress[0].DomainName != "api.example.com" || egress[0].IPCidr != "" {
		t.Fatalf("derived rule = %#v, want domain-only api.example.com", egress[0])
	}
	if egress[0].Priority != 2025 || egress[0].Action != policyendpoint.ClusterNetworkPolicyRuleActionAccept {
		t.Fatalf("derived tier metadata = priority %d action %q, want Baseline-encoded 2025/Accept", egress[0].Priority, egress[0].Action)
	}
}
