package fwruleprocessor

import (
	"net"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

// An invalid CIDR string passes the ClusterNetworkPolicy CRD validation (for example a literal
// "<kube-dns ClusterIP>/32" left in a manifest). It must be skipped, not dereferenced, so the
// remaining rules of the selected pods are still programmed.

func trieKeyFor(t *testing.T, cidr string) string {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	assert.NoError(t, err)
	return string(utils.ComputeTrieKey(*ipNet, false))
}

func TestComputeClusterPolicyMapEntries_InvalidCIDRIsSkipped(t *testing.T) {
	protocolUDP := corev1.ProtocolUDP
	protocolTCP := corev1.ProtocolTCP
	var port53 int32 = 53
	var port443 int32 = 443
	nodeIP := "192.168.0.1"

	tests := []struct {
		name     string
		rules    []EbpfFirewallRules
		wantKeys []string
	}{
		{
			name: "invalid CIDR among valid rules",
			rules: []EbpfFirewallRules{
				{
					IPCidr:   "<kube-dns ClusterIP>/32",
					L4Info:   []v1alpha1.Port{{Protocol: &protocolUDP, Port: &port53}},
					Action:   v1alpha1.ClusterNetworkPolicyRuleActionAccept,
					Priority: 10,
				},
				{
					IPCidr:   "10.0.0.0/8",
					L4Info:   []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}},
					Action:   v1alpha1.ClusterNetworkPolicyRuleActionAccept,
					Priority: 20,
				},
				{
					IPCidr:   "0.0.0.0/0",
					Action:   v1alpha1.ClusterNetworkPolicyRuleActionDeny,
					Priority: 30,
				},
			},
			wantKeys: []string{nodeIP + "/32", "10.0.0.0/8", "0.0.0.0/0"},
		},
		{
			name: "only an invalid CIDR",
			rules: []EbpfFirewallRules{
				{
					IPCidr:   "<kube-dns ClusterIP>/32",
					L4Info:   []v1alpha1.Port{{Protocol: &protocolUDP, Port: &port53}},
					Action:   v1alpha1.ClusterNetworkPolicyRuleActionAccept,
					Priority: 10,
				},
			},
			wantKeys: []string{nodeIP + "/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got map[string][]byte
			var err error
			assert.NotPanics(t, func() {
				got, err = NewFirewallRuleProcessor(nodeIP, "/32", false).ComputeClusterPolicyMapEntriesFromEndpointRules(tt.rules)
			})
			assert.NoError(t, err)
			assert.Len(t, got, len(tt.wantKeys))
			for _, cidr := range tt.wantKeys {
				assert.Contains(t, got, trieKeyFor(t, cidr), "missing map entry for %s", cidr)
			}
		})
	}
}

func TestComputeMapEntries_InvalidCIDRIsSkipped(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port443 int32 = 443
	nodeIP := "192.168.0.1"

	tests := []struct {
		name     string
		rules    []EbpfFirewallRules
		wantKeys []string
	}{
		{
			name: "invalid CIDR",
			rules: []EbpfFirewallRules{
				{IPCidr: "10.0.0.0/8", L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}}},
				{IPCidr: "not-a-cidr/32", L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}}},
			},
			wantKeys: []string{nodeIP + "/32", "10.0.0.0/8"},
		},
		{
			name: "invalid except CIDR",
			rules: []EbpfFirewallRules{
				{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{"10.0.0.0/8", "not-a-cidr/24"}},
			},
			wantKeys: []string{nodeIP + "/32", "0.0.0.0/0", "10.0.0.0/8"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got map[string][]byte
			var err error
			assert.NotPanics(t, func() {
				got, err = NewFirewallRuleProcessor(nodeIP, "/32", false).ComputeMapEntriesFromEndpointRules(tt.rules)
			})
			assert.NoError(t, err)
			assert.Len(t, got, len(tt.wantKeys))
			for _, cidr := range tt.wantKeys {
				assert.Contains(t, got, trieKeyFor(t, cidr), "missing map entry for %s", cidr)
			}
		})
	}
}
