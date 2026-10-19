package fwruleprocessor

import (
	"encoding/binary"
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

// cpeTrieEntry is one port entry of a cluster policy trie value (utils.ComputeTrieValueForCPE).
// priority holds the policy priority * 10 + the action (Deny 0, Accept 1, Pass 2).
type cpeTrieEntry struct {
	protocol, priority, startPort, endPort uint32
}

func decodeCPETrieValue(value []byte) []cpeTrieEntry {
	var entries []cpeTrieEntry
	for off := 0; off+16 <= len(value); off += 16 {
		entry := cpeTrieEntry{
			protocol:  binary.LittleEndian.Uint32(value[off : off+4]),
			priority:  binary.LittleEndian.Uint32(value[off+4 : off+8]),
			startPort: binary.LittleEndian.Uint32(value[off+8 : off+12]),
			endPort:   binary.LittleEndian.Uint32(value[off+12 : off+16]),
		}
		if entry.protocol != 0 {
			entries = append(entries, entry)
		}
	}
	return entries
}

// trieEntry is one port entry of a namespaced policy trie value (utils.ComputeTrieValue).
type trieEntry struct {
	protocol, startPort, endPort uint32
}

func decodeTrieValue(value []byte) []trieEntry {
	var entries []trieEntry
	for off := 0; off+12 <= len(value); off += 12 {
		entry := trieEntry{
			protocol:  binary.LittleEndian.Uint32(value[off : off+4]),
			startPort: binary.LittleEndian.Uint32(value[off+4 : off+8]),
			endPort:   binary.LittleEndian.Uint32(value[off+8 : off+12]),
		}
		if entry.protocol != 0 {
			entries = append(entries, entry)
		}
	}
	return entries
}

func TestComputeClusterPolicyMapEntries_InvalidCIDRIsSkipped(t *testing.T) {
	protocolUDP := corev1.ProtocolUDP
	protocolTCP := corev1.ProtocolTCP
	var port53 int32 = 53
	var port443 int32 = 443
	nodeIP := "192.168.0.1"
	anyProtocol := uint32(utils.ANY_IP_PROTOCOL)
	tcp := uint32(utils.TCP_PROTOCOL_NUMBER)
	// the node IP is always accepted, at priority 0
	nodeIPEntries := []cpeTrieEntry{{protocol: anyProtocol, priority: 1}}

	tests := []struct {
		name  string
		rules []EbpfFirewallRules
		want  map[string][]cpeTrieEntry
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
			// 10.0.0.0/8 keeps its own TCP 443 Accept at priority 20 and inherits the catch-all Deny of
			// 0.0.0.0/0 at priority 30; nothing of the skipped UDP 53 rule appears in any entry
			want: map[string][]cpeTrieEntry{
				nodeIP + "/32": nodeIPEntries,
				"10.0.0.0/8":   {{protocol: tcp, priority: 20*10 + 1, startPort: 443}, {protocol: anyProtocol, priority: 30 * 10}},
				"0.0.0.0/0":    {{protocol: anyProtocol, priority: 30 * 10}},
			},
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
			want: map[string][]cpeTrieEntry{nodeIP + "/32": nodeIPEntries},
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
			assert.Len(t, got, len(tt.want))
			for cidr, wantEntries := range tt.want {
				value, ok := got[trieKeyFor(t, cidr)]
				if assert.True(t, ok, "missing map entry for %s", cidr) {
					assert.ElementsMatch(t, wantEntries, decodeCPETrieValue(value), "entries of %s", cidr)
				}
			}
		})
	}
}

func TestComputeMapEntries_InvalidCIDRIsSkipped(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port443 int32 = 443
	nodeIP := "192.168.0.1"
	tcp443 := []trieEntry{{protocol: uint32(utils.TCP_PROTOCOL_NUMBER), startPort: 443}}
	// the node IP is always allowed on every protocol and port
	nodeIPEntries := []trieEntry{{protocol: uint32(utils.ANY_IP_PROTOCOL)}}

	tests := []struct {
		name  string
		rules []EbpfFirewallRules
		want  map[string][]trieEntry
	}{
		{
			name: "invalid CIDR",
			rules: []EbpfFirewallRules{
				{IPCidr: "10.0.0.0/8", L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}}},
				{IPCidr: "not-a-cidr/32", L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}}},
			},
			want: map[string][]trieEntry{nodeIP + "/32": nodeIPEntries, "10.0.0.0/8": tcp443},
		},
		{
			// the except entry was meant to exclude addresses, so allowing 0.0.0.0/0 without it would
			// widen the rule; the whole rule is skipped instead
			name: "invalid except CIDR drops its rule",
			rules: []EbpfFirewallRules{
				{IPCidr: "0.0.0.0/0", Except: []v1alpha1.NetworkAddress{"10.0.0.0/8", "169.254.169.254/322"}},
				{IPCidr: "192.168.0.0/16", L4Info: []v1alpha1.Port{{Protocol: &protocolTCP, Port: &port443}}},
			},
			want: map[string][]trieEntry{nodeIP + "/32": nodeIPEntries, "192.168.0.0/16": tcp443},
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
			assert.Len(t, got, len(tt.want))
			for cidr, wantEntries := range tt.want {
				value, ok := got[trieKeyFor(t, cidr)]
				if assert.True(t, ok, "missing map entry for %s", cidr) {
					assert.ElementsMatch(t, wantEntries, decodeTrieValue(value), "entries of %s", cidr)
				}
			}
		})
	}
}
