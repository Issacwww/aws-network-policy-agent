package utils

import (
	"encoding/binary"
	"testing"

	policyendpoint "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	corev1 "k8s.io/api/core/v1"
)

func TestAutoConformanceDNSIPCacheUsesFixedTwentyFourRuleValue(t *testing.T) {
	protocol := corev1.ProtocolTCP
	rules := make([]npatypes.L4Rule, 25)
	for index := range rules {
		port := int32(8000 + index)
		rules[index] = npatypes.L4Rule{
			L4PortProtocolInfo: policyendpoint.Port{Protocol: &protocol, Port: &port},
			Priority:           index + 1,
		}
	}

	value := ComputeValueForL4Rules(rules)
	if len(value) != npatypes.L4RULE_VALUES_LENGTH {
		t.Fatalf("encoded value length = %d, want %d", len(value), npatypes.L4RULE_VALUES_LENGTH)
	}
	const lastOffset = 23 * 16
	if got := binary.LittleEndian.Uint32(value[lastOffset+8 : lastOffset+12]); got != 8023 {
		t.Fatalf("last representable start port = %d, want 8023", got)
	}
	if got := binary.LittleEndian.Uint32(value[lastOffset+4 : lastOffset+8]); got != 24 {
		t.Fatalf("last representable priority = %d, want 24", got)
	}
}
