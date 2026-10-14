package ebpf

import (
	"encoding/binary"
	"net"
	"testing"

	policyendpoint "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	corev1 "k8s.io/api/core/v1"
)

func TestEncodeIPCacheEntryPriorityAndPorts(t *testing.T) {
	tcp := corev1.ProtocolTCP
	startPort := int32(8000)
	endPort := int32(8100)
	tests := []struct {
		name         string
		priority     int
		wantPriority uint32
	}{
		{name: "Admin raw Auto value", priority: 50, wantPriority: 50},
		{name: "namespace pre-encoded Auto value", priority: utils.PE_PRIORITY*10 + 1, wantPriority: 15001},
		{name: "Baseline raw Auto value", priority: fwrp.BASELINE_TIER_PRIORITY_OFFSET + 10, wantPriority: 2010},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, value, err := EncodeIPCacheEntry(
				net.ParseIP("192.0.2.10"),
				123,
				[]npatypes.L4Rule{{
					L4PortProtocolInfo: policyendpoint.Port{
						Protocol: &tcp,
						Port:     &startPort,
						EndPort:  &endPort,
					},
					Priority: test.priority,
				}},
			)
			if err != nil {
				t.Fatalf("EncodeIPCacheEntry: %v", err)
			}
			if key != 0x0a0200c0 {
				t.Fatalf("key = %#x, want little-endian IPv4 bytes", key)
			}
			if got := binary.LittleEndian.Uint32(value.Ports[0:4]); got != uint32(utils.TCP_PROTOCOL_NUMBER) {
				t.Errorf("protocol = %d, want TCP", got)
			}
			if got := binary.LittleEndian.Uint32(value.Ports[4:8]); got != test.wantPriority {
				t.Errorf("encoded priority = %d, want %d", got, test.wantPriority)
			}
			if got := binary.LittleEndian.Uint32(value.Ports[8:12]); got != uint32(startPort) {
				t.Errorf("start port = %d, want %d", got, startPort)
			}
			if got := binary.LittleEndian.Uint32(value.Ports[12:16]); got != uint32(endPort) {
				t.Errorf("end port = %d, want %d", got, endPort)
			}
		})
	}
}

func TestAutoPriorityEncodingDocumentsLowerPriorityAcceptOverride(t *testing.T) {
	_, value, err := EncodeIPCacheEntry(
		net.ParseIP("192.0.2.10"),
		123,
		[]npatypes.L4Rule{{Priority: 50}},
	)
	if err != nil {
		t.Fatal(err)
	}
	stored := binary.LittleEndian.Uint32(value.Ports[4:8])
	effectiveDomainPriority := stored / 10
	if effectiveDomainPriority != 5 {
		t.Fatalf("Auto p50 domain priority is read as %d, want 5", effectiveDomainPriority)
	}
	if effectiveDomainPriority >= 10 {
		t.Fatal("test setup no longer documents the Auto p50 Accept override of p10 Deny")
	}
}

func TestEncodeIPCacheEntryRejectsIPv6(t *testing.T) {
	if _, _, err := EncodeIPCacheEntry(net.ParseIP("2001:db8::1"), 1, nil); err == nil {
		t.Fatal("expected IPv6 encoding to fail in S1")
	}
}
