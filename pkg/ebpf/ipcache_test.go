package ebpf

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	policyendpoint "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	corev1 "k8s.io/api/core/v1"
)

func TestEncodeIPCacheEntriesPriorityAndPorts(t *testing.T) {
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
			entries := encodeIPCacheEntries(
				false,
				123,
				[]npatypes.IPWithTTL{{IP: net.ParseIP("192.0.2.10")}},
				[]npatypes.L4Rule{{
					L4PortProtocolInfo: policyendpoint.Port{
						Protocol: &tcp,
						Port:     &startPort,
						EndPort:  &endPort,
					},
					Priority: test.priority,
				}},
			)
			if len(entries) != 1 {
				t.Fatalf("encoded entries = %#v, want one", entries)
			}
			entry := entries[0]
			if key := binary.LittleEndian.Uint32(entry.key[:4]); key != 0x0a0200c0 {
				t.Fatalf("key = %#x, want little-endian IPv4 bytes", key)
			}
			if got := binary.LittleEndian.Uint32(entry.value.Ports[0:4]); got != uint32(utils.TCP_PROTOCOL_NUMBER) {
				t.Errorf("protocol = %d, want TCP", got)
			}
			if got := binary.LittleEndian.Uint32(entry.value.Ports[4:8]); got != test.wantPriority {
				t.Errorf("encoded priority = %d, want %d", got, test.wantPriority)
			}
			if got := binary.LittleEndian.Uint32(entry.value.Ports[8:12]); got != uint32(startPort) {
				t.Errorf("start port = %d, want %d", got, startPort)
			}
			if got := binary.LittleEndian.Uint32(entry.value.Ports[12:16]); got != uint32(endPort) {
				t.Errorf("end port = %d, want %d", got, endPort)
			}
		})
	}
}

func TestAutoPriorityEncodingDocumentsLowerPriorityAcceptOverride(t *testing.T) {
	entries := encodeIPCacheEntries(
		false,
		123,
		[]npatypes.IPWithTTL{{IP: net.ParseIP("192.0.2.10")}},
		[]npatypes.L4Rule{{Priority: 50}},
	)
	if len(entries) != 1 {
		t.Fatalf("encoded entries = %#v, want one", entries)
	}
	stored := binary.LittleEndian.Uint32(entries[0].value.Ports[4:8])
	effectiveDomainPriority := stored / 10
	if effectiveDomainPriority != 5 {
		t.Fatalf("Auto p50 domain priority is read as %d, want 5", effectiveDomainPriority)
	}
	if effectiveDomainPriority >= 10 {
		t.Fatal("test setup no longer documents the Auto p50 Accept override of p10 Deny")
	}
}

func TestEncodeIPCacheKeySupportsSelectedAddressFamily(t *testing.T) {
	ipv4Key, err := encodeIPCacheKey(net.ParseIP("192.0.2.10"), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(ipv4Key[:4]); got != 0x0a0200c0 {
		t.Fatalf("IPv4 key = %#x, want little-endian IPv4 bytes", got)
	}

	ipv6Key, err := encodeIPCacheKey(net.ParseIP("2001:db8::1"), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := net.IP(ipv6Key[:]).String(); got != "2001:db8::1" {
		t.Fatalf("IPv6 key = %s, want 2001:db8::1", got)
	}

	if _, err := encodeIPCacheKey(net.ParseIP("2001:db8::1"), false); err == nil {
		t.Fatal("expected IPv6 input to fail for the IPv4 map")
	}
	if _, err := encodeIPCacheKey(net.ParseIP("192.0.2.10"), true); err == nil {
		t.Fatal("expected IPv4 input to fail for the IPv6 map")
	}
}

func TestWriteIPCacheEntriesOverwriteWholeValueWithBPFAny(t *testing.T) {
	tcp := corev1.ProtocolTCP
	port := int32(443)
	writer := &recordingIPCacheMap{}
	nowNs := uint64(100)
	ip := net.ParseIP("192.0.2.10")
	ips := []npatypes.IPWithTTL{{IP: ip, TTL: 30}, {IP: ip, TTL: 60}}
	rules := []npatypes.L4Rule{{
		L4PortProtocolInfo: policyendpoint.Port{Protocol: &tcp, Port: &port},
		Priority:           15001,
	}}

	err := writeIPCacheEntries(
		writer,
		false,
		nowNs,
		ips,
		rules,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(writer.keys) != 2 || writer.keys[0] != writer.keys[1] {
		t.Fatalf("keys = %#v, want two writes to the same IP key", writer.keys)
	}
	if writer.flags[0] != 0 || writer.flags[1] != 0 {
		t.Fatalf("update flags = %#v, want BPF_ANY (0) for whole-value overwrite", writer.flags)
	}
	if got, want := writer.values[0].ExpiryTime, nowNs+uint64(30*time.Second); got != want {
		t.Fatalf("first expiry = %d, want %d", got, want)
	}
	if got, want := writer.values[1].ExpiryTime, nowNs+uint64(60*time.Second); got != want {
		t.Fatalf("replacement expiry = %d, want %d", got, want)
	}
	if got := binary.LittleEndian.Uint32(writer.values[1].Ports[8:12]); got != uint32(port) {
		t.Fatalf("replacement start port = %d, want %d", got, port)
	}
}

func TestWriteIPCacheEntriesStopsAfterFirstMapFailure(t *testing.T) {
	injected := errors.New("injected map failure")
	writer := &recordingIPCacheMap{failAt: 2, err: injected}
	err := writeIPCacheEntries(
		writer,
		true,
		0,
		[]npatypes.IPWithTTL{
			{IP: net.ParseIP("2001:db8::1"), TTL: 1},
			{IP: net.ParseIP("2001:db8::2"), TTL: 1},
			{IP: net.ParseIP("2001:db8::3"), TTL: 1},
		},
		nil,
	)
	if !errors.Is(err, injected) {
		t.Fatalf("write error = %v, want injected map failure", err)
	}
	if writer.calls != 2 {
		t.Fatalf("map writes = %d, want stop after failing second write", writer.calls)
	}
	if got := net.IP(writer.keys[0][:]).String(); got != "2001:db8::1" {
		t.Fatalf("first IPv6 key = %s, want 2001:db8::1", got)
	}
	if got := net.IP(writer.keys[1][:]).String(); got != "2001:db8::2" {
		t.Fatalf("second IPv6 key = %s, want 2001:db8::2", got)
	}
}

type recordingIPCacheMap struct {
	failAt int
	err    error
	calls  int
	keys   [][16]byte
	values []npatypes.IPCacheVal
	flags  []uint64
}

func (m *recordingIPCacheMap) writeIPCacheEntry(
	key *[16]byte,
	value *npatypes.IPCacheVal,
	updateFlags uint64,
) error {
	m.calls++
	m.keys = append(m.keys, *key)
	m.values = append(m.values, *value)
	m.flags = append(m.flags, updateFlags)
	if m.failAt > 0 && m.calls == m.failAt {
		return m.err
	}
	return nil
}
