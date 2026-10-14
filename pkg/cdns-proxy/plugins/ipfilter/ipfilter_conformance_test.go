package ipfilter

import (
	"context"
	"errors"
	"net"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/filter"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/miekg/dns"
	corev1 "k8s.io/api/core/v1"
)

func TestAutoConformanceIPFilterExactWildcardAndMiss(t *testing.T) {
	podIdentifier := "workload@default"
	clientIP := "10.0.0.10"
	filter.SetPodIPToPodId(clientIP, podIdentifier)
	filter.SetPolicyEndpointDomains(podIdentifier, []fwrp.EbpfFirewallRules{
		{DomainName: "api.example.com.", Priority: 15001},
		{DomainName: "*.amazon.com.", Priority: 15001},
	})
	t.Cleanup(func() {
		filter.DeletePolicyEndpointDomains(podIdentifier)
		filter.DeletePodIPToPodIdEntry(clientIP)
	})

	next := &matchRecordingHandler{}
	handler := &IPFilter{Next: next}
	for _, test := range []struct {
		qname   string
		matched bool
	}{
		{qname: "api.example.com.", matched: true},
		{qname: "service.amazon.com.", matched: true},
		{qname: "amazon.com.", matched: false},
		{qname: "API.EXAMPLE.COM.", matched: false},
		{qname: "blocked.example.com.", matched: false},
	} {
		next.matched = false
		request := new(dns.Msg)
		request.SetQuestion(test.qname, dns.TypeA)
		writer := &remoteResponseWriter{
			Recorder:   &dnstest.Recorder{},
			remoteAddr: &net.UDPAddr{IP: net.ParseIP(clientIP), Port: 53000},
		}
		if _, err := handler.ServeDNS(context.Background(), writer, request); err != nil {
			t.Fatalf("%s: %v", test.qname, err)
		}
		if next.matched != test.matched {
			t.Fatalf("%s matched = %v, want %v", test.qname, next.matched, test.matched)
		}
	}
}

func TestAutoConformanceResponseRecorderKeepsIPv4TTLAndIgnoresWriteFailure(t *testing.T) {
	tcp := corev1.ProtocolTCP
	port := int32(443)
	rules := []npatypes.L4Rule{{
		L4PortProtocolInfo: policyk8sawsv1.Port{Protocol: &tcp, Port: &port},
		Priority:           15001,
	}}
	mock := &ebpf.MockBpfClient{WriteIPsForPodErr: errors.New("injected ipcache write failure")}
	filter.BpfClient = mock
	filter.IsIPv6 = false
	writer := &captureResponseWriter{}
	recorder := &ResponseRecorder{
		ResponseWriter: writer,
		PodId:          "workload@default",
		L4Rules:        rules,
	}
	response := new(dns.Msg)
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
			A:   net.ParseIP("192.0.2.10"),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "b.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 42},
			A:   net.ParseIP("192.0.2.11"),
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "v6.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 99},
			AAAA: net.ParseIP("2001:db8::10"),
		},
	}
	if err := recorder.WriteMsg(response); err != nil {
		t.Fatalf("WriteMsg must return the DNS writer result, not the ipcache error: %v", err)
	}
	if len(mock.LastWrittenIPs) != 2 {
		t.Fatalf("written IPs = %#v, want the two A records", mock.LastWrittenIPs)
	}
	if mock.LastWrittenIPs[0].TTL != 300 || mock.LastWrittenIPs[1].TTL != 42 {
		t.Fatalf("written TTLs = %d/%d, want 300/42", mock.LastWrittenIPs[0].TTL, mock.LastWrittenIPs[1].TTL)
	}
}

type matchRecordingHandler struct {
	matched bool
}

func (h *matchRecordingHandler) ServeDNS(
	ctx context.Context,
	_ dns.ResponseWriter,
	_ *dns.Msg,
) (int, error) {
	h.matched, _ = ctx.Value(IPFilterMatchKey).(bool)
	return dns.RcodeSuccess, nil
}

func (*matchRecordingHandler) Name() string { return "match-recorder" }

type remoteResponseWriter struct {
	*dnstest.Recorder
	remoteAddr net.Addr
}

func (w *remoteResponseWriter) RemoteAddr() net.Addr { return w.remoteAddr }

type captureResponseWriter struct {
	message *dns.Msg
}

func (*captureResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

func (*captureResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("10.0.0.10"), Port: 53000}
}

func (w *captureResponseWriter) WriteMsg(message *dns.Msg) error {
	w.message = message
	return nil
}

func (*captureResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (*captureResponseWriter) Close() error              { return nil }
func (*captureResponseWriter) TsigStatus() error         { return nil }
func (*captureResponseWriter) TsigTimersOnly(bool)       {}
func (*captureResponseWriter) Hijack()                   {}

var _ plugin.Handler = (*matchRecordingHandler)(nil)
var _ dns.ResponseWriter = (*captureResponseWriter)(nil)
