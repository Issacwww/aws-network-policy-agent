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
			ResponseWriter: &captureResponseWriter{},
			remoteAddr:     &net.UDPAddr{IP: net.ParseIP(clientIP), Port: 53000},
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

func TestAutoConformanceResponseRecorderKeepsIPv6CNAMEAnswers(t *testing.T) {
	mock := &ebpf.MockBpfClient{}
	filter.BpfClient = mock
	filter.IsIPv6 = true
	t.Cleanup(func() {
		filter.IsIPv6 = false
	})

	recorder := &ResponseRecorder{
		ResponseWriter: &captureResponseWriter{},
		PodId:          "workload@default",
	}
	response := new(dns.Msg)
	response.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "service.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30},
			Target: "target.example.com.",
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "target.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET},
			AAAA: net.ParseIP("2001:db8::10"),
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "target.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 42},
			AAAA: net.ParseIP("2001:db8::11"),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "target.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 99},
			A:   net.ParseIP("192.0.2.10"),
		},
	}

	if err := recorder.WriteMsg(response); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	if len(mock.LastWrittenIPs) != 2 {
		t.Fatalf("written IPs = %#v, want the two AAAA records after the CNAME", mock.LastWrittenIPs)
	}
	if got := mock.LastWrittenIPs[0]; !got.IP.Equal(net.ParseIP("2001:db8::10")) || got.TTL != 300 {
		t.Fatalf("first IPv6 answer = %#v, want 2001:db8::10 TTL 300", got)
	}
	if got := mock.LastWrittenIPs[1]; !got.IP.Equal(net.ParseIP("2001:db8::11")) || got.TTL != 42 {
		t.Fatalf("second IPv6 answer = %#v, want 2001:db8::11 TTL 42", got)
	}
}

func TestAutoConformanceUpstreamFailureDoesNotWriteIPCache(t *testing.T) {
	const (
		podIdentifier = "workload@default"
		clientIP      = "10.0.0.10"
	)
	filter.SetPodIPToPodId(clientIP, podIdentifier)
	filter.SetPolicyEndpointDomains(podIdentifier, []fwrp.EbpfFirewallRules{{
		DomainName: "api.example.com.",
		Priority:   15001,
	}})
	mock := &ebpf.MockBpfClient{}
	filter.BpfClient = mock
	filter.IsIPv6 = false
	t.Cleanup(func() {
		filter.DeletePolicyEndpointDomains(podIdentifier)
		filter.DeletePodIPToPodIdEntry(clientIP)
	})

	upstreamErr := errors.New("injected upstream failure")
	handler := &IPFilter{Next: &failingHandler{err: upstreamErr}}
	request := new(dns.Msg)
	request.SetQuestion("api.example.com.", dns.TypeA)
	writer := &remoteResponseWriter{
		ResponseWriter: &captureResponseWriter{},
		remoteAddr:     &net.UDPAddr{IP: net.ParseIP(clientIP), Port: 53000},
	}
	if _, err := handler.ServeDNS(context.Background(), writer, request); !errors.Is(err, upstreamErr) {
		t.Fatalf("ServeDNS error = %v, want injected upstream failure", err)
	}
	if got := mock.WriteIPsForPodIdCount.Load(); got != 0 {
		t.Fatalf("ipcache writes = %d, want 0 after upstream failure", got)
	}
}

func TestAutoConformanceMatchedQueriesForwardOnceAndRefreshIPCache(t *testing.T) {
	const (
		podIdentifier = "refresh@default"
		clientIP      = "10.0.0.20"
	)
	tcp := corev1.ProtocolTCP
	port80 := int32(80)
	port443 := int32(443)
	filter.SetPodIPToPodId(clientIP, podIdentifier)
	filter.SetPolicyEndpointDomains(podIdentifier, []fwrp.EbpfFirewallRules{{
		DomainName: "refresh.example.com.",
		Priority:   15001,
		L4Info:     []policyk8sawsv1.Port{{Protocol: &tcp, Port: &port80}},
	}})
	mock := &ebpf.MockBpfClient{}
	filter.BpfClient = mock
	filter.IsIPv6 = false
	t.Cleanup(func() {
		filter.DeletePolicyEndpointDomains(podIdentifier)
		filter.DeletePodIPToPodIdEntry(clientIP)
	})

	next := &answerHandler{address: net.ParseIP("192.0.2.10")}
	handler := &IPFilter{Next: next}
	request := new(dns.Msg)
	request.SetQuestion("refresh.example.com.", dns.TypeA)
	writer := &remoteResponseWriter{
		ResponseWriter: &captureResponseWriter{},
		remoteAddr:     &net.UDPAddr{IP: net.ParseIP(clientIP), Port: 53000},
	}

	if _, err := handler.ServeDNS(context.Background(), writer, request); err != nil {
		t.Fatal(err)
	}
	if next.calls != 1 || mock.WriteIPsForPodIdCount.Load() != 1 ||
		len(mock.LastWrittenIPs) != 1 || !mock.LastWrittenIPs[0].IP.Equal(net.ParseIP("192.0.2.10")) ||
		len(mock.LastWrittenL4Rules) != 1 || mock.LastWrittenL4Rules[0].L4PortProtocolInfo.Port == nil ||
		*mock.LastWrittenL4Rules[0].L4PortProtocolInfo.Port != port80 {
		t.Fatalf(
			"first query = forwards %d writes %d IPs %#v L4 %#v, want 192.0.2.10 TCP/80",
			next.calls,
			mock.WriteIPsForPodIdCount.Load(),
			mock.LastWrittenIPs,
			mock.LastWrittenL4Rules,
		)
	}

	filter.SetPolicyEndpointDomains(podIdentifier, []fwrp.EbpfFirewallRules{{
		DomainName: "refresh.example.com.",
		Priority:   15001,
		L4Info:     []policyk8sawsv1.Port{{Protocol: &tcp, Port: &port443}},
	}})
	next.address = net.ParseIP("192.0.2.11")
	if _, err := handler.ServeDNS(context.Background(), writer, request); err != nil {
		t.Fatal(err)
	}
	if next.calls != 2 || mock.WriteIPsForPodIdCount.Load() != 2 ||
		len(mock.LastWrittenIPs) != 1 || !mock.LastWrittenIPs[0].IP.Equal(net.ParseIP("192.0.2.11")) ||
		len(mock.LastWrittenL4Rules) != 1 || mock.LastWrittenL4Rules[0].L4PortProtocolInfo.Port == nil ||
		*mock.LastWrittenL4Rules[0].L4PortProtocolInfo.Port != port443 {
		t.Fatalf(
			"refresh query = forwards %d writes %d IPs %#v L4 %#v, want replacement with 192.0.2.11 TCP/443",
			next.calls,
			mock.WriteIPsForPodIdCount.Load(),
			mock.LastWrittenIPs,
			mock.LastWrittenL4Rules,
		)
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

type failingHandler struct {
	err error
}

func (h *failingHandler) ServeDNS(
	context.Context,
	dns.ResponseWriter,
	*dns.Msg,
) (int, error) {
	return dns.RcodeServerFailure, h.err
}

func (*failingHandler) Name() string { return "failing-handler" }

type answerHandler struct {
	address net.IP
	calls   int
}

func (h *answerHandler) ServeDNS(
	_ context.Context,
	writer dns.ResponseWriter,
	request *dns.Msg,
) (int, error) {
	h.calls++
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
		A:   h.address,
	}}
	return dns.RcodeSuccess, writer.WriteMsg(response)
}

func (*answerHandler) Name() string { return "answer-handler" }

type remoteResponseWriter struct {
	dns.ResponseWriter
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
var _ plugin.Handler = (*failingHandler)(nil)
var _ plugin.Handler = (*answerHandler)(nil)
var _ dns.ResponseWriter = (*captureResponseWriter)(nil)
