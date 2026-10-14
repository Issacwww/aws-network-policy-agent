package cdnsproxy

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/filter"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	corev1 "k8s.io/api/core/v1"
)

func TestAutoConformanceUnknownPodAndWriteFailureStillReturnAnswer(t *testing.T) {
	upstream := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(r)
		response.Answer = append(response.Answer, test.A("www.example.org. 30 IN A 192.0.2.10"))
		_ = w.WriteMsg(response)
	})
	defer upstream.Close()

	listener := freeDNSAddress(t)
	corefile := fmt.Sprintf(`.:%d {
		bind %s
		log
		ipfilter
		forward . %s
	}`, listener.Port, listener.IP, upstream.Addr)

	mock := &ebpf.MockBpfClient{}
	filter.BpfClient = mock
	filter.IsIPv6 = false
	proxy := NewDNSProxy(logger.Get(), mock, false, upstream.Addr, listener.String())
	if err := proxy.Start(context.Background(), corefile); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Stop()

	query := new(dns.Msg)
	query.SetQuestion("www.example.org.", dns.TypeA)
	client := new(dns.Client)

	response, _, err := client.Exchange(query, listener.String())
	if err != nil {
		t.Fatalf("unknown-pod query: %v", err)
	}
	assertAnswer(t, response)
	if mock.WriteIPsForPodIdCount.Load() != 0 {
		t.Fatal("unknown pod response must not be recorded")
	}

	tcp := corev1.ProtocolTCP
	port := int32(443)
	clientIP := listener.IP.String()
	filter.SetPodIPToPodId(clientIP, "pod@ns")
	response, _, err = client.Exchange(query, listener.String())
	if err != nil {
		t.Fatalf("known pod without filter: %v", err)
	}
	assertAnswer(t, response)
	if mock.WriteIPsForPodIdCount.Load() != 0 {
		t.Fatal("known pod without a filter must not record the response")
	}

	filter.SetPolicyEndpointDomains("pod@ns", []fwrp.EbpfFirewallRules{{
		DomainName: "www.example.org.",
		Priority:   15001,
		L4Info:     []v1alpha1.Port{{Protocol: &tcp, Port: &port}},
	}})
	defer filter.DeletePolicyEndpointDomains("pod@ns")
	defer filter.DeletePodIPToPodIdEntry(clientIP)

	mock.WriteIPsForPodErr = fmt.Errorf("injected ipcache failure")
	response, _, err = client.Exchange(query, listener.String())
	if err != nil {
		t.Fatalf("matched query with ipcache failure: %v", err)
	}
	assertAnswer(t, response)

	tcpClient := &dns.Client{Net: "tcp"}
	response, _, err = tcpClient.Exchange(query, listener.String())
	if err != nil {
		t.Fatalf("matched TCP query with ipcache failure: %v", err)
	}
	assertAnswer(t, response)
	if response.Truncated {
		t.Fatal("TCP response must not be truncated")
	}
}

func TestAutoConformanceLargeUDPResponseAndTCPFallback(t *testing.T) {
	upstream := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(r)
		for index := 0; index < 50; index++ {
			response.Answer = append(response.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   "large.example.org.",
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Txt: []string{fmt.Sprintf("large DNS answer record %d with enough text to exceed a 512-byte UDP response", index)},
			})
		}
		if w.RemoteAddr().Network() == "udp" && response.Len() > 512 {
			response.Truncated = true
			response.Answer = response.Answer[:5]
		}
		_ = w.WriteMsg(response)
	})
	defer upstream.Close()

	listener := freeDNSAddress(t)
	corefile := fmt.Sprintf(`.:%d {
		bind %s
		log
		ipfilter
		forward . %s
	}`, listener.Port, listener.IP, upstream.Addr)
	mock := &ebpf.MockBpfClient{}
	filter.BpfClient = mock
	filter.IsIPv6 = false
	filter.SetPodIPToPodId(listener.IP.String(), "large@default")
	filter.SetPolicyEndpointDomains("large@default", []fwrp.EbpfFirewallRules{{
		DomainName: "large.example.org.",
		Priority:   15001,
	}})
	t.Cleanup(func() {
		filter.DeletePolicyEndpointDomains("large@default")
		filter.DeletePodIPToPodIdEntry(listener.IP.String())
	})

	proxy := NewDNSProxy(logger.Get(), mock, false, upstream.Addr, listener.String())
	if err := proxy.Start(context.Background(), corefile); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Stop()

	query := new(dns.Msg)
	query.SetQuestion("large.example.org.", dns.TypeTXT)
	udpResponse, _, err := (&dns.Client{Net: "udp", UDPSize: 512}).Exchange(query, listener.String())
	if err != nil {
		t.Fatalf("UDP query: %v", err)
	}
	if !udpResponse.Truncated || len(udpResponse.Answer) >= 50 {
		t.Fatalf("UDP response truncated=%v answers=%d, want truncated partial response", udpResponse.Truncated, len(udpResponse.Answer))
	}

	tcpResponse, _, err := (&dns.Client{Net: "tcp"}).Exchange(query, listener.String())
	if err != nil {
		t.Fatalf("TCP fallback query: %v", err)
	}
	if tcpResponse.Truncated || len(tcpResponse.Answer) != 50 {
		t.Fatalf("TCP response truncated=%v answers=%d, want complete 50-record response", tcpResponse.Truncated, len(tcpResponse.Answer))
	}
}

func assertAnswer(t *testing.T, response *dns.Msg) {
	t.Helper()
	if response == nil || len(response.Answer) != 1 {
		t.Fatalf("response = %#v, want one upstream answer", response)
	}
	record, ok := response.Answer[0].(*dns.A)
	if !ok || record.A.String() != "192.0.2.10" {
		t.Fatalf("answer = %#v, want 192.0.2.10", response.Answer)
	}
}

func freeDNSAddress(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	address := conn.LocalAddr().(*net.UDPAddr)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
