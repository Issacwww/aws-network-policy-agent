//go:build linux

package dnsproxy

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"net"
	"testing"
)

func TestAddressesOnlyFollowAnswerChain(t *testing.T) {
	parse := func(s string) dns.RR {
		r, e := dns.NewRR(s)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	records := []dns.RR{parse("api.test. 3 IN CNAME target.test."), parse("target.test. 30 IN A 203.0.113.2"), parse("evil.test. 60 IN A 203.0.113.3")}
	a := addresses("API.TEST.", records)
	if len(a) != 1 || a[0].TTL != 3 || a[0].IP.String() != "203.0.113.2" {
		t.Fatalf("unexpected grants: %+v", a)
	}
	records[0] = parse("api.test. 0 IN CNAME target.test.")
	if len(addresses("api.test.", records)) != 0 {
		t.Fatal("zero TTL extended")
	}
	records[0] = parse("api.test. 3 IN CNAME api.test.")
	if len(addresses("api.test.", records)) != 0 {
		t.Fatal("CNAME loop granted")
	}
}

func TestFailureBecomesSERVFAIL(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("api.test.", dns.TypeA)
	b, _ := q.Pack()
	s := Server{handle: func(context.Context, net.IP, string, *dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("map update failed")
	}}
	wire := s.answer(context.Background(), net.ParseIP("192.0.2.1"), "192.0.2.53:53", b, false)
	response := new(dns.Msg)
	if err := response.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if response.Rcode != dns.RcodeServerFailure || len(response.Answer) != 0 || response.Id != q.Id {
		t.Fatalf("unsafe response: %v", response)
	}
}

func TestUDPReplyChecksumAndTruncation(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 53}
	dst := &net.UDPAddr{IP: net.ParseIP("192.0.2.7"), Port: 12345}
	b := udpDatagram(src, dst, []byte{1, 2, 3})
	var sum uint32
	for _, ip := range []net.IP{src.IP.To4(), dst.IP.To4()} {
		sum += uint32(ip[0])<<8 | uint32(ip[1])
		sum += uint32(ip[2])<<8 | uint32(ip[3])
	}
	sum += 17 + uint32(len(b))
	for i := 0; i < len(b); i += 2 {
		v := uint32(b[i]) << 8
		if i+1 < len(b) {
			v |= uint32(b[i+1])
		}
		sum += v
	}
	for sum > 65535 {
		sum = (sum & 65535) + (sum >> 16)
	}
	if sum != 65535 {
		t.Fatalf("invalid UDP checksum: %x", sum)
	}
	q := new(dns.Msg)
	q.SetQuestion("api.test.", dns.TypeA)
	wire, _ := q.Pack()
	s := Server{handle: func(_ context.Context, _ net.IP, _ string, q *dns.Msg) (*dns.Msg, error) {
		r := new(dns.Msg)
		r.SetReply(q)
		for i := 0; i < 100; i++ {
			r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: "api.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: net.IPv4(192, 0, 2, 1)})
		}
		return r, nil
	}}
	answer := s.answer(context.Background(), dst.IP, src.String(), wire, true)
	r := new(dns.Msg)
	if err := r.Unpack(answer); err != nil {
		t.Fatal(err)
	}
	if len(answer) > 512 || !r.Truncated {
		t.Fatal("UDP answer did not respect advertised size")
	}
}
