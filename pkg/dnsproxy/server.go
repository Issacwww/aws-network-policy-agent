package dnsproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/filter"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/miekg/dns"
)

type BPFWriter interface {
	WriteIPsForPod(string, []npatypes.IPWithTTL, []npatypes.L4Rule) error
}

type Server interface {
	Start() error
	Stop() error
}

type DNSServer struct {
	log      logger.Logger
	listener netip.AddrPort
	upstream netip.AddrPort
	rules    filter.Store
	writer   BPFWriter

	mu        sync.Mutex
	udpServer *dns.Server
	tcpServer *dns.Server
}

func NewServer(
	log logger.Logger,
	listener netip.AddrPort,
	upstream netip.AddrPort,
	rules filter.Store,
	writer BPFWriter,
) *DNSServer {
	return &DNSServer{
		log:      log,
		listener: listener,
		upstream: upstream,
		rules:    rules,
		writer:   writer,
	}
}

func (s *DNSServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udpServer != nil || s.tcpServer != nil {
		return nil
	}

	udpAddress := &net.UDPAddr{IP: net.IP(s.listener.Addr().AsSlice()), Port: int(s.listener.Port())}
	udpConn, err := net.ListenUDP("udp4", udpAddress)
	if err != nil {
		return fmt.Errorf("listen for UDP DNS on %s: %w", s.listener, err)
	}
	tcpAddress := &net.TCPAddr{IP: net.IP(s.listener.Addr().AsSlice()), Port: int(s.listener.Port())}
	tcpListener, err := net.ListenTCP("tcp4", tcpAddress)
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("listen for TCP DNS on %s: %w", s.listener, err)
	}

	handler := dns.HandlerFunc(s.serveDNS)
	s.udpServer = &dns.Server{PacketConn: udpConn, Handler: handler}
	s.tcpServer = &dns.Server{Listener: tcpListener, Handler: handler}
	go s.activate(s.udpServer, "UDP")
	go s.activate(s.tcpServer, "TCP")
	s.log.Infof("Started DNS policy proxy on %s with upstream %s", s.listener, s.upstream)
	return nil
}

func (s *DNSServer) activate(server *dns.Server, network string) {
	if err := server.ActivateAndServe(); err != nil && !isClosedNetworkError(err) {
		s.log.Errorf("%s DNS policy proxy stopped unexpectedly: %v", network, err)
	}
}

func (s *DNSServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var udpErr, tcpErr error
	if s.udpServer != nil {
		udpErr = s.udpServer.ShutdownContext(shutdownCtx)
		s.udpServer = nil
	}
	if s.tcpServer != nil {
		tcpErr = s.tcpServer.ShutdownContext(shutdownCtx)
		s.tcpServer = nil
	}
	if udpErr != nil {
		return udpErr
	}
	return tcpErr
}

func (s *DNSServer) serveDNS(writer dns.ResponseWriter, request *dns.Msg) {
	if len(request.Question) == 0 {
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeFormatError)
		_ = writer.WriteMsg(response)
		return
	}

	clientIP, _, err := net.SplitHostPort(writer.RemoteAddr().String())
	if err != nil {
		s.writeFailure(writer, request, dns.RcodeRefused)
		return
	}
	podIdentifier, ok := s.rules.PodIdentifier(clientIP)
	if !ok {
		s.writeFailure(writer, request, dns.RcodeRefused)
		return
	}

	network := "udp"
	if strings.HasPrefix(writer.RemoteAddr().Network(), "tcp") {
		network = "tcp"
	}
	response, _, err := (&dns.Client{
		Net:     network,
		Timeout: 5 * time.Second,
	}).Exchange(request, s.upstream.String())
	if err != nil {
		s.log.Errorf("DNS upstream query for pod %s failed: %v", podIdentifier, err)
		s.writeFailure(writer, request, dns.RcodeServerFailure)
		return
	}

	rules, matched := s.rules.MatchPod(podIdentifier, request.Question[0].Name)
	if matched {
		answers := ipv4Answers(response)
		if len(answers) > 0 {
			if err := s.writer.WriteIPsForPod(podIdentifier, answers, rules); err != nil {
				s.log.Errorf("Writing DNS response to ipcache for pod %s failed: %v", podIdentifier, err)
				s.writeFailure(writer, request, dns.RcodeServerFailure)
				return
			}
		}
	}
	if err := writer.WriteMsg(response); err != nil {
		s.log.Errorf("Writing DNS response to pod %s failed: %v", podIdentifier, err)
	}
}

func ipv4Answers(response *dns.Msg) []npatypes.IPWithTTL {
	answers := make([]npatypes.IPWithTTL, 0, len(response.Answer))
	for _, answer := range response.Answer {
		record, ok := answer.(*dns.A)
		if !ok || record.A.To4() == nil {
			continue
		}
		ttl := record.Hdr.Ttl
		if ttl == 0 {
			ttl = 300
		}
		answers = append(answers, npatypes.IPWithTTL{IP: record.A.To4(), TTL: ttl})
	}
	return answers
}

func (s *DNSServer) writeFailure(writer dns.ResponseWriter, request *dns.Msg, rcode int) {
	response := new(dns.Msg)
	response.SetRcode(request, rcode)
	if err := writer.WriteMsg(response); err != nil {
		s.log.Errorf("Writing DNS failure response failed: %v", err)
	}
}

func isClosedNetworkError(err error) bool {
	return strings.Contains(err.Error(), "use of closed network connection")
}

var _ Server = (*DNSServer)(nil)
