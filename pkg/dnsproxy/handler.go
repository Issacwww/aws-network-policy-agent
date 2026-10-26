package dnsproxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/filter"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/miekg/dns"
)

// Handle forwards unmatched names too: DNS transport authorization is independent
// of a domain grant. Only matched answers contribute application permissions.
func Handle(ctx context.Context, clientIP net.IP, original string, q *dns.Msg) (*dns.Msg, error) {
	host, port, err := net.SplitHostPort(original)
	if err != nil || port != "53" || net.ParseIP(host) == nil {
		return nil, fmt.Errorf("invalid original resolver")
	}
	if q.Response || len(q.Question) != 1 || q.Opcode != dns.OpcodeQuery {
		return nil, fmt.Errorf("unsupported DNS message")
	}
	pod, err := filter.GetPodId(clientIP.String())
	if err != nil {
		return nil, err
	}
	// The experiment uses TCP upstream to preserve NodeLocal's UDP NOTRACK behavior
	// on the client leg while avoiding large UDP replies and truncation upstream.
	dc := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	res, _, err := dc.ExchangeContext(ctx, q, original)
	if err != nil {
		return nil, err
	}
	if !res.Response || res.Id != q.Id || len(res.Question) != 1 || res.Question[0] != q.Question[0] {
		return nil, fmt.Errorf("mismatched DNS response")
	}
	filter.PolicyMu.Lock()
	defer filter.PolicyMu.Unlock()
	current, err := filter.GetPodId(clientIP.String())
	if err != nil || current != pod {
		return nil, fmt.Errorf("pod identity changed")
	}
	f, ok := filter.GetIPFilter(pod)
	if !ok {
		return res, nil
	}
	allowed, rules := f.IsAllowed(strings.ToLower(dns.Fqdn(q.Question[0].Name)))
	if !allowed || res.Rcode != dns.RcodeSuccess || res.Truncated {
		return res, nil
	}
	ips := addresses(q.Question[0].Name, res.Answer)
	if len(ips) > 0 {
		if err = filter.BpfClient.WriteIPsForPod(pod, ips, rules); err != nil {
			return nil, fmt.Errorf("publish DNS authorization: %w", err)
		}
	}
	return res, nil
}

// Only grant A records reached from the queried name. CNAME TTL bounds the grant;
// zero TTL never becomes an invented grace period. Ignore unrelated/additional RRs.
func addresses(name string, answers []dns.RR) []npatypes.IPWithTTL {
	name = strings.ToLower(dns.Fqdn(name))
	ttl := ^uint32(0)
	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		if seen[name] {
			return nil
		}
		seen[name] = true
		next := ""
		for _, rr := range answers {
			if strings.ToLower(rr.Header().Name) != name {
				continue
			}
			if c, ok := rr.(*dns.CNAME); ok {
				if c.Hdr.Ttl < ttl {
					ttl = c.Hdr.Ttl
				}
				next = strings.ToLower(dns.Fqdn(c.Target))
				break
			}
		}
		if next != "" {
			name = next
			continue
		}
		var out []npatypes.IPWithTTL
		for _, rr := range answers {
			a, ok := rr.(*dns.A)
			if !ok || strings.ToLower(a.Hdr.Name) != name {
				continue
			}
			t := a.Hdr.Ttl
			if ttl < t {
				t = ttl
			}
			if t > 0 {
				out = append(out, npatypes.IPWithTTL{IP: a.A, TTL: t})
			}
		}
		return out
	}
	return nil
}
