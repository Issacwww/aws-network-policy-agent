package ipfilter

import (
	"context"
	"net"

	"github.com/aws/aws-network-policy-agent/pkg/filter"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

func log() logger.Logger {
	return logger.Get()
}

type contextKey string

const IPFilterMatchKey = contextKey("ipfiltermatch")

type IPFilter struct {
	Next plugin.Handler
}

func (i *IPFilter) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	ipString, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		log().Errorf("IPFilter: Failed to parse client IP: %v", err)
		return plugin.NextOrFailure(i.Name(), i.Next, ctx, w, r)
	}

	podIdentifier, err := filter.GetPodId(ipString)
	if err != nil {
		log().Errorf("IPFilter: Failed to get PodId for IP %s: err %v", ipString, err)
		return plugin.NextOrFailure(i.Name(), i.Next, ctx, w, r)
	}

	podFilter, ok := filter.GetIPFilter(podIdentifier)
	if !ok {
		log().Errorf("IPFilter: No filter for PodId %s PodIP %s", podIdentifier, ipString)
		return plugin.NextOrFailure(i.Name(), i.Next, ctx, w, r)
	}

	state := request.Request{W: w, Req: r}
	allowed, l4Rules := podFilter.IsAllowed(state.QName())
	if !allowed {
		return plugin.NextOrFailure(i.Name(), i.Next, ctx, w, r)
	}

	ctx = context.WithValue(ctx, IPFilterMatchKey, true)
	recorder := &ResponseRecorder{
		ResponseWriter: w,
		req:            r,
		PodId:          podIdentifier,
		L4Rules:        l4Rules,
	}
	return plugin.NextOrFailure(i.Name(), i.Next, ctx, recorder, r)
}

func (i *IPFilter) Name() string { return "ipfilter" }

type ResponseRecorder struct {
	dns.ResponseWriter
	Msg     *dns.Msg
	req     *dns.Msg
	PodId   string
	L4Rules []npatypes.L4Rule
}

func (r *ResponseRecorder) WriteMsg(response *dns.Msg) error {
	ipsWithTTL := []npatypes.IPWithTTL{}
	const defaultTTL uint32 = 300

	if filter.IsIPv6 {
		for _, answer := range response.Answer {
			if record, ok := answer.(*dns.AAAA); ok {
				ttl := record.Hdr.Ttl
				if ttl == 0 {
					ttl = defaultTTL
				}
				ipsWithTTL = append(ipsWithTTL, npatypes.IPWithTTL{IP: record.AAAA, TTL: ttl})
			}
		}
	} else {
		for _, answer := range response.Answer {
			if record, ok := answer.(*dns.A); ok {
				ttl := record.Hdr.Ttl
				if ttl == 0 {
					ttl = defaultTTL
				}
				ipsWithTTL = append(ipsWithTTL, npatypes.IPWithTTL{IP: record.A, TTL: ttl})
			}
		}
	}

	if len(ipsWithTTL) > 0 {
		_ = filter.BpfClient.WriteIPsForPod(r.PodId, ipsWithTTL, r.L4Rules)
	}
	r.Msg = response
	return r.ResponseWriter.WriteMsg(response)
}
