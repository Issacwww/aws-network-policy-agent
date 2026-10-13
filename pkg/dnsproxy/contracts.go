package dnsproxy

import (
	"net/netip"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/filter"
)

type IPFamily uint8

const (
	IPv4 IPFamily = iota + 1
	IPv6
)

type AddressRecord struct {
	Name string
	IP   netip.Addr
	TTL  uint32
}

type Response struct {
	QueryName string
	Addresses []AddressRecord
}

type PlanRequest struct {
	Response Response
	Matched  bool
	Rule     filter.Rule
	Family   IPFamily
	Now      time.Time
}

type CacheWrite struct {
	QueryName string
	IP        netip.Addr
	ExpiresAt time.Time
	Rule      filter.Rule
}

type RouteDecision struct {
	Upstream netip.AddrPort
	Bypass   bool
}

type QueryMatcher interface {
	Match(string) (filter.Rule, bool)
}

type CacheWriter interface {
	Write(CacheWrite) error
}

type QueryForwarder interface {
	Forward(string) (Response, error)
}

type Proxy struct {
	forwarder QueryForwarder
	matcher   QueryMatcher
	writer    CacheWriter
}

func NewProxy(forwarder QueryForwarder, matcher QueryMatcher, writer CacheWriter) *Proxy {
	return &Proxy{forwarder: forwarder, matcher: matcher, writer: writer}
}

func (p *Proxy) HandleApplicationQuery(queryName string, family IPFamily, now time.Time) error {
	response, err := p.forwarder.Forward(queryName)
	if err != nil {
		return err
	}
	return ProcessResponse(response, family, now, p.matcher, p.writer)
}

func PlanCacheWrites(request PlanRequest) ([]CacheWrite, error) {
	if !request.Matched {
		return nil, nil
	}
	writes := make([]CacheWrite, 0, len(request.Response.Addresses))
	for _, address := range request.Response.Addresses {
		if request.Family == IPv4 && !address.IP.Is4() {
			continue
		}
		if request.Family == IPv6 && !address.IP.Is6() {
			continue
		}
		ttl := address.TTL
		if ttl == 0 {
			ttl = 300
		}
		writes = append(writes, CacheWrite{
			QueryName: request.Response.QueryName,
			IP:        address.IP,
			ExpiresAt: request.Now.Add(time.Duration(ttl) * time.Second),
			Rule:      request.Rule,
		})
	}
	return writes, nil
}

func ProcessResponse(response Response, family IPFamily, now time.Time, matcher QueryMatcher, writer CacheWriter) error {
	rule, matched := matcher.Match(response.QueryName)
	writes, err := PlanCacheWrites(PlanRequest{
		Response: response,
		Matched:  matched,
		Rule:     rule,
		Family:   family,
		Now:      now,
	})
	if err != nil {
		return err
	}
	for _, write := range writes {
		if err := writer.Write(write); err != nil {
			return err
		}
	}
	return nil
}

func SelectUpstream(original netip.AddrPort, intercepted bool) (RouteDecision, error) {
	return RouteDecision{Upstream: original, Bypass: !intercepted}, nil
}

func AuthorizesNewConnection(entry CacheWrite, now time.Time) bool {
	return entry.ExpiresAt.After(now)
}
