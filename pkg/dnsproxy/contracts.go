package dnsproxy

import (
	"errors"
	"net/netip"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/filter"
)

var ErrNotImplemented = errors.New("DNS response planning is not implemented")

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

type Proxy struct{}

func NewProxy(QueryForwarder, QueryMatcher, CacheWriter) *Proxy {
	return &Proxy{}
}

func (p *Proxy) HandleApplicationQuery(string, IPFamily, time.Time) error {
	return ErrNotImplemented
}

func PlanCacheWrites(PlanRequest) ([]CacheWrite, error) {
	return nil, ErrNotImplemented
}

func ProcessResponse(Response, IPFamily, time.Time, QueryMatcher, CacheWriter) error {
	return ErrNotImplemented
}

func SelectUpstream(netip.AddrPort, bool) (RouteDecision, error) {
	return RouteDecision{}, ErrNotImplemented
}

func AuthorizesNewConnection(CacheWrite, time.Time) bool {
	return false
}
