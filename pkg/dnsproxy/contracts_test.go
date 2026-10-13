package dnsproxy

import (
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/filter"
)

func TestOriginalDNSDestinationIsPreserved(t *testing.T) {
	tests := []struct {
		name     string
		original string
	}{
		{name: "kube dns", original: "10.100.0.10:53"},
		{name: "vpc resolver for dnsPolicy Default", original: "10.0.0.2:53"},
		{name: "custom resolver", original: "192.0.2.53:5353"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := netip.MustParseAddrPort(tt.original)
			got, err := SelectUpstream(original, true)
			if err != nil {
				t.Fatalf("SelectUpstream(%s): %v", original, err)
			}
			if got.Upstream != original {
				t.Errorf("upstream = %s, want original destination %s", got.Upstream, original)
			}
		})
	}
}

func TestOnlyMatchedQueryWritesItsAnswerAddresses(t *testing.T) {
	now := time.Unix(1000, 0)
	response := Response{
		QueryName: "alias.example.com.",
		Addresses: []AddressRecord{
			{Name: "canonical.example.net.", IP: netip.MustParseAddr("192.0.2.10"), TTL: 30},
			{Name: "canonical.example.net.", IP: netip.MustParseAddr("192.0.2.11"), TTL: 60},
		},
	}

	t.Run("matched CNAME chain attributes every A record to query name", func(t *testing.T) {
		matcher := &fakeMatcher{rule: filter.Rule{DomainName: "alias.example.com"}, matched: true}
		writer := &fakeWriter{}
		err := ProcessResponse(response, IPv4, now, matcher, writer)
		if err != nil {
			t.Fatalf("ProcessResponse: %v", err)
		}
		if matcher.query != response.QueryName {
			t.Errorf("matched query = %q, want %q", matcher.query, response.QueryName)
		}
		if len(writer.writes) != 2 {
			t.Fatalf("write count = %d, want both A records from the answer", len(writer.writes))
		}
		wantIPs := map[netip.Addr]int{
			netip.MustParseAddr("192.0.2.10"): 1,
			netip.MustParseAddr("192.0.2.11"): 1,
		}
		for _, write := range writer.writes {
			if write.QueryName != response.QueryName {
				t.Errorf("write for %s attributed to %q, want query name %q", write.IP, write.QueryName, response.QueryName)
			}
			if !reflect.DeepEqual(write.Rule, matcher.rule) {
				t.Errorf("write rule = %#v, want matcher rule %#v", write.Rule, matcher.rule)
			}
			wantIPs[write.IP]--
		}
		for ip, remaining := range wantIPs {
			if remaining != 0 {
				t.Errorf("write count delta for %s = %d, want 0", ip, remaining)
			}
		}
	})

	t.Run("unmatched query produces no writes", func(t *testing.T) {
		matcher := &fakeMatcher{}
		writer := &fakeWriter{}
		err := ProcessResponse(response, IPv4, now, matcher, writer)
		if err != nil {
			t.Fatalf("ProcessResponse: %v", err)
		}
		if len(writer.writes) != 0 {
			t.Fatalf("unmatched query write count = %d, want 0", len(writer.writes))
		}
	})
}

func TestAddressTTLContract(t *testing.T) {
	now := time.Unix(2000, 0)
	response := Response{
		QueryName: "ttl.example.com.",
		Addresses: []AddressRecord{
			{Name: "ttl.example.com.", IP: netip.MustParseAddr("192.0.2.21"), TTL: 1},
			{Name: "ttl.example.com.", IP: netip.MustParseAddr("192.0.2.22"), TTL: 30},
			{Name: "ttl.example.com.", IP: netip.MustParseAddr("192.0.2.23"), TTL: 300},
			{Name: "ttl.example.com.", IP: netip.MustParseAddr("192.0.2.24"), TTL: 0},
		},
	}

	writes, err := PlanCacheWrites(PlanRequest{
		Response: response,
		Matched:  true,
		Family:   IPv4,
		Now:      now,
	})
	if err != nil {
		t.Fatalf("PlanCacheWrites: %v", err)
	}
	if len(writes) != len(response.Addresses) {
		t.Fatalf("write count = %d, want %d records with independent TTLs", len(writes), len(response.Addresses))
	}

	wantDurations := map[netip.Addr]time.Duration{
		netip.MustParseAddr("192.0.2.21"): time.Second,
		netip.MustParseAddr("192.0.2.22"): 30 * time.Second,
		netip.MustParseAddr("192.0.2.23"): 300 * time.Second,
		netip.MustParseAddr("192.0.2.24"): 300 * time.Second,
	}
	seen := make(map[netip.Addr]int, len(wantDurations))
	for _, write := range writes {
		want, ok := wantDurations[write.IP]
		if !ok {
			t.Errorf("unexpected cache write IP %s", write.IP)
			continue
		}
		if got := write.ExpiresAt.Sub(now); got != want {
			t.Errorf("expiry duration for %s = %s, want %s", write.IP, got, want)
		}
		seen[write.IP]++
	}
	for ip := range wantDurations {
		if seen[ip] != 1 {
			t.Errorf("write count for %s = %d, want exactly 1", ip, seen[ip])
		}
	}
}

func TestNextDNSQueryRefreshesExpiry(t *testing.T) {
	firstQuery := time.Unix(2500, 0)
	response := Response{
		QueryName: "refresh.example.com.",
		Addresses: []AddressRecord{{
			Name: "refresh.example.com.",
			IP:   netip.MustParseAddr("192.0.2.25"),
			TTL:  30,
		}},
	}
	matcher := &fakeMatcher{rule: filter.Rule{DomainName: "refresh.example.com"}, matched: true}
	writer := newStatefulWriter()
	err := ProcessResponse(response, IPv4, firstQuery, matcher, writer)
	if err != nil {
		t.Fatalf("first ProcessResponse: %v", err)
	}
	first := writer.latestWrite(response.Addresses[0].IP)
	if !first.ExpiresAt.Equal(firstQuery.Add(30 * time.Second)) {
		t.Errorf("first expiry = %s, want %s", first.ExpiresAt, firstQuery.Add(30*time.Second))
	}

	nextQuery := firstQuery.Add(20 * time.Second)
	err = ProcessResponse(response, IPv4, nextQuery, matcher, writer)
	if err != nil {
		t.Fatalf("refreshed ProcessResponse: %v", err)
	}
	if writer.writeCount() != 2 {
		t.Fatalf("write count after two application queries = %d, want 2", writer.writeCount())
	}
	refreshed := writer.latestWrite(response.Addresses[0].IP)
	if !refreshed.ExpiresAt.Equal(nextQuery.Add(30 * time.Second)) {
		t.Errorf("refreshed expiry = %s, want %s", refreshed.ExpiresAt, nextQuery.Add(30*time.Second))
	}
	if !refreshed.ExpiresAt.After(first.ExpiresAt) {
		t.Errorf("refreshed expiry = %s, want after first expiry %s", refreshed.ExpiresAt, first.ExpiresAt)
	}
}

func TestProxyDoesNotActivelyRefreshExpiredEntry(t *testing.T) {
	firstQuery := time.Now()
	response := Response{
		QueryName: "passive-refresh.example.com.",
		Addresses: []AddressRecord{{
			Name: "passive-refresh.example.com.",
			IP:   netip.MustParseAddr("192.0.2.26"),
			TTL:  1,
		}},
	}
	forwarder := &countingForwarder{response: response}
	matcher := &fakeMatcher{rule: filter.Rule{DomainName: "passive-refresh.example.com"}, matched: true}
	writer := newStatefulWriter()
	proxy := NewProxy(forwarder, matcher, writer)

	if err := proxy.HandleApplicationQuery(response.QueryName, IPv4, firstQuery); err != nil {
		t.Fatalf("first HandleApplicationQuery: %v", err)
	}
	if forwarder.callCount() != 1 {
		t.Fatalf("upstream query count after application query = %d, want 1", forwarder.callCount())
	}

	deadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if forwarder.callCount() != 1 {
			t.Fatalf("proxy actively requeried after TTL expiry; upstream count = %d, want 1", forwarder.callCount())
		}
		time.Sleep(50 * time.Millisecond)
	}

	nextQuery := firstQuery.Add(2 * time.Second)
	if err := proxy.HandleApplicationQuery(response.QueryName, IPv4, nextQuery); err != nil {
		t.Fatalf("second HandleApplicationQuery: %v", err)
	}
	if forwarder.callCount() != 2 {
		t.Fatalf("upstream query count after second application query = %d, want 2", forwarder.callCount())
	}
	refreshed := writer.latestWrite(response.Addresses[0].IP)
	if !refreshed.ExpiresAt.Equal(nextQuery.Add(time.Second)) {
		t.Errorf("application-triggered refreshed expiry = %s, want %s", refreshed.ExpiresAt, nextQuery.Add(time.Second))
	}
}

func TestExpiredEntryDoesNotAuthorizeNewConnection(t *testing.T) {
	now := time.Unix(3000, 0)
	entry := CacheWrite{ExpiresAt: now.Add(time.Second)}
	if !AuthorizesNewConnection(entry, now) {
		t.Error("unexpired entry should authorize a new connection")
	}
	if AuthorizesNewConnection(entry, now.Add(time.Second)) {
		t.Error("entry at its expiry must not authorize a new connection")
	}
}

type fakeMatcher struct {
	query   string
	rule    filter.Rule
	matched bool
}

func (m *fakeMatcher) Match(query string) (filter.Rule, bool) {
	m.query = query
	return m.rule, m.matched
}

type fakeWriter struct {
	writes []CacheWrite
}

func (w *fakeWriter) Write(write CacheWrite) error {
	w.writes = append(w.writes, write)
	return nil
}

type statefulWriter struct {
	mu     sync.Mutex
	writes []CacheWrite
	latest map[netip.Addr]CacheWrite
}

func newStatefulWriter() *statefulWriter {
	return &statefulWriter{latest: make(map[netip.Addr]CacheWrite)}
}

func (w *statefulWriter) Write(write CacheWrite) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, write)
	w.latest[write.IP] = write
	return nil
}

func (w *statefulWriter) writeCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.writes)
}

func (w *statefulWriter) latestWrite(ip netip.Addr) CacheWrite {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.latest[ip]
}

type countingForwarder struct {
	calls    atomic.Int32
	response Response
}

func (f *countingForwarder) Forward(string) (Response, error) {
	f.calls.Add(1)
	return f.response, nil
}

func (f *countingForwarder) callCount() int {
	return int(f.calls.Load())
}

func TestIPv4PlanDoesNotAuthorizeIPv6Address(t *testing.T) {
	writes, err := PlanCacheWrites(PlanRequest{
		Response: Response{
			QueryName: "dual.example.com.",
			Addresses: []AddressRecord{
				{Name: "dual.example.com.", IP: netip.MustParseAddr("192.0.2.30"), TTL: 30},
				{Name: "dual.example.com.", IP: netip.MustParseAddr("2001:db8::30"), TTL: 30},
			},
		},
		Matched: true,
		Family:  IPv4,
		Now:     time.Unix(4000, 0),
	})
	if err != nil {
		t.Fatalf("PlanCacheWrites: %v", err)
	}
	if len(writes) != 1 || !writes[0].IP.Is4() {
		t.Fatalf("IPv4 write plan = %#v, want only the A record", writes)
	}
}
