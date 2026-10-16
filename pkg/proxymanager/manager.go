package proxymanager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/avast/retry-go"
	cdnsproxy "github.com/aws/aws-network-policy-agent/pkg/cdns-proxy"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/filter"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
)

const (
	IPv4ListenerAddress  = "169.254.20.10:50052"
	IPv6ListenerAddress  = "[fd00::53]:50052"
	NftTableName         = "dns_redirect"
	NftChainName         = "prerouting"
	AutoNftChainPriority = -100
	OSSNftChainPriority  = -110
	NftChainPriority     = OSSNftChainPriority
	listenerLinkName     = "dnsproxy"
)

type ProxyManager interface {
	SyncPod(npatypes.Pod, string) error
	RemovePod(types.NamespacedName) error
	HealthCheckDNSProxy() error
	Stop() error
}

type productionRuleManager interface {
	Initialize() error
	Add(RedirectRequest) error
	Delete(string) error
	Cleanup() error
}

type vethResolver func(types.NamespacedName) (string, error)
type podIPResolver func(string) (string, error)

type proxyServer interface {
	Start() error
	Stop() error
}

type manager struct {
	log           logger.Logger
	rules         filter.Store
	redirects     productionRuleManager
	proxy         proxyServer
	resolveVeth   vethResolver
	resolvePodIP  podIPResolver
	setupListener func(netip.AddrPort) error
	hookPriority  int

	mu              sync.Mutex
	started         bool
	initialized     bool
	startupFailures atomic.Uint64
	podVeth         map[string]string
	podIP           map[string]string
}

func New(
	log logger.Logger,
	rules filter.Store,
	writer ebpf.BpfClient,
	upstream netip.AddrPort,
	enableIPv6 bool,
	hookPriority int,
) (ProxyManager, error) {
	listenerAddress := IPv4ListenerAddress
	if enableIPv6 {
		listenerAddress = IPv6ListenerAddress
	}
	listener := netip.MustParseAddrPort(listenerAddress)
	redirects := newNFTRules(listener, hookPriority)
	return newManager(
		log,
		rules,
		redirects,
		newCoreDNSServer(log, writer, enableIPv6, upstream, listener),
		func(pod types.NamespacedName) (string, error) {
			return utils.GetHostVethName(
				pod.Name,
				pod.Namespace,
				0,
				[]string{ebpf.POD_VETH_PREFIX, ebpf.BRANCH_ENI_VETH_PREFIX},
			)
		},
		func(interfaceName string) (string, error) {
			return resolveIPFromVeth(interfaceName, enableIPv6)
		},
		hookPriority,
	), nil
}

func newManager(
	log logger.Logger,
	rules filter.Store,
	redirects productionRuleManager,
	proxy proxyServer,
	resolveVeth vethResolver,
	resolvePodIP podIPResolver,
	hookPriority int,
) *manager {
	return &manager{
		log:           log,
		rules:         rules,
		redirects:     redirects,
		proxy:         proxy,
		resolveVeth:   resolveVeth,
		resolvePodIP:  resolvePodIP,
		setupListener: ensureListenerAddress,
		hookPriority:  hookPriority,
		podVeth:       make(map[string]string),
		podIP:         make(map[string]string),
	}
}

func (m *manager) SyncPod(pod npatypes.Pod, podIdentifier string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.rules.HasAnyDomainRules(podIdentifier) {
		return m.removePodLocked(pod.NamespacedName)
	}
	if !m.started {
		if !m.initialized {
			listener := netip.MustParseAddrPort(IPv4ListenerAddress)
			if coreDNS, ok := m.proxy.(*coreDNSServer); ok {
				listener = coreDNS.listener
			}
			if err := m.setupListener(listener); err != nil {
				m.startupFailures.Add(1)
				return err
			}
			if err := m.redirects.Initialize(); err != nil {
				m.startupFailures.Add(1)
				return fmt.Errorf("initialize DNS redirection: %w", err)
			}
			m.initialized = true
		}
		if err := m.proxy.Start(); err != nil {
			m.startupFailures.Add(1)
			return err
		}
		if err := m.checkDNSProxyHealth(); err != nil {
			m.startupFailures.Add(1)
			return err
		}
		m.started = true
	}

	podKey := pod.NamespacedName.String()
	veth, exists := m.podVeth[podKey]
	if !exists {
		var err error
		veth, err = m.resolveVeth(pod.NamespacedName)
		if err != nil {
			return fmt.Errorf("resolve host veth for pod %s: %w", podKey, err)
		}
	}

	podIP := string(pod.PodIP)
	if podIP == "" {
		var err error
		podIP, err = m.resolvePodIP(veth)
		if err != nil {
			return fmt.Errorf("resolve IPv4 address for pod %s: %w", podKey, err)
		}
	}
	parsedPodIP := net.ParseIP(podIP)
	if parsedPodIP == nil {
		return fmt.Errorf("pod %s address %q is invalid", podKey, podIP)
	}
	if coreDNS, ok := m.proxy.(*coreDNSServer); ok && coreDNS.enableIPv6 == (parsedPodIP.To4() != nil) {
		return fmt.Errorf("pod %s address %q has the wrong IP family", podKey, podIP)
	}

	if previousIP := m.podIP[podKey]; previousIP != "" && previousIP != podIP {
		m.rules.DeletePod(previousIP)
	}
	m.rules.SetPod(podIP, podIdentifier)
	m.podIP[podKey] = podIP
	if exists {
		return nil
	}

	if err := m.redirects.Add(RedirectRequest{
		HostVeth:                    veth,
		PreserveOriginalDestination: true,
		HookPriority:                m.hookPriority,
	}); err != nil {
		m.rules.DeletePod(podIP)
		delete(m.podIP, podKey)
		return fmt.Errorf("add DNS redirection for pod %s: %w", podKey, err)
	}
	m.podVeth[podKey] = veth
	return nil
}

func (m *manager) RemovePod(pod types.NamespacedName) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.removePodLocked(pod)
}

func (m *manager) removePodLocked(pod types.NamespacedName) error {
	podKey := pod.String()
	veth, ok := m.podVeth[podKey]
	if podIP := m.podIP[podKey]; podIP != "" {
		m.rules.DeletePod(podIP)
	}
	delete(m.podIP, podKey)
	if !ok {
		return nil
	}
	if err := m.redirects.Delete(veth); err != nil {
		return fmt.Errorf("delete DNS redirection for pod %s: %w", podKey, err)
	}
	delete(m.podVeth, podKey)
	return nil
}

func (m *manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	redirectErr := m.redirects.Cleanup()
	var proxyErr error
	if m.started {
		proxyErr = m.proxy.Stop()
		m.started = false
	}
	return errors.Join(redirectErr, proxyErr)
}

func (m *manager) checkDNSProxyHealth() error {
	coreDNS, ok := m.proxy.(*coreDNSServer)
	if !ok {
		return nil
	}
	client := &http.Client{Timeout: 2 * time.Second}
	return retry.Do(
		func() error {
			response, err := client.Get(coreDNS.healthURL())
			if err != nil {
				return err
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				return fmt.Errorf("DNS proxy health returned status %d", response.StatusCode)
			}
			return nil
		},
		retry.Attempts(3),
		retry.Delay(100*time.Millisecond),
		retry.DelayType(retry.BackOffDelay),
		retry.LastErrorOnly(true),
	)
}

func (m *manager) HealthCheckDNSProxy() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return m.checkDNSProxyHealth()
	}
	if failures := m.startupFailures.Load(); failures > 0 {
		return fmt.Errorf("DNS proxy has not started and has failed %d times", failures)
	}
	return nil
}

type coreDNSServer struct {
	log        logger.Logger
	client     ebpf.BpfClient
	enableIPv6 bool
	upstream   netip.AddrPort
	listener   netip.AddrPort
	proxy      *cdnsproxy.DNSProxy
}

func newCoreDNSServer(log logger.Logger, client ebpf.BpfClient, enableIPv6 bool, upstream, listener netip.AddrPort) *coreDNSServer {
	return &coreDNSServer{
		log:        log,
		client:     client,
		enableIPv6: enableIPv6,
		upstream:   upstream,
		listener:   listener,
	}
}

func (s *coreDNSServer) Start() error {
	corefile := fmt.Sprintf(`.:%d {
	bind %s
	health %s
	log . {
		class denial error
	}
	ipfilter
	forward . %s
}`, s.listener.Port(), s.listener.Addr(), s.healthAddress(), s.upstream)
	s.proxy = cdnsproxy.NewDNSProxy(s.log, s.client, s.enableIPv6, s.upstream.String(), s.listener.String())
	if err := s.proxy.Start(context.Background(), corefile); err != nil {
		return fmt.Errorf("start DNS proxy: %w", err)
	}
	return nil
}

func (s *coreDNSServer) Stop() error {
	if s.proxy == nil {
		return nil
	}
	return s.proxy.Stop()
}

func (s *coreDNSServer) healthAddress() string {
	return netip.AddrPortFrom(s.listener.Addr(), s.listener.Port()+1).String()
}

func (s *coreDNSServer) healthURL() string {
	return "http://" + s.healthAddress() + "/health"
}

type nftRules struct {
	listener     netip.AddrPort
	hookPriority int

	mu       sync.Mutex
	conn     *nftables.Conn
	table    *nftables.Table
	chain    *nftables.Chain
	selected map[string][]*nftables.Rule
}

func newNFTRules(listener netip.AddrPort, hookPriority int) *nftRules {
	return &nftRules{
		listener:     listener,
		hookPriority: hookPriority,
		selected:     make(map[string][]*nftables.Rule),
	}
}

func (n *nftRules) Initialize() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.conn = &nftables.Conn{}
	tableFamily := nftables.TableFamilyIPv4
	if n.listener.Addr().Is6() {
		tableFamily = nftables.TableFamilyIPv6
	}
	tables, err := n.conn.ListTables()
	if err != nil {
		return err
	}
	for _, table := range tables {
		if table.Family == tableFamily && table.Name == NftTableName {
			n.conn.DelTable(table)
		}
	}
	if err := n.conn.Flush(); err != nil {
		return err
	}

	n.table = n.conn.AddTable(&nftables.Table{
		Family: tableFamily,
		Name:   NftTableName,
	})
	n.chain = n.conn.AddChain(&nftables.Chain{
		Name:     NftChainName,
		Table:    n.table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(nftables.ChainPriority(n.hookPriority)),
	})
	return n.conn.Flush()
}

func (n *nftRules) Add(request RedirectRequest) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !request.PreserveOriginalDestination || request.HookPriority != n.hookPriority {
		return fmt.Errorf("invalid DNS redirect request")
	}
	if _, ok := n.selected[request.HostVeth]; ok {
		return nil
	}
	for _, protocol := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		n.conn.AddRule(&nftables.Rule{
			Table: n.table,
			Chain: n.chain,
			Exprs: n.redirectExpressions(protocol, request.HostVeth),
		})
	}
	if err := n.conn.Flush(); err != nil {
		return err
	}
	chainRules, err := n.conn.GetRules(n.table, n.chain)
	if err != nil {
		return fmt.Errorf("get DNS redirect rules: %w", err)
	}
	var addedRules []*nftables.Rule
	for _, rule := range chainRules {
		if ruleMatchesInterface(rule, request.HostVeth) {
			addedRules = append(addedRules, rule)
		}
	}
	n.selected[request.HostVeth] = addedRules
	return nil
}

func (n *nftRules) Delete(hostVeth string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	rules, ok := n.selected[hostVeth]
	if !ok {
		return nil
	}
	for _, rule := range rules {
		if err := n.conn.DelRule(rule); err != nil {
			return err
		}
	}
	if err := n.conn.Flush(); err != nil {
		return err
	}
	delete(n.selected, hostVeth)
	return nil
}

func (n *nftRules) Cleanup() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conn == nil || n.table == nil {
		return nil
	}
	n.conn.DelTable(n.table)
	if err := n.conn.Flush(); err != nil {
		return err
	}
	n.table = nil
	n.chain = nil
	n.selected = make(map[string][]*nftables.Rule)
	return nil
}

func (n *nftRules) redirectExpressions(protocol byte, interfaceName string) []expr.Any {
	listenerIP := n.listener.Addr().AsSlice()
	protocolOffset := uint32(9)
	natFamily := uint32(nftables.TableFamilyIPv4)
	if n.listener.Addr().Is6() {
		protocolOffset = 6
		natFamily = uint32(nftables.TableFamilyIPv6)
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte(interfaceName),
		},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: protocolOffset, Len: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 53}},
		&expr.Immediate{Register: 1, Data: listenerIP},
		&expr.Immediate{Register: 2, Data: []byte{byte(n.listener.Port() >> 8), byte(n.listener.Port())}},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      natFamily,
			RegAddrMin:  1,
			RegProtoMin: 2,
		},
	}
}

func ruleMatchesInterface(rule *nftables.Rule, interfaceName string) bool {
	for index, expression := range rule.Exprs {
		meta, ok := expression.(*expr.Meta)
		if !ok || meta.Key != expr.MetaKeyIIFNAME || index+1 >= len(rule.Exprs) {
			continue
		}
		comparison, ok := rule.Exprs[index+1].(*expr.Cmp)
		if ok && comparison.Op == expr.CmpOpEq && string(comparison.Data) == interfaceName {
			return true
		}
	}
	return false
}

func ensureListenerAddress(listener netip.AddrPort) error {
	link, err := netlink.LinkByName(listenerLinkName)
	if err != nil {
		dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: listenerLinkName}}
		if err := netlink.LinkAdd(dummy); err != nil {
			return fmt.Errorf("create DNS listener interface: %w", err)
		}
		link, err = netlink.LinkByName(listenerLinkName)
		if err != nil {
			return fmt.Errorf("find DNS listener interface: %w", err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring DNS listener interface up: %w", err)
	}
	prefixLength := 32
	if listener.Addr().Is6() {
		prefixLength = 128
	}
	address := &netlink.Addr{IPNet: &net.IPNet{
		IP:   net.IP(listener.Addr().AsSlice()),
		Mask: net.CIDRMask(prefixLength, prefixLength),
	}}
	if err := netlink.AddrAdd(link, address); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("assign DNS listener address: %w", err)
	}
	return nil
}

func resolveIPFromVeth(interfaceName string, enableIPv6 bool) (string, error) {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return "", err
	}
	family := netlink.FAMILY_V4
	bits := 32
	if enableIPv6 {
		family = netlink.FAMILY_V6
		bits = 128
	}
	routes, err := netlink.RouteList(link, family)
	if err != nil {
		return "", err
	}
	for _, route := range routes {
		if route.Dst == nil || enableIPv6 == (route.Dst.IP.To4() != nil) {
			continue
		}
		ones, routeBits := route.Dst.Mask.Size()
		if ones == bits && routeBits == bits {
			return route.Dst.IP.String(), nil
		}
	}
	return "", fmt.Errorf("no host route found on interface %s", interfaceName)
}

var _ ProxyManager = (*manager)(nil)
