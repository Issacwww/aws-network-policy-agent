package proxymanager

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/aws/aws-network-policy-agent/pkg/dnsproxy"
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
	ListenerAddress  = "169.254.171.1:50053"
	NftTableName     = "aws_npa_dns"
	NftChainName     = "prerouting"
	NftSetName       = "domain_policy_veths"
	NftChainPriority = -110
	listenerLinkName = "npa-dns"
)

type ProxyManager interface {
	SyncPod(npatypes.Pod, string) error
	RemovePod(types.NamespacedName) error
	Stop() error
}

type productionRuleManager interface {
	Add(RedirectRequest) error
	Delete(string) error
	Cleanup() error
}

type vethResolver func(types.NamespacedName) (string, error)
type podIPResolver func(string) (string, error)

type manager struct {
	rules        filter.Store
	redirects    productionRuleManager
	proxy        dnsproxy.Server
	resolveVeth  vethResolver
	resolvePodIP podIPResolver

	mu      sync.Mutex
	started bool
	podVeth map[string]string
	podIP   map[string]string
}

func New(
	log logger.Logger,
	rules filter.Store,
	writer dnsproxy.BPFWriter,
	upstream netip.AddrPort,
) (ProxyManager, error) {
	listener := netip.MustParseAddrPort(ListenerAddress)
	if err := ensureListenerAddress(listener); err != nil {
		return nil, err
	}
	redirects := newNFTRules(listener, upstream)
	if err := redirects.Initialize(); err != nil {
		return nil, fmt.Errorf("initialize DNS redirection: %w", err)
	}
	return newManager(
		rules,
		redirects,
		dnsproxy.NewServer(log, listener, upstream, rules, writer),
		func(pod types.NamespacedName) (string, error) {
			return utils.GetHostVethName(
				pod.Name,
				pod.Namespace,
				0,
				[]string{ebpf.POD_VETH_PREFIX, ebpf.BRANCH_ENI_VETH_PREFIX},
			)
		},
		resolveIPv4FromVeth,
	), nil
}

func newManager(
	rules filter.Store,
	redirects productionRuleManager,
	proxy dnsproxy.Server,
	resolveVeth vethResolver,
	resolvePodIP podIPResolver,
) *manager {
	return &manager{
		rules:        rules,
		redirects:    redirects,
		proxy:        proxy,
		resolveVeth:  resolveVeth,
		resolvePodIP: resolvePodIP,
		podVeth:      make(map[string]string),
		podIP:        make(map[string]string),
	}
}

func (m *manager) SyncPod(pod npatypes.Pod, podIdentifier string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.rules.HasAnyDomainRules(podIdentifier) {
		return m.removePodLocked(pod.NamespacedName)
	}
	if !m.started {
		if err := m.proxy.Start(); err != nil {
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
	if net.ParseIP(podIP).To4() == nil {
		return fmt.Errorf("pod %s address %q is not IPv4", podKey, podIP)
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
		HookPriority:                NftChainPriority,
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
	if !ok {
		return nil
	}
	if err := m.redirects.Delete(veth); err != nil {
		return fmt.Errorf("delete DNS redirection for pod %s: %w", podKey, err)
	}
	if podIP := m.podIP[podKey]; podIP != "" {
		m.rules.DeletePod(podIP)
	}
	delete(m.podVeth, podKey)
	delete(m.podIP, podKey)
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

type nftRules struct {
	listener netip.AddrPort
	upstream netip.AddrPort

	mu       sync.Mutex
	conn     *nftables.Conn
	table    *nftables.Table
	chain    *nftables.Chain
	vethSet  *nftables.Set
	selected map[string]struct{}
}

func newNFTRules(listener, upstream netip.AddrPort) *nftRules {
	return &nftRules{
		listener: listener,
		upstream: upstream,
		selected: make(map[string]struct{}),
	}
}

func (n *nftRules) Initialize() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.conn = &nftables.Conn{}
	tables, err := n.conn.ListTables()
	if err != nil {
		return err
	}
	for _, table := range tables {
		if table.Family == nftables.TableFamilyIPv4 && table.Name == NftTableName {
			n.conn.DelTable(table)
		}
	}
	if err := n.conn.Flush(); err != nil {
		return err
	}

	n.table = n.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   NftTableName,
	})
	n.chain = n.conn.AddChain(&nftables.Chain{
		Name:     NftChainName,
		Table:    n.table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(nftables.ChainPriority(NftChainPriority)),
	})
	n.vethSet = &nftables.Set{
		Table:   n.table,
		Name:    NftSetName,
		KeyType: nftables.TypeIFName,
	}
	if err := n.conn.AddSet(n.vethSet, nil); err != nil {
		return err
	}
	for _, protocol := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		n.conn.AddRule(&nftables.Rule{
			Table: n.table,
			Chain: n.chain,
			Exprs: n.redirectExpressions(protocol),
		})
	}
	return n.conn.Flush()
}

func (n *nftRules) Add(request RedirectRequest) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !request.PreserveOriginalDestination || request.HookPriority != NftChainPriority {
		return fmt.Errorf("invalid DNS redirect request")
	}
	if _, ok := n.selected[request.HostVeth]; ok {
		return nil
	}
	key, err := interfaceSetKey(request.HostVeth)
	if err != nil {
		return err
	}
	if err := n.conn.SetAddElements(n.vethSet, []nftables.SetElement{{Key: key}}); err != nil {
		return err
	}
	if err := n.conn.Flush(); err != nil {
		return err
	}
	n.selected[request.HostVeth] = struct{}{}
	return nil
}

func (n *nftRules) Delete(hostVeth string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.selected[hostVeth]; !ok {
		return nil
	}
	key, err := interfaceSetKey(hostVeth)
	if err != nil {
		return err
	}
	if err := n.conn.SetDeleteElements(n.vethSet, []nftables.SetElement{{Key: key}}); err != nil {
		return err
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
	n.vethSet = nil
	n.selected = make(map[string]struct{})
	return nil
}

func (n *nftRules) redirectExpressions(protocol byte) []expr.Any {
	listenerIP := n.listener.Addr().As4()
	upstreamIP := n.upstream.Addr().As4()
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        n.vethSet.Name,
			SetID:          n.vethSet.ID,
		},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: upstreamIP[:]},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 53}},
		&expr.Immediate{Register: 1, Data: listenerIP[:]},
		&expr.Immediate{Register: 2, Data: []byte{byte(n.listener.Port() >> 8), byte(n.listener.Port())}},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      uint32(nftables.TableFamilyIPv4),
			RegAddrMin:  1,
			RegProtoMin: 2,
		},
	}
}

func interfaceSetKey(interfaceName string) ([]byte, error) {
	if len(interfaceName) > 15 {
		return nil, fmt.Errorf("interface name %q exceeds 15 bytes", interfaceName)
	}
	key := make([]byte, 16)
	copy(key, interfaceName)
	return key, nil
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
	address := &netlink.Addr{IPNet: &net.IPNet{
		IP:   net.IP(listener.Addr().AsSlice()),
		Mask: net.CIDRMask(32, 32),
	}}
	if err := netlink.AddrAdd(link, address); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("assign DNS listener address: %w", err)
	}
	return nil
}

func resolveIPv4FromVeth(interfaceName string) (string, error) {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return "", err
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}
	for _, route := range routes {
		if route.Dst == nil || route.Dst.IP.To4() == nil {
			continue
		}
		ones, bits := route.Dst.Mask.Size()
		if ones == 32 && bits == 32 {
			return route.Dst.IP.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 /32 route found on interface %s", interfaceName)
}

var _ ProxyManager = (*manager)(nil)
