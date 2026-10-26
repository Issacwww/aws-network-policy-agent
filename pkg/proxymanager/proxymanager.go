package proxymanager

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/aws/aws-network-policy-agent/pkg/dnsproxy"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/filter"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"k8s.io/apimachinery/pkg/types"
)

const table = "dns_policy_poc"

type ProxyManager interface {
	AddDNSRedirectionRulesForPod(npatypes.Pod, string) error
	RemoveDNSRedirectionRulesForPod(types.NamespacedName, string) error
	ForceRemoveDNSRedirectionRulesForPod(types.NamespacedName, string) error
	HealthCheckDNSProxy() error
}
type proxyManager struct {
	mu      sync.Mutex
	mode    string
	server  *dnsproxy.Server
	cancel  context.CancelFunc
	pods    map[string]string
	started bool
	err     error
}

// Retain the port's constructor surface; resolver discovery is deliberately unused.
func NewProxyManager(_ logger.Logger, _ ebpf.BpfClient, _ bool, _ net.IP, _ int, _ net.IP, _ int, _ string, _ int32) ProxyManager {
	return &proxyManager{mode: os.Getenv("DNS_POLICY_INTERCEPTION"), pods: map[string]string{}}
}
func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return nil
}
func nft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w: %s", err, out)
	}
	return nil
}
func (pm *proxyManager) start() error {
	if pm.started {
		return nil
	}
	if pm.mode != "dnat" && pm.mode != "tproxy" && pm.mode != "hybrid" {
		return fmt.Errorf("set DNS_POLICY_INTERCEPTION to dnat, tproxy or hybrid")
	}
	// Refuse to take ownership of pre-existing experiment state; cleanup is explicit.
	if exec.Command("nft", "list", "table", "ip", table).Run() == nil {
		return fmt.Errorf("table %s already exists; inspect and clean up the previous experiment", table)
	}
	var natResolvers []string
	if pm.mode == "hybrid" {
		for _, raw := range strings.Split(os.Getenv("DNS_POLICY_DNAT_RESOLVERS"), ",") {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip == nil || ip.To4() == nil {
				return fmt.Errorf("hybrid requires explicit IPv4 DNS_POLICY_DNAT_RESOLVERS")
			}
			natResolvers = append(natResolvers, ip.String())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	pm.cancel = cancel
	s, err := dnsproxy.Start(ctx, "0.0.0.0:50052", pm.mode, dnsproxy.Handle)
	if err != nil {
		cancel()
		return err
	}
	pm.server = s
	script := "add table ip " + table + "\nadd set ip " + table + " pods { type ifname . ipv4_addr; }\n"
	if pm.mode == "dnat" || pm.mode == "hybrid" {
		destination := ""
		if pm.mode == "hybrid" {
			script += "add set ip " + table + " nat_resolvers { type ipv4_addr; elements = { " + strings.Join(natResolvers, ", ") + " }; }\n"
			destination = "ip daddr @nat_resolvers "
		}
		script += "add chain ip " + table + " pre { type nat hook prerouting priority -110; policy accept; }\nadd rule ip " + table + " pre iifname . ip saddr @pods " + destination + "meta l4proto { udp, tcp } th dport 53 dnat to 169.254.29.53:50052\n"
		if err = run("ip", "address", "add", "169.254.29.53/32", "dev", "lo"); err != nil {
			cancel()
			s.Close()
			return err
		}
	}
	if pm.mode != "dnat" {
		if err = run("ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "2053"); err != nil {
			cancel()
			s.Close()
			return err
		}
		if err = run("ip", "rule", "add", "priority", "1053", "fwmark", "0x20000000/0x20000000", "lookup", "2053"); err != nil {
			cancel()
			s.Close()
			run("ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "2053")
			return err
		}
		// Keep this transparent client leg out of later kube-proxy Service NAT.
		// Only intercepted Pod DNS and its replies are untracked; upstream sockets
		// use the normal node routing/Service translation path.
		transparentDest := ""
		if pm.mode == "hybrid" {
			transparentDest = "ip daddr != @nat_resolvers "
		}
		script += "add chain ip " + table + " rawpre { type filter hook prerouting priority -310; policy accept; }\nadd rule ip " + table + " rawpre iifname . ip saddr @pods " + transparentDest + "meta l4proto { udp, tcp } th dport 53 notrack\n"
		script += "add chain ip " + table + " rawout { type filter hook output priority -310; policy accept; }\nadd rule ip " + table + " rawout oifname . ip daddr @pods meta l4proto { udp, tcp } th sport 53 notrack\n"
		script += "add chain ip " + table + " transparent { type filter hook prerouting priority -150; policy accept; }\nadd rule ip " + table + " transparent iifname . ip saddr @pods " + transparentDest + "meta l4proto { udp, tcp } th dport 53 tproxy to :50052 meta mark set meta mark | 0x20000000 accept\n"
	}
	if err = nft(script); err != nil {
		cancel()
		s.Close()
		pm.cleanupRouting()
		return err
	}
	pm.started = true
	return nil
}
func (pm *proxyManager) cleanupRouting() {
	if pm.mode == "dnat" || pm.mode == "hybrid" {
		run("ip", "address", "del", "169.254.29.53/32", "dev", "lo")
	}
	if pm.mode != "dnat" {
		run("ip", "rule", "del", "priority", "1053", "fwmark", "0x20000000/0x20000000", "lookup", "2053")
		run("ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "2053")
	}
}
func (pm *proxyManager) Close() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if !pm.started {
		return
	}
	run("nft", "delete", "table", "ip", table)
	pm.cleanupRouting()
	pm.cancel()
	pm.server.Close()
	pm.started = false
}
func (pm *proxyManager) AddDNSRedirectionRulesForPod(pod npatypes.Pod, id string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if err := pm.start(); err != nil {
		pm.err = err
		return err
	}
	ip := net.ParseIP(string(pod.PodIP))
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("IPv4 pod required")
	}
	if old := pm.pods[pod.String()]; strings.HasSuffix(old, " . "+ip.String()) {
		return nil
	} else if old != "" {
		return fmt.Errorf("pod address changed before cleanup")
	}
	// Only packets arriving from this Pod's VPC-CNI veth may enter its proxy path.
	iface, err := utils.GetHostVethName(pod.Name, pod.Namespace, 0, []string{ebpf.POD_VETH_PREFIX, ebpf.BRANCH_ENI_VETH_PREFIX})
	if err != nil {
		return err
	}
	filter.SetPodIPToPodId(ip.String(), id)
	if err := nft("add element ip " + table + " pods { " + fmt.Sprintf("%q . %s", iface, ip.String()) + " }"); err != nil {
		filter.DeletePodIPToPodIdEntry(ip.String())
		return err
	}
	pm.pods[pod.String()] = fmt.Sprintf("%q . %s", iface, ip.String())
	pm.err = nil
	return nil
}
func (pm *proxyManager) RemoveDNSRedirectionRulesForPod(pod types.NamespacedName, id string) error {
	if filter.HasAnyDomainRules(id) {
		return nil
	}
	return pm.ForceRemoveDNSRedirectionRulesForPod(pod, id)
}
func (pm *proxyManager) ForceRemoveDNSRedirectionRulesForPod(pod types.NamespacedName, _ string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	ip := pm.pods[pod.String()]
	if ip == "" {
		return nil
	}
	if err := nft("delete element ip " + table + " pods { " + ip + " }"); err != nil {
		return err
	}
	filter.DeletePodIPToPodIdEntry(strings.Split(ip, " . ")[1])
	delete(pm.pods, pod.String())
	return nil
}
func (pm *proxyManager) HealthCheckDNSProxy() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.err
}
