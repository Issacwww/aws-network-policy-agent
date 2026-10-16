package cdnsproxy

import (
	"context"
	"fmt"

	_ "github.com/aws/aws-network-policy-agent/pkg/cdns-proxy/plugins/ipfilter"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/forward"
	_ "github.com/coredns/coredns/plugin/health"
	_ "github.com/coredns/coredns/plugin/log"
)

func init() {
	dnsserver.Directives = append([]string{"ipfilter"}, dnsserver.Directives...)
}

type DNSProxy struct {
	log           logger.Logger
	ebpfClient    ebpf.BpfClient
	enableIPv6    bool
	upstreamAddr  string
	listenerAddr  string
	caddyInstance *caddy.Instance
}

func NewDNSProxy(log logger.Logger, ebpfClient ebpf.BpfClient, enableIPv6 bool, upstreamAddr, listenerAddr string) *DNSProxy {
	return &DNSProxy{
		log:          log,
		ebpfClient:   ebpfClient,
		enableIPv6:   enableIPv6,
		upstreamAddr: upstreamAddr,
		listenerAddr: listenerAddr,
	}
}

func (p *DNSProxy) Start(_ context.Context, corefileContent string) error {
	p.log.Infof("starting dns proxy with Corefile content %s", corefileContent)
	instance, err := caddy.Start(&Input{corefile: []byte(corefileContent)})
	if err != nil {
		return fmt.Errorf("error is starting dns proxy %w", err)
	}
	p.caddyInstance = instance
	p.log.Infof("started dns proxy")
	return nil
}

func (p *DNSProxy) Stop() error {
	p.log.Info("stopping dns proxy")
	if p.caddyInstance == nil {
		return nil
	}
	return p.caddyInstance.Stop()
}

type Input struct {
	corefile []byte
}

func NewInput(corefile string) *Input {
	return &Input{corefile: []byte(corefile)}
}

func (i *Input) Body() []byte       { return i.corefile }
func (i *Input) Path() string       { return "Corefile" }
func (i *Input) ServerType() string { return "dns" }
