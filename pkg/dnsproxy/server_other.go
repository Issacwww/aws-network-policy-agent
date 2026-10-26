//go:build !linux

package dnsproxy

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"net"
)

type Handler func(context.Context, net.IP, string, *dns.Msg) (*dns.Msg, error)
type Server struct{}

func Start(context.Context, string, string, Handler) (*Server, error) {
	return nil, fmt.Errorf("DNS interception requires Linux")
}
func (*Server) Close() {}
