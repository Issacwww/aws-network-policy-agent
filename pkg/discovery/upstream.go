package discovery

import (
	"fmt"
	"net"
	"os"
)

const (
	// UpstreamSourceKubeDNS selects the kube-dns Service IP, which kubelet injects into the node agent
	// as KUBE_DNS_SERVICE_HOST. This is the default on EC2 nodes.
	UpstreamSourceKubeDNS = "kube-dns"
	// UpstreamSourceBottlerocket selects the cluster DNS IP from the Bottlerocket settings, as in EKS Auto Mode.
	UpstreamSourceBottlerocket = "bottlerocket"

	kubeDNSServiceHostEnv = "KUBE_DNS_SERVICE_HOST"
)

// ResolveDNSPolicyUpstream reports whether DNS policy can run on this node and, if it can, the
// address its proxy forwards queries to. It returns a reason to log whenever DNS policy stays off.
//
// DNS policy is IPv4 only for now, and it needs the address of the cluster DNS service. When
// either is missing the agent keeps enforcing everything else instead of failing: it serves the
// socket the CNI plugin calls on every pod setup, so exiting here would stop new pods from
// starting on the node. The controllers then skip domainName entries, as before DNS policy
// support, and an operator sees the reason in the agent log.
func ResolveDNSPolicyUpstream(source string, enableIPv6 bool) (upstreamIP net.IP, enabled bool, reason string) {
	if enableIPv6 {
		return nil, false, "DNS policy is not supported on IPv6 clusters"
	}
	upstreamIP, err := GetUpstreamDNSIP(source)
	if err != nil {
		return nil, false, fmt.Sprintf("the upstream DNS server could not be discovered (source %s): %v", source, err)
	}
	return upstreamIP, true, ""
}

// GetUpstreamDNSIP returns the IPv4 address the DNS policy proxy forwards queries to.
func GetUpstreamDNSIP(source string) (net.IP, error) {
	switch source {
	case UpstreamSourceKubeDNS:
		return getKubeDNSServiceIP(os.Getenv)
	case UpstreamSourceBottlerocket:
		dnsIPs, err := GetDNSIPs("ipv4")
		if err != nil {
			return nil, err
		}
		return dnsIPs[0], nil
	default:
		return nil, fmt.Errorf("unsupported DNS upstream source %q, should be %s or %s", source, UpstreamSourceKubeDNS, UpstreamSourceBottlerocket)
	}
}

func getKubeDNSServiceIP(getenv func(string) string) (net.IP, error) {
	value := getenv(kubeDNSServiceHostEnv)
	if value == "" {
		return nil, fmt.Errorf("%s is not set: kubelet sets it only when the kube-dns Service exists in the node agent's namespace "+
			"when the container starts, and the pod does not disable enableServiceLinks", kubeDNSServiceHostEnv)
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("%s=%q is not an IPv4 address", kubeDNSServiceHostEnv, value)
	}
	return ip, nil
}
