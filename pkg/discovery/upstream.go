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
