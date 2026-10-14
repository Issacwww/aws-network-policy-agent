package discovery

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/aws/aws-network-policy-agent/pkg/logger"
)

func log() logger.Logger {
	return logger.Get()
}

func GetDNSIPs(ipFamily string) ([]net.IP, error) {
	userData, err := parseUserData()
	if err != nil {
		return nil, fmt.Errorf("error in getting userdata %w", err)
	}

	uniqueDNSIPs := make(map[string]struct{})
	for _, serviceCIDR := range userData.Coredns.ServiceCIDR {
		if dnsIP, err := cidrToIP(serviceCIDR); err == nil {
			uniqueDNSIPs[dnsIP] = struct{}{}
		} else {
			log().Errorf("Failed to parse CIDR: %v", err)
		}
	}
	for _, dnsIP := range userData.Kubernetes.ClusterDNSIP.IPs {
		uniqueDNSIPs[dnsIP] = struct{}{}
	}

	var result []net.IP
	for dnsIP := range uniqueDNSIPs {
		ip := net.ParseIP(dnsIP)
		if ip == nil {
			continue
		}
		if strings.ToLower(ipFamily) == "ipv4" && ip.To4() != nil {
			result = append(result, ip)
		} else if strings.ToLower(ipFamily) == "ipv6" && ip.To4() == nil && ip.To16() != nil {
			result = append(result, ip)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("didn't found any DNS Service IP for IPFamily: %s", ipFamily)
	}
	return result, nil
}

type ClusterDNSIP struct {
	IPs []string
}

func (c *ClusterDNSIP) UnmarshalJSON(data []byte) error {
	var ipOrIPs any
	if err := json.Unmarshal(data, &ipOrIPs); err != nil {
		return fmt.Errorf("invalid type for ClusterDNSIP: %v", err)
	}
	switch value := ipOrIPs.(type) {
	case string:
		c.IPs = []string{value}
	case []string:
		c.IPs = value
	default:
		return fmt.Errorf("invalid type for ClusterDNSIP, expected string or slice of strings but got %v", value)
	}
	return nil
}

type UserData struct {
	Kubernetes struct {
		ClusterDNSIP ClusterDNSIP `json:"cluster-dns-ip"`
	} `json:"kubernetes"`
	Coredns struct {
		ServiceCIDR []string `json:"service-cidr"`
	} `json:"coredns"`
}

func parseUserData() (*UserData, error) {
	output, err := exec.Command("apiclient", "-u", "/settings").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute apiclient: %w", err)
	}
	var userData UserData
	if err := json.Unmarshal(output, &userData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return &userData, nil
}

func cidrToIP(cidr string) (string, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("unrecognized CIDR format: %s", cidr)
	}
	if ip.To4() != nil {
		return fmt.Sprintf("%s.10", cidr[:strings.LastIndex(cidr, ".")]), nil
	}
	if ip.To16() != nil {
		return fmt.Sprintf("%sa", strings.Split(cidr, "/")[0]), nil
	}
	return "", fmt.Errorf("unrecognized IP format: %s", ip)
}
