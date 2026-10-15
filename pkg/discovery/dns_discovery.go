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

// This is adaptation from CoreDNS bootstrap service in EKS Auto.
func GetDNSIPs(ipFamily string) ([]net.IP, error) {
	userData, err := parseUserData()
	if err != nil {
		return nil, fmt.Errorf("error in getting userdata %w", err)
	}

	uniqueDnsIps := make(map[string]struct{})
	for _, serviceCidr := range userData.Coredns.ServiceCidr {
		if dnsIp, err := cidrToIP(serviceCidr); err == nil {
			uniqueDnsIps[dnsIp] = struct{}{}
		} else {
			log().Errorf("Failed to parse CIDR: %v", err)
		}
	}

	for _, dnsIp := range userData.Kubernetes.ClusterDNSIP.IPs {
		uniqueDnsIps[dnsIp] = struct{}{}
	}

	log().Infof("Unique DNS Service IPs %v", uniqueDnsIps)

	var result []net.IP
	for dnsIP := range uniqueDnsIps {
		ip := net.ParseIP(dnsIP)
		if ip == nil {
			continue
		}

		// Filter based on IP family
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
	var ipOrIPs interface{}
	if err := json.Unmarshal(data, &ipOrIPs); err != nil {
		return fmt.Errorf("invalid type for ClusterDNSIP: %v", err)
	}

	switch v := ipOrIPs.(type) {
	case string:
		c.IPs = []string{v}
	case []string:
		c.IPs = v
	default:
		return fmt.Errorf("invalid type for ClusterDNSIP, expect string or sclice of strings but get %v", v)
	}
	return nil
}

type UserData struct {
	Kubernetes struct {
		ClusterDNSIP ClusterDNSIP `json:"cluster-dns-ip"`
	} `json:"kubernetes"`
	Coredns struct {
		ServiceCidr []string `json:"service-cidr"`
	} `json:"coredns"`
}

func parseUserData() (*UserData, error) {
	cmd := exec.Command("apiclient", "-u", "/settings")
	output, err := cmd.Output()
	if err != nil {
		log().Errorf("Failed to execute apiclient: %v", err)
		return nil, fmt.Errorf("failed to execute apiclient: %w", err)
	}

	var userData UserData
	if err := json.Unmarshal(output, &userData); err != nil {
		log().Errorf("Failed to parse JSON: %v", err)
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return &userData, nil
}

// cidrToIP convert service cidr to cluster dns Ip for configuring coredns
// Ipv4: replace last byte to `10`
// Ipv6: append `a` at the end
// behavior align with AL2 https://github.com/awslabs/amazon-eks-ami/blob/main/templates/al2/runtime/bootstrap.sh#L462-L485
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
