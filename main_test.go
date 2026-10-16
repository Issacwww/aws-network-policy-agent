package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKubeDNSUpstreamFromServiceLink(t *testing.T) {
	upstream, err := kubeDNSUpstream(func(name string) string {
		if name == "KUBE_DNS_SERVICE_HOST" {
			return "10.100.0.10"
		}
		return ""
	}, false)

	require.NoError(t, err)
	assert.Equal(t, "10.100.0.10:53", upstream.String())
}

func TestKubeDNSUpstreamRejectsMissingOrIPv6ServiceLink(t *testing.T) {
	for _, value := range []string{"", "2001:db8::53"} {
		_, err := kubeDNSUpstream(func(string) string { return value }, false)
		assert.Error(t, err)
	}
}

func TestKubeDNSUpstreamSupportsIPv6ServiceLink(t *testing.T) {
	upstream, err := kubeDNSUpstream(func(string) string { return "2001:db8::53" }, true)

	require.NoError(t, err)
	assert.Equal(t, "[2001:db8::53]:53", upstream.String())
}

func TestDNSPolicyUpstreamDiscoveryUsesSelectedFamily(t *testing.T) {
	tests := []struct {
		name       string
		enableIPv6 bool
		discovered []net.IP
		wantFamily string
		want       string
	}{
		{
			name:       "IPv4",
			discovered: []net.IP{net.ParseIP("10.100.0.10")},
			wantFamily: "ipv4",
			want:       "10.100.0.10:53",
		},
		{
			name:       "IPv6",
			enableIPv6: true,
			discovered: []net.IP{net.ParseIP("2001:db8::53")},
			wantFamily: "ipv6",
			want:       "[2001:db8::53]:53",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotFamily string
			upstream, err := dnsPolicyUpstreamWithDiscovery(
				"bottlerocket",
				tt.enableIPv6,
				func(string) string { return "" },
				func(family string) ([]net.IP, error) {
					gotFamily = family
					return tt.discovered, nil
				},
			)
			require.NoError(t, err)
			assert.Equal(t, tt.wantFamily, gotFamily)
			assert.Equal(t, tt.want, upstream.String())
		})
	}
}

func TestDNSPolicyUpstreamDiscoveryRejectsEmptyAndWrongFamilyResults(t *testing.T) {
	tests := []struct {
		name       string
		enableIPv6 bool
		discovered []net.IP
	}{
		{name: "empty IPv4 result"},
		{name: "IPv6 requested but IPv4 returned", enableIPv6: true, discovered: []net.IP{net.ParseIP("10.0.0.10")}},
		{name: "IPv4 requested but IPv6 returned", discovered: []net.IP{net.ParseIP("2001:db8::10")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := dnsPolicyUpstreamWithDiscovery(
				"bottlerocket",
				tt.enableIPv6,
				func(string) string { return "" },
				func(string) ([]net.IP, error) { return tt.discovered, nil },
			)
			assert.Error(t, err)
		})
	}
}

func TestGetNetworkPolicyConfigsFallsBackAcrossAddresses(t *testing.T) {
	var calls []string
	networkPolicyMode, multiNICEnabled, err := getNetworkPolicyConfigsFromAddresses(
		context.Background(),
		[]string{"unix:///var/run/aws-node/ipamd.sock", "127.0.0.1:50051"},
		time.Second,
		func(_ context.Context, address string) (string, bool, error) {
			calls = append(calls, address)
			if address == "unix:///var/run/aws-node/ipamd.sock" {
				return "", false, errors.New("socket unavailable")
			}
			return "standard", false, nil
		},
	)

	require.NoError(t, err)
	assert.Equal(t, "standard", networkPolicyMode)
	assert.False(t, multiNICEnabled)
	assert.Equal(t, []string{
		"unix:///var/run/aws-node/ipamd.sock",
		"127.0.0.1:50051",
	}, calls)
}
