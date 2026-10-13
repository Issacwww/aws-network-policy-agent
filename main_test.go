package main

import (
	"context"
	"errors"
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
	})

	require.NoError(t, err)
	assert.Equal(t, "10.100.0.10:53", upstream.String())
}

func TestKubeDNSUpstreamRejectsMissingOrIPv6ServiceLink(t *testing.T) {
	for _, value := range []string{"", "2001:db8::53"} {
		_, err := kubeDNSUpstream(func(string) string { return value })
		assert.Error(t, err)
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
