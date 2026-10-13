package main

import (
	"testing"

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
