package config

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func parseFlags(t *testing.T, args ...string) ControllerConfig {
	t.Helper()
	cfg := ControllerConfig{}
	fs := pflag.NewFlagSet("", pflag.ContinueOnError)
	cfg.BindFlags(fs)
	assert.NoError(t, fs.Parse(args))
	return cfg
}

func TestDNSPolicyFlagDefaults(t *testing.T) {
	cfg := parseFlags(t)
	assert.Equal(t, "kube-dns", cfg.DNSPolicyUpstreamSource)
	assert.Equal(t, -110, cfg.DNSPolicyNftPriority)
	assert.NoError(t, cfg.ValidControllerFlags())
}

func TestDNSPolicyFlagValidation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name: "EC2 defaults",
			args: []string{},
		},
		{
			name: "Auto Mode values",
			args: []string{"--dns-policy-upstream-source=bottlerocket", "--dns-policy-nft-priority=-100"},
		},
		{
			name:    "unknown upstream source",
			args:    []string{"--dns-policy-upstream-source=coredns"},
			wantErr: `Invalid DNS policy upstream source "coredns"`,
		},
		{
			name:    "unsupported nft priority",
			args:    []string{"--dns-policy-nft-priority=-150"},
			wantErr: "Invalid DNS policy nft priority -150",
		},
		{
			name: "IPv6 cluster",
			args: []string{"--enable-ipv6=true"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := parseFlags(t, tt.args...)
			err := cfg.ValidControllerFlags()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}
