package config

import (
	"testing"

	"github.com/spf13/pflag"
)

func TestDNSPolicyCanBeEnabledByFlag(t *testing.T) {
	cfg := &ControllerConfig{}
	flags := pflag.NewFlagSet("dns-policy", pflag.ContinueOnError)
	cfg.BindFlags(flags)

	if flags.Lookup("enable-dns-policy") == nil {
		t.Fatal("expected --enable-dns-policy flag to be registered")
	}
	if err := flags.Parse([]string{"--enable-dns-policy=true"}); err != nil {
		t.Fatalf("parse --enable-dns-policy: %v", err)
	}
	if !cfg.EnableDNSPolicy {
		t.Fatal("ControllerConfig.EnableDNSPolicy = false after parsing true")
	}
}

func TestDNSPolicyAutoSelectorsAreAvailable(t *testing.T) {
	cfg := &ControllerConfig{}
	flags := pflag.NewFlagSet("dns-policy-auto", pflag.ContinueOnError)
	cfg.BindFlags(flags)
	if err := flags.Parse([]string{
		"--dns-policy-nft-priority=-100",
		"--dns-policy-upstream-source=bottlerocket",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ValidControllerFlags(); err != nil {
		t.Fatal(err)
	}
	if cfg.DNSPolicyNftPriority != -100 {
		t.Fatalf("nft priority = %d, want Auto -100", cfg.DNSPolicyNftPriority)
	}
	if cfg.DNSPolicyUpstreamSource != "bottlerocket" {
		t.Fatalf("upstream source = %q, want bottlerocket", cfg.DNSPolicyUpstreamSource)
	}
}

func TestDNSPolicyOSSSelectorsRemainDefaults(t *testing.T) {
	cfg := &ControllerConfig{}
	flags := pflag.NewFlagSet("dns-policy-oss", pflag.ContinueOnError)
	cfg.BindFlags(flags)
	if cfg.DNSPolicyNftPriority != -110 {
		t.Fatalf("default nft priority = %d, want OSS -110", cfg.DNSPolicyNftPriority)
	}
	if cfg.DNSPolicyUpstreamSource != "kube-dns" {
		t.Fatalf("default upstream source = %q, want kube-dns", cfg.DNSPolicyUpstreamSource)
	}
}
