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
