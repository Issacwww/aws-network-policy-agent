package config

import (
	"errors"
	"fmt"

	"github.com/aws/aws-network-policy-agent/pkg/discovery"
	"github.com/aws/aws-network-policy-agent/pkg/logger"

	"github.com/spf13/pflag"
)

const (
	flagLogLevel                       = "log-level"
	flagLogFile                        = "log-file"
	flagLogFileMaxSize                 = "log-file-max-size"
	flagLogFileMaxBackups              = "log-file-max-backups"
	flagMaxConcurrentReconciles        = "max-concurrent-reconciles"
	defaultLogLevel                    = "debug"
	defaultLogFile                     = "/var/log/aws-routed-eni/network-policy-agent.log"
	defaultLogFileMaxSize              = logger.DEFAULT_LOG_FILE_MAX_SIZE
	defaultLogFileMaxBackups           = logger.DEFAULT_LOG_FILE_MAX_BACKUPS
	defaultMaxConcurrentReconciles     = 3
	defaultConntrackCacheCleanupPeriod = 300
	defaultConntrackCacheTableSize     = 512 * 1024
	flagEnablePolicyEventLogs          = "enable-policy-event-logs"
	flagEnableCloudWatchLogs           = "enable-cloudwatch-logs"
	flagEnableIPv6                     = "enable-ipv6"
	flagEnableNetworkPolicy            = "enable-network-policy"
	flagConntrackCacheCleanupPeriod    = "conntrack-cache-cleanup-period"
	flagConntrackCacheTableSize        = "conntrack-cache-table-size"
	flagEnableProfiling                = "enable-profiling"
	flagDNSPolicyUpstreamSource        = "dns-policy-upstream-source"
	flagDNSPolicyNftPriority           = "dns-policy-nft-priority"
	// DNSPolicyNftPriorityEC2 places the DNS redirect DNAT ahead of kube-proxy's Service DNAT (-100),
	// so a pod's query to the kube-dns Service IP is redirected before kube-proxy rewrites it.
	DNSPolicyNftPriorityEC2 = -110
	// DNSPolicyNftPriorityAuto is the standard dstnat priority used by EKS Auto Mode.
	DNSPolicyNftPriorityAuto = -100
)

// ControllerConfig contains the controller configuration
type ControllerConfig struct {
	// Log level for the controller logs
	LogLevel string
	// Local log file for Network Policy Agent
	LogFile string
	// Network Policy Agent local log file max size
	LogFileMaxSize int
	// Count of rotated Network Policy Agent local log files
	LogFileMaxBackups int
	// MaxConcurrentReconciles specifies the max number of reconcile loops
	MaxConcurrentReconciles int
	// Enable Policy decision logs
	EnablePolicyEventLogs bool
	// Enable Policy decision logs streaming to CloudWatch
	EnableCloudWatchLogs bool
	// Enable IPv6 mode
	EnableIPv6 bool
	// Enable Network Policy
	EnableNetworkPolicy bool
	// ConntrackCacheCleanupPeriod specifies the cleanup period
	ConntrackCacheCleanupPeriod int
	// ConntrackTableSize specifies the conntrack table size for the agent
	ConntrackCacheTableSize int
	// Configurations for the Controller Runtime
	RuntimeConfig RuntimeConfig
	// Configuration for enabling profiling
	EnableProfiling bool
	// DNSPolicyUpstreamSource selects where the DNS proxy upstream comes from: discovery.UpstreamSourceKubeDNS
	// or discovery.UpstreamSourceBottlerocket
	DNSPolicyUpstreamSource string
	// DNSPolicyNftPriority is the priority of the nftables chain that redirects pod DNS traffic to the DNS proxy
	DNSPolicyNftPriority int
}

func (cfg *ControllerConfig) BindFlags(fs *pflag.FlagSet) {
	fs.StringVar(&cfg.LogLevel, flagLogLevel, defaultLogLevel,
		"Set the controller log level - info, debug")
	fs.StringVar(&cfg.LogFile, flagLogFile, defaultLogFile, ""+
		"Set the controller log file - if not specified logs are written to stdout")
	fs.IntVar(&cfg.LogFileMaxSize, flagLogFileMaxSize, defaultLogFileMaxSize, ""+
		"Set the controller log file max size in megabytes before it gets rotated")
	fs.IntVar(&cfg.LogFileMaxBackups, flagLogFileMaxBackups, defaultLogFileMaxBackups, ""+
		"Set the controller maximum number of rotated log files to retain")
	fs.IntVar(&cfg.MaxConcurrentReconciles, flagMaxConcurrentReconciles, defaultMaxConcurrentReconciles, ""+
		"Maximum number of concurrent reconcile loops")
	fs.BoolVar(&cfg.EnablePolicyEventLogs, flagEnablePolicyEventLogs, false, "If enabled, policy decision logs will be collected & logged")
	fs.BoolVar(&cfg.EnableCloudWatchLogs, flagEnableCloudWatchLogs, false, "If enabled, policy decision logs will be streamed to CloudWatch, requires \"enable-policy-event-logs=true\"")
	fs.BoolVar(&cfg.EnableIPv6, flagEnableIPv6, false, "If enabled, Network Policy agent will operate in IPv6 mode")
	fs.BoolVar(&cfg.EnableNetworkPolicy, flagEnableNetworkPolicy, false, "If enabled, Network Policy agent will initialize BPF maps and start reconciler")
	fs.BoolVar(&cfg.EnableProfiling, flagEnableProfiling, false, "If enabled, Network Policy agent will enable profiling")
	fs.StringVar(&cfg.DNSPolicyUpstreamSource, flagDNSPolicyUpstreamSource, discovery.UpstreamSourceKubeDNS, ""+
		"Upstream DNS server for the DNS policy proxy - kube-dns (kube-dns Service IP) or bottlerocket (Bottlerocket settings)")
	fs.IntVar(&cfg.DNSPolicyNftPriority, flagDNSPolicyNftPriority, DNSPolicyNftPriorityEC2, ""+
		"Priority of the nftables chain that redirects pod DNS traffic to the DNS policy proxy - -110 or -100")
	fs.IntVar(&cfg.ConntrackCacheCleanupPeriod, flagConntrackCacheCleanupPeriod, defaultConntrackCacheCleanupPeriod, ""+
		"Cleanup interval for network policy agent conntrack cache")
	fs.IntVar(&cfg.ConntrackCacheTableSize, flagConntrackCacheTableSize, defaultConntrackCacheTableSize, ""+
		"Table size for network policy agent conntrack cache")

	cfg.RuntimeConfig.BindFlags(fs)
}

// Validate controller flags
func (cfg *ControllerConfig) ValidControllerFlags() error {
	// Validate conntrack cache table size
	if cfg.ConntrackCacheTableSize < (32*1024) || cfg.ConntrackCacheTableSize > (1024*1024) {
		return errors.New("Invalid conntrack cache table size, should be between 32K and 1024K")
	}
	if cfg.DNSPolicyUpstreamSource != discovery.UpstreamSourceKubeDNS && cfg.DNSPolicyUpstreamSource != discovery.UpstreamSourceBottlerocket {
		return fmt.Errorf("Invalid DNS policy upstream source %q, should be %s or %s", cfg.DNSPolicyUpstreamSource,
			discovery.UpstreamSourceKubeDNS, discovery.UpstreamSourceBottlerocket)
	}
	if cfg.DNSPolicyNftPriority != DNSPolicyNftPriorityEC2 && cfg.DNSPolicyNftPriority != DNSPolicyNftPriorityAuto {
		return fmt.Errorf("Invalid DNS policy nft priority %d, should be %d or %d", cfg.DNSPolicyNftPriority,
			DNSPolicyNftPriorityEC2, DNSPolicyNftPriorityAuto)
	}
	return nil
}
