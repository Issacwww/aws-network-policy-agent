/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"os"
	"time"

	cnirpc "github.com/aws/amazon-vpc-cni-k8s/rpc"
	"github.com/aws/aws-network-policy-agent/pkg/discovery"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/filter"
	"github.com/aws/aws-network-policy-agent/pkg/proxymanager"
	"github.com/aws/aws-network-policy-agent/pkg/rpc"
	"github.com/aws/aws-network-policy-agent/pkg/rpcclient"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-network-policy-agent/pkg/utils/imds"
	"github.com/aws/aws-network-policy-agent/pkg/version"
	"github.com/samber/lo"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aws/aws-network-policy-agent/pkg/logger"

	"github.com/spf13/pflag"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/controllers"
	"github.com/aws/aws-network-policy-agent/pkg/config"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	//+kubebuilder:scaffold:imports
)

var (
	scheme                       = runtime.NewScheme()
	LOCAL_IPAMD_ADDRESS          = "unix:///var/run/aws-node/ipamd.sock"
	LOCAL_IPAMD_FALLBACK_ADDRESS = "127.0.0.1:50051"
	localIPAMDAddresses          = []string{LOCAL_IPAMD_ADDRESS, LOCAL_IPAMD_FALLBACK_ADDRESS}
	localIPAMDAttemptTimeout     = 2 * time.Second
	npaSocketPath                = "/var/run/aws-node/npa.sock"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(policyk8sawsv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	initLogger := logger.New("info", "", logger.DEFAULT_LOG_FILE_MAX_SIZE, logger.DEFAULT_LOG_FILE_MAX_BACKUPS)

	ctrlConfig, err := loadControllerConfig()
	if err != nil {
		initLogger.Errorf("unable to load policy endpoint controller config %v", err)
		os.Exit(1)
	}
	log := logger.New(ctrlConfig.LogLevel, ctrlConfig.LogFile, ctrlConfig.LogFileMaxSize, ctrlConfig.LogFileMaxBackups)
	log.Infof("Starting network policy agent: %s, log level: %s", version.String(), ctrlConfig.LogLevel)

	ctrl.SetLogger(logger.GetControllerRuntimeLogger())
	if ctrlConfig.EnableProfiling {
		go func() {
			log.Errorf("failed to setup pprof server: %v", http.ListenAndServe("localhost:6060", nil))
		}()
	}
	restCFG, err := config.BuildRestConfig(ctrlConfig.RuntimeConfig)
	if err != nil {
		log.Errorf("unable to build REST config %v", err)
		os.Exit(1)
	}

	runtimeOpts := config.BuildRuntimeOptions(ctrlConfig.RuntimeConfig, scheme)
	mgr, err := ctrl.NewManager(restCFG, runtimeOpts)
	if err != nil {
		log.Errorf("unable to create controller manager %v", err)
		os.Exit(1)
	}

	err = ctrlConfig.ValidControllerFlags()
	if err != nil {
		log.Errorf("Controller flags validation failed %v", err)
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()

	var policyEndpointController *controllers.PolicyEndpointsReconciler
	var clusterPolicyEndpointController *controllers.ClusterPolicyEndpointsReconciler
	var dnsProxyManager proxymanager.ProxyManager
	if ctrlConfig.EnableNetworkPolicy {
		log.Info("Network Policy is enabled, registering controllers...")

		var nodeIP string
		if !ctrlConfig.EnableIPv6 {
			nodeIP = lo.Must1(imds.GetMetaData("local-ipv4"))
		} else {
			nodeIP = lo.Must1(imds.GetMetaData("ipv6"))
		}

		npMode, isMultiNICEnabled := lo.Must2(getNetworkPolicyConfigsFromIpamd(ctx, log))

		ebpfClient := lo.Must1(ebpf.NewBpfClient(ctx, nodeIP, ctrlConfig.EnablePolicyEventLogs, ctrlConfig.EnableCloudWatchLogs,
			ctrlConfig.EnableIPv6, ctrlConfig.EnableDNSPolicy, ctrlConfig.ConntrackCacheCleanupPeriod, ctrlConfig.ConntrackCacheTableSize, npMode, isMultiNICEnabled, ctrlConfig.LogLevel))
		ebpfClient.ReAttachEbpfProbes()

		var dnsDependencies []controllers.DNSPolicyDependencies
		if ctrlConfig.EnableDNSPolicy {
			if ctrlConfig.EnableIPv6 {
				log.Error("DNS policy is only supported for IPv4 in S1")
				os.Exit(1)
			}
			upstream, err := dnsPolicyUpstream(ctrlConfig.DNSPolicyUpstreamSource, os.Getenv)
			if err != nil {
				log.Errorf("Failed to discover DNS upstream: %v", err)
				os.Exit(1)
			}
			filter.BpfClient = ebpfClient
			filter.IsIPv6 = ctrlConfig.EnableIPv6
			domainFilter := filter.DefaultStore()
			dnsProxyManager, err = proxymanager.New(
				log,
				domainFilter,
				ebpfClient,
				upstream,
				ctrlConfig.EnableIPv6,
				ctrlConfig.DNSPolicyNftPriority,
			)
			if err != nil {
				log.Errorf("Failed to initialize DNS policy proxy: %v", err)
				os.Exit(1)
			}
			defer dnsProxyManager.Stop()
			dnsDependencies = append(dnsDependencies, controllers.DNSPolicyDependencies{
				Filter: domainFilter,
				Proxy:  dnsProxyManager,
			})
		}

		policyEndpointController = controllers.NewPolicyEndpointsReconciler(
			mgr.GetClient(), nodeIP, ebpfClient, ctrlConfig.EnableIPv6, dnsDependencies...,
		)

		if err = policyEndpointController.SetupWithManager(ctx, mgr); err != nil {
			log.Errorf("unable to create controller PolicyEndpoints %v", err)
			os.Exit(1)
		}

		clusterPolicyEndpointController = controllers.NewClusterPolicyEndpointsReconciler(
			mgr.GetClient(), nodeIP, ebpfClient, dnsDependencies...,
		)
		if err = clusterPolicyEndpointController.SetupWithManager(ctx, mgr); err != nil {
			log.Errorf("unable to create controller ClusterPolicyEndpoints %v", err)
			os.Exit(1)
		}

		readyzPaths := []string{ebpf.CONNTRACK_MAP_PIN_PATH, ebpf.POLICY_EVENTS_MAP_PIN_PATH}
		if err := mgr.AddReadyzCheck("bpf-maps", ebpf.NewGlobalMapsReadinessCheck(readyzPaths)); err != nil {
			log.Errorf("unable to set up bpf-maps readiness check %v", err)
			os.Exit(1)
		}

		if err := mgr.AddReadyzCheck("bpf-fs", ebpf.NewBpfFsReadinessCheck(ebpf.BPF_FS_ROOT)); err != nil {
			log.Errorf("unable to set up bpf-fs readiness check %v", err)
			os.Exit(1)
		}
		if err := mgr.AddHealthzCheck("dns-proxy", func(_ *http.Request) error {
			if dnsProxyManager == nil {
				return nil
			}
			return dnsProxyManager.HealthCheckDNSProxy()
		}); err != nil {
			log.Errorf("unable to set up DNS proxy health check %v", err)
			os.Exit(1)
		}
	} else {
		log.Info("Network Policy is disabled, skip the controller registration")
	}

	//+kubebuilder:scaffold:builder

	// The gRPC server runs whether or not network policy is enabled, so its
	// health checks are registered unconditionally. The checker is created once
	// and shared between the liveness and readiness probes.
	grpcHealthChecker, err := rpc.NewGRPCSocketHealthChecker(npaSocketPath)
	if err != nil {
		log.Errorf("unable to set up gRPC socket health checker %v", err)
		os.Exit(1)
	}
	defer grpcHealthChecker.Close()

	if err := mgr.AddHealthzCheck("grpc-socket", grpcHealthChecker.Check); err != nil {
		log.Errorf("unable to set up gRPC socket health check %v", err)
		os.Exit(1)
	}

	if err := mgr.AddReadyzCheck("grpc-socket", grpcHealthChecker.Check); err != nil {
		log.Errorf("unable to set up grpc-socket readiness check %v", err)
		os.Exit(1)
	}

	// CNI makes rpc calls to NP agent regardless NP is enabled or not
	// need to start rpc always
	// todo: add a liveness probe to this gRPC server and remove closing based on this errCh, liveness probe will check and re-start this container
	errCh, err := rpc.RunRPCHandler(policyEndpointController, clusterPolicyEndpointController, npaSocketPath)
	if err != nil {
		log.Errorf("Failed to set up gRPC Handler %v", err)
		os.Exit(1)
	}
	go func() {
		if err := <-errCh; err != nil {
			log.Errorf("gRPC server stopped: %v", err)
			os.Exit(1)
		}
	}()

	log.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		log.Errorf("problem running manager %v", err)
		os.Exit(1)
	}

}

func kubeDNSUpstream(getenv func(string) string) (netip.AddrPort, error) {
	rawIP := getenv("KUBE_DNS_SERVICE_HOST")
	upstreamIP, err := netip.ParseAddr(rawIP)
	if err != nil || !upstreamIP.Is4() {
		return netip.AddrPort{}, fmt.Errorf("KUBE_DNS_SERVICE_HOST is not a valid IPv4 address: %q", rawIP)
	}
	return netip.AddrPortFrom(upstreamIP, 53), nil
}

func dnsPolicyUpstream(source string, getenv func(string) string) (netip.AddrPort, error) {
	if source == "kube-dns" {
		return kubeDNSUpstream(getenv)
	}
	dnsIPs, err := discovery.GetDNSIPs("ipv4")
	if err != nil {
		return netip.AddrPort{}, err
	}
	upstream, ok := netip.AddrFromSlice(dnsIPs[0].To4())
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("Bottlerocket DNS upstream is not IPv4: %s", dnsIPs[0])
	}
	return netip.AddrPortFrom(upstream, 53), nil
}

// loadControllerConfig loads the controller configuration
func loadControllerConfig() (config.ControllerConfig, error) {
	controllerConfig := config.ControllerConfig{}
	fs := pflag.NewFlagSet("", pflag.ExitOnError)
	controllerConfig.BindFlags(fs)

	if err := fs.Parse(os.Args); err != nil {
		return controllerConfig, err
	}

	return controllerConfig, nil
}

func getNetworkPolicyConfigsFromIpamd(ctx context.Context, log logger.Logger) (string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	return getNetworkPolicyConfigsFromAddresses(
		ctx,
		localIPAMDAddresses,
		localIPAMDAttemptTimeout,
		func(attemptCtx context.Context, address string) (string, bool, error) {
			log.Infof("Trying to establish GRPC connection to ipamd at %s", address)
			grpcConn, err := rpcclient.New().Dial(
				attemptCtx,
				address,
				rpcclient.GetDefaultServiceRetryConfig(),
				rpcclient.GetInsecureConnectionType(),
			)
			if err != nil {
				return "", false, err
			}
			defer grpcConn.Close()

			ipamd := cnirpc.NewConfigServerBackendClient(grpcConn)
			resp, err := ipamd.GetNetworkPolicyConfigs(attemptCtx, &emptypb.Empty{})
			if err != nil {
				return "", false, err
			}
			if !utils.IsValidNetworkPolicyEnforcingMode(resp.NetworkPolicyMode) {
				return "", false, errors.New("invalid Network Policy Mode")
			}
			log.Infof(
				"Connected to ipamd at %s. NetworkPolicyMode: %s MultiNICEnabled: %v",
				address,
				resp.NetworkPolicyMode,
				resp.MultiNICEnabled,
			)
			return resp.NetworkPolicyMode, resp.MultiNICEnabled, nil
		},
	)
}

func getNetworkPolicyConfigsFromAddresses(
	ctx context.Context,
	addresses []string,
	attemptTimeout time.Duration,
	fetch func(context.Context, string) (string, bool, error),
) (string, bool, error) {
	if len(addresses) == 0 {
		return "", false, errors.New("no ipamd addresses configured")
	}

	var lastErr error
	for ctx.Err() == nil {
		for _, address := range addresses {
			attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
			networkPolicyMode, multiNICEnabled, err := fetch(attemptCtx, address)
			cancel()
			if err == nil {
				return networkPolicyMode, multiNICEnabled, nil
			}
			lastErr = fmt.Errorf("ipamd at %s: %w", address, err)
			if ctx.Err() != nil {
				break
			}
		}
	}

	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return "", false, fmt.Errorf("failed to get network policy configs: %w", lastErr)
}
