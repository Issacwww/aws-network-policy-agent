package controllers

import (
	"errors"

	"github.com/aws/aws-network-policy-agent/pkg/filter"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/proxymanager"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"k8s.io/apimachinery/pkg/types"
)

type DNSPolicyDependencies struct {
	Filter filter.Store
	Proxy  proxymanager.ProxyManager
}

func (r *PolicyEndpointsReconciler) RemoveDNSPolicyForPod(pod types.NamespacedName) error {
	if r.proxyManager == nil {
		return nil
	}
	return r.proxyManager.RemovePod(pod)
}

func (r *PolicyEndpointsReconciler) SyncDNSPolicyForPod(
	pod npatypes.Pod,
	podIdentifier string,
	egressRules []fwrp.EbpfFirewallRules,
) error {
	if r.domainFilter == nil || r.proxyManager == nil {
		return nil
	}
	domainRules, _ := fwrp.SplitDomainAndIPRules(egressRules)
	r.domainFilter.SetRules(podIdentifier, filter.PolicyEndpointSource, domainRules)
	return r.proxyManager.SyncPod(pod, podIdentifier)
}

func (r *ClusterPolicyEndpointsReconciler) SyncDNSPolicyForPod(
	pod npatypes.Pod,
	podIdentifier string,
	egressRules []fwrp.EbpfFirewallRules,
) error {
	if r.domainFilter == nil || r.proxyManager == nil {
		return nil
	}
	domainRules, _ := fwrp.SplitDomainAndIPRules(egressRules)
	r.domainFilter.SetRules(podIdentifier, filter.ClusterPolicyEndpointSource, domainRules)
	return r.proxyManager.SyncPod(pod, podIdentifier)
}

func syncDNSPolicyForPods(
	rules filter.Store,
	proxy proxymanager.ProxyManager,
	source filter.Source,
	podIdentifier string,
	domainRules []fwrp.EbpfFirewallRules,
	pods []npatypes.Pod,
) error {
	if rules == nil || proxy == nil {
		return nil
	}
	rules.SetRules(podIdentifier, source, domainRules)
	var syncErr error
	for _, pod := range pods {
		if utils.GetPodIdentifier(pod.Name, pod.Namespace) != podIdentifier {
			continue
		}
		syncErr = errors.Join(syncErr, proxy.SyncPod(pod, podIdentifier))
	}
	return syncErr
}

func disableDNSPolicyForPods(
	rules filter.Store,
	proxy proxymanager.ProxyManager,
	source filter.Source,
	podIdentifier string,
	pods []npatypes.Pod,
) error {
	if rules == nil || proxy == nil {
		return nil
	}
	rules.DeleteRules(podIdentifier, source)
	var syncErr error
	for _, pod := range pods {
		if utils.GetPodIdentifier(pod.Name, pod.Namespace) != podIdentifier {
			continue
		}
		syncErr = errors.Join(syncErr, proxy.SyncPod(pod, podIdentifier))
	}
	return syncErr
}
