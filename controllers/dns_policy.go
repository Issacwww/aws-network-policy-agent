package controllers

import (
	"github.com/aws/aws-network-policy-agent/pkg/filter"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/proxymanager"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
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
