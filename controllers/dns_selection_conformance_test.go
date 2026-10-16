package controllers

import (
	"testing"

	policyendpoint "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAutoConformanceCPEKeepsHostNetworkSelectionAsymmetry(t *testing.T) {
	reconciler := &ClusterPolicyEndpointsReconciler{nodeIP: "10.0.0.1"}
	cpe := &policyendpoint.ClusterPolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "cpe-host-network"},
		Spec: policyendpoint.ClusterPolicyEndpointSpec{
			PodSelectorEndpoints: []policyendpoint.PodEndpoint{{
				Name:      "host-network-pod",
				Namespace: "default",
				HostIP:    "10.0.0.1",
				PodIP:     "10.0.0.1",
			}},
		},
	}

	pods, identifiers := reconciler.deriveClusterPolicyTargetPods(cpe, []string{cpe.Name})
	if len(pods) != 1 || pods[0].Name != "host-network-pod" {
		t.Fatalf("CPE target pods = %#v, want Auto's hostNetwork selection", pods)
	}
	podIdentifier := utils.GetPodIdentifier("host-network-pod", "default")
	if !identifiers[podIdentifier] {
		t.Fatalf("CPE identifiers = %#v, want %s", identifiers, podIdentifier)
	}
}
