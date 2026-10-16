package controllers

import (
	"context"
	"path/filepath"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestDomainOnlyEndpointsReachTheReconcilerThroughEnvtest(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := policyk8sawsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("register policy API scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("register core API scheme: %v", err)
	}

	testEnvironment := &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "config", "crd", "bases")},
	}
	restConfig, err := testEnvironment.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		if err := testEnvironment.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})

	k8sClient, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("create envtest client: %v", err)
	}
	if err := k8sClient.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "ns-a"},
	}); err != nil {
		t.Fatalf("create envtest namespace: %v", err)
	}

	t.Run("PolicyEndpoint domain-only egress is programmed", func(t *testing.T) {
		pe := &policyk8sawsv1.PolicyEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: "np-a-abcde", Namespace: "ns-a"},
			Spec: policyk8sawsv1.PolicyEndpointSpec{
				PolicyRef: policyk8sawsv1.PolicyReference{Name: "np-a", Namespace: "ns-a"},
				PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{{
					Name: "pod-a", Namespace: "ns-a", HostIP: "10.0.0.1", PodIP: "10.0.0.10",
				}},
				Egress: []policyk8sawsv1.EndpointInfo{{DomainName: "api.example.com"}},
			},
		}
		if err := k8sClient.Create(context.Background(), pe); err != nil {
			t.Fatalf("create PolicyEndpoint: %v", err)
		}

		bpfClient := &ebpf.MockBpfClient{}
		reconciler := NewPolicyEndpointsReconciler(k8sClient, "10.0.0.1", bpfClient, false)
		_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: pe.Name, Namespace: pe.Namespace},
		})
		if err != nil {
			t.Fatalf("reconcile PolicyEndpoint: %v", err)
		}
		if len(bpfClient.LastEgressRules) != 1 {
			t.Fatalf("programmed egress rule count = %d, want domain-only rule from envtest object", len(bpfClient.LastEgressRules))
		}
		if bpfClient.LastEgressRules[0].DomainName != "api.example.com" {
			t.Fatalf("programmed domain = %q, want api.example.com", bpfClient.LastEgressRules[0].DomainName)
		}
	})

	t.Run("ClusterPolicyEndpoint domain-only egress preserves tier metadata", func(t *testing.T) {
		cpe := &policyk8sawsv1.ClusterPolicyEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: "cnp-a-abcde"},
			Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
				PolicyRef: policyk8sawsv1.ClusterPolicyReference{Name: "cnp-a"},
				Tier:      policyk8sawsv1.BaselineTier,
				Priority:  10,
				PodSelectorEndpoints: []policyk8sawsv1.PodEndpoint{{
					Name: "pod-b", Namespace: "ns-a", HostIP: "10.0.0.1", PodIP: "10.0.0.11",
				}},
				Egress: []policyk8sawsv1.ClusterEndpointInfo{{
					DomainName: "api.example.com",
					Action:     policyk8sawsv1.ClusterNetworkPolicyRuleActionAccept,
				}},
			},
		}
		if err := k8sClient.Create(context.Background(), cpe); err != nil {
			t.Fatalf("create ClusterPolicyEndpoint: %v", err)
		}

		bpfClient := &ebpf.MockBpfClient{}
		reconciler := NewClusterPolicyEndpointsReconciler(k8sClient, "10.0.0.1", bpfClient)
		_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: cpe.Name},
		})
		if err != nil {
			t.Fatalf("reconcile ClusterPolicyEndpoint: %v", err)
		}
		if len(bpfClient.LastClusterPolicyEgressRules) != 1 {
			t.Fatalf("programmed cluster egress rule count = %d, want domain-only rule from envtest object", len(bpfClient.LastClusterPolicyEgressRules))
		}
		got := bpfClient.LastClusterPolicyEgressRules[0]
		if got.DomainName != "api.example.com" || got.Priority != 2010 {
			t.Fatalf("programmed cluster domain metadata = domain %q priority %d, want api.example.com/2010", got.DomainName, got.Priority)
		}
	})
}
