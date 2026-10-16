package networkpolicy

import (
	"context"
	"testing"

	networking "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDeleteNetworkPolicyTreatsObservedNotFoundAsSuccess(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := networking.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &networking.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "test"},
	}
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		Build()

	if err := NewManager(k8sClient).DeleteNetworkPolicy(context.Background(), policy); err != nil {
		t.Fatalf("DeleteNetworkPolicy: %v", err)
	}
	err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(policy), &networking.NetworkPolicy{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("post-delete Get error = %v, want NotFound", err)
	}
}
