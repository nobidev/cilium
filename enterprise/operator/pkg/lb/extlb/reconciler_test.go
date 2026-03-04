//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package extlb

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlFakeClient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

const nonexistentClusterName = "does-not-exist"

func newTestScheme(t *testing.T) *runtime.Scheme {
	scheme := clientgoscheme.Scheme
	require.NoError(t, isovalentv1alpha1.AddToScheme(scheme))
	return scheme
}

func newTestRemoteClusterManager(logger *slog.Logger) *remoteClusterManager {
	return &remoteClusterManager{
		logger:   logger,
		clusters: make(map[string]*remoteCluster),
	}
}

func TestLBK8sBackendClusterReconciler_ClusterNotFound(t *testing.T) {
	scheme := newTestScheme(t)

	c := ctrlFakeClient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&isovalentv1alpha1.LBK8sBackendCluster{}).
		Build()

	remoteMgr := newTestRemoteClusterManager(slog.New(slog.DiscardHandler))

	r := newLBK8sBackendClusterReconciler(
		slog.New(slog.DiscardHandler),
		c,
		scheme,
		remoteMgr,
		Config{},
	)

	// Reconcile a cluster that doesn't exist - should succeed with no-op
	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent-cluster"},
	})
	require.NoError(t, err)
	require.False(t, result.Requeue)
	require.Zero(t, result.RequeueAfter)
}

func TestLBK8sBackendClusterReconciler_AddsFinalizer(t *testing.T) {
	scheme := newTestScheme(t)

	cluster := &isovalentv1alpha1.LBK8sBackendCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster",
		},
		Spec: isovalentv1alpha1.LBK8sBackendClusterSpec{
			Authentication: isovalentv1alpha1.LBK8sBackendClusterAuth{
				SecretRef: isovalentv1alpha1.LBK8sBackendClusterSecretRef{
					Name:      "test-secret",
					Namespace: "default",
				},
			},
		},
	}

	c := ctrlFakeClient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&isovalentv1alpha1.LBK8sBackendCluster{}).
		WithObjects(cluster).
		Build()

	remoteMgr := newTestRemoteClusterManager(slog.New(slog.DiscardHandler))

	r := newLBK8sBackendClusterReconciler(
		slog.New(slog.DiscardHandler),
		c,
		scheme,
		remoteMgr,
		Config{},
	)

	// First reconcile should add the finalizer
	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster"},
	})
	require.NoError(t, err)
	require.False(t, result.Requeue)

	var updated isovalentv1alpha1.LBK8sBackendCluster
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "test-cluster"}, &updated))
	require.Contains(t, updated.Finalizers, k8sBackendClusterFinalizer)
}

func TestLBK8sBackendClusterReconciler_SecretNotFound(t *testing.T) {
	scheme := newTestScheme(t)

	cluster := &isovalentv1alpha1.LBK8sBackendCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-cluster",
			Finalizers: []string{k8sBackendClusterFinalizer},
		},
		Spec: isovalentv1alpha1.LBK8sBackendClusterSpec{
			Authentication: isovalentv1alpha1.LBK8sBackendClusterAuth{
				SecretRef: isovalentv1alpha1.LBK8sBackendClusterSecretRef{
					Name:      "missing-secret",
					Namespace: "default",
				},
			},
		},
	}

	c := ctrlFakeClient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&isovalentv1alpha1.LBK8sBackendCluster{}).
		WithObjects(cluster).
		Build()

	remoteMgr := newTestRemoteClusterManager(slog.New(slog.DiscardHandler))

	r := newLBK8sBackendClusterReconciler(
		slog.New(slog.DiscardHandler),
		c,
		scheme,
		remoteMgr,
		Config{},
	)

	// Reconcile should fail to find the secret
	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster"},
	})
	require.NoError(t, err)

	// Check that status was updated with error
	var updated isovalentv1alpha1.LBK8sBackendCluster
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "test-cluster"}, &updated))
	require.NotNil(t, updated.Status.Status)
	require.Equal(t, isovalentv1alpha1.ExtLBResourceStatusConditionNotMet, *updated.Status.Status)

	// Check that the condition was set
	require.Len(t, updated.Status.Conditions, 1)
	require.Equal(t, isovalentv1alpha1.ConditionTypeClusterConnected, updated.Status.Conditions[0].Type)
	require.Equal(t, metav1.ConditionFalse, updated.Status.Conditions[0].Status)
}

func TestLBK8sBackendClusterReconciler_Deletion(t *testing.T) {
	scheme := newTestScheme(t)

	now := metav1.Now()
	cluster := &isovalentv1alpha1.LBK8sBackendCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cluster",
			Finalizers:        []string{k8sBackendClusterFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: isovalentv1alpha1.LBK8sBackendClusterSpec{
			Authentication: isovalentv1alpha1.LBK8sBackendClusterAuth{
				SecretRef: isovalentv1alpha1.LBK8sBackendClusterSecretRef{
					Name:      "test-secret",
					Namespace: "default",
				},
			},
		},
	}

	c := ctrlFakeClient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&isovalentv1alpha1.LBK8sBackendCluster{}).
		WithObjects(cluster).
		Build()

	remoteMgr := newTestRemoteClusterManager(slog.New(slog.DiscardHandler))

	r := newLBK8sBackendClusterReconciler(
		slog.New(slog.DiscardHandler),
		c,
		scheme,
		remoteMgr,
		Config{},
	)

	// Reconcile should handle deletion and remove finalizer
	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster"},
	})
	require.NoError(t, err)
	require.False(t, result.Requeue)

	var updated isovalentv1alpha1.LBK8sBackendCluster
	err = c.Get(context.Background(), types.NamespacedName{Name: "test-cluster"}, &updated)
	require.True(t, k8serrors.IsNotFound(err), "expected object to be deleted after finalizer removal")
}

func TestUpdateCondition_AddsNew(t *testing.T) {
	conditions := updateCondition(nil,
		isovalentv1alpha1.ConditionTypeClusterConnected,
		metav1.ConditionTrue,
		"Connected",
		"cluster is connected",
	)

	require.Len(t, conditions, 1)
	require.Equal(t, isovalentv1alpha1.ConditionTypeClusterConnected, conditions[0].Type)
	require.Equal(t, metav1.ConditionTrue, conditions[0].Status)
	require.Equal(t, "Connected", conditions[0].Reason)
	require.Equal(t, "cluster is connected", conditions[0].Message)
	require.False(t, conditions[0].LastTransitionTime.IsZero())
}

func TestUpdateCondition_UpdatesExisting(t *testing.T) {
	oldTime := metav1.Now()
	conditions := []metav1.Condition{
		{
			Type:               isovalentv1alpha1.ConditionTypeClusterConnected,
			Status:             metav1.ConditionTrue,
			Reason:             "Connected",
			Message:            "cluster is connected",
			LastTransitionTime: oldTime,
		},
	}

	conditions = updateCondition(conditions,
		isovalentv1alpha1.ConditionTypeClusterConnected,
		metav1.ConditionFalse,
		"ConnectionError",
		"connection lost",
	)

	require.Len(t, conditions, 1)
	require.Equal(t, metav1.ConditionFalse, conditions[0].Status)
	require.Equal(t, "ConnectionError", conditions[0].Reason)
	require.Equal(t, "connection lost", conditions[0].Message)
	// LastTransitionTime should be updated since the status changed
	require.NotEqual(t, oldTime, conditions[0].LastTransitionTime)
}

func TestUpdateCondition_NoOpWhenUnchanged(t *testing.T) {
	oldTime := metav1.Now()
	conditions := []metav1.Condition{
		{
			Type:               isovalentv1alpha1.ConditionTypeClusterConnected,
			Status:             metav1.ConditionTrue,
			Reason:             "Connected",
			Message:            "cluster is connected",
			LastTransitionTime: oldTime,
		},
	}

	conditions = updateCondition(conditions,
		isovalentv1alpha1.ConditionTypeClusterConnected,
		metav1.ConditionTrue,
		"Connected",
		"cluster is connected",
	)

	require.Len(t, conditions, 1)
	// LastTransitionTime should be preserved since nothing changed
	require.Equal(t, oldTime, conditions[0].LastTransitionTime)
}

func TestNodeIPChanged(t *testing.T) {
	makeNode := func(ips ...string) *corev1.Node {
		var addrs []corev1.NodeAddress
		for _, ip := range ips {
			addrs = append(addrs, corev1.NodeAddress{
				Type:    corev1.NodeInternalIP,
				Address: ip,
			})
		}
		return &corev1.Node{
			Status: corev1.NodeStatus{Addresses: addrs},
		}
	}

	// Same IP — no change
	require.False(t, nodeIPChanged(makeNode("10.0.0.1"), makeNode("10.0.0.1")))

	// Different IP — changed
	require.True(t, nodeIPChanged(makeNode("10.0.0.1"), makeNode("10.0.0.2")))

	// IP added where there was none
	require.True(t, nodeIPChanged(makeNode(), makeNode("10.0.0.1")))

	// IP removed
	require.True(t, nodeIPChanged(makeNode("10.0.0.1"), makeNode()))

	// Both empty — no change
	require.False(t, nodeIPChanged(makeNode(), makeNode()))

	// Node with only ExternalIP — nodeIPChanged checks InternalIP only
	externalOnly := &corev1.Node{
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
			},
		},
	}
	require.False(t, nodeIPChanged(externalOnly, externalOnly))
}

func TestRemoteClusterManager_StopNonexistent(t *testing.T) {
	mgr := newTestRemoteClusterManager(slog.New(slog.DiscardHandler))
	// Should not panic
	mgr.Stop(nonexistentClusterName)
}

func TestRemoteClusterManager_GetClientNotFound(t *testing.T) {
	mgr := newTestRemoteClusterManager(slog.New(slog.DiscardHandler))
	_, err := mgr.GetClient(nonexistentClusterName)
	require.Error(t, err)
	require.Contains(t, err.Error(), nonexistentClusterName)
}

func TestFindLBK8sBackendClustersForSecret(t *testing.T) {
	scheme := newTestScheme(t)

	cluster1 := &isovalentv1alpha1.LBK8sBackendCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-1"},
		Spec: isovalentv1alpha1.LBK8sBackendClusterSpec{
			Authentication: isovalentv1alpha1.LBK8sBackendClusterAuth{
				SecretRef: isovalentv1alpha1.LBK8sBackendClusterSecretRef{
					Name: "shared-secret", Namespace: "default",
				},
			},
		},
	}
	cluster2 := &isovalentv1alpha1.LBK8sBackendCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-2"},
		Spec: isovalentv1alpha1.LBK8sBackendClusterSpec{
			Authentication: isovalentv1alpha1.LBK8sBackendClusterAuth{
				SecretRef: isovalentv1alpha1.LBK8sBackendClusterSecretRef{
					Name: "shared-secret", Namespace: "default",
				},
			},
		},
	}
	cluster3 := &isovalentv1alpha1.LBK8sBackendCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-3"},
		Spec: isovalentv1alpha1.LBK8sBackendClusterSpec{
			Authentication: isovalentv1alpha1.LBK8sBackendClusterAuth{
				SecretRef: isovalentv1alpha1.LBK8sBackendClusterSecretRef{
					Name: "other-secret", Namespace: "default",
				},
			},
		},
	}

	c := ctrlFakeClient.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster1, cluster2, cluster3).
		Build()

	remoteMgr := newTestRemoteClusterManager(slog.New(slog.DiscardHandler))
	r := newLBK8sBackendClusterReconciler(
		slog.New(slog.DiscardHandler), c, scheme, remoteMgr, Config{},
	)

	// Secret matching cluster-1 and cluster-2
	matchingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-secret", Namespace: "default"},
	}
	requests := r.findLBK8sBackendClustersForSecret(context.Background(), matchingSecret)
	require.Len(t, requests, 2)

	names := map[string]bool{}
	for _, req := range requests {
		names[req.Name] = true
	}
	require.True(t, names["cluster-1"])
	require.True(t, names["cluster-2"])

	// Secret matching no clusters
	unmatchedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "no-match", Namespace: "default"},
	}
	requests = r.findLBK8sBackendClustersForSecret(context.Background(), unmatchedSecret)
	require.Empty(t, requests)
}
