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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlFakeClient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestLBK8sBackendClusterReconciler_SecretNotFound(t *testing.T) {
	scheme := clientgoscheme.Scheme
	require.NoError(t, isovalentv1alpha1.AddToScheme(scheme))

	c := ctrlFakeClient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&isovalentv1alpha1.LBK8sBackendCluster{}).
		Build()

	r := &lbK8sBackendClusterReconciler{
		client: c,
		logger: slog.New(slog.DiscardHandler),
	}

	cluster := &isovalentv1alpha1.LBK8sBackendCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster",
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

	require.NoError(t, c.Create(context.Background(), cluster))

	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster"},
	})
	require.NoError(t, err)

	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "test-cluster"}, cluster))
	require.NotNil(t, cluster.Status.Status)
	require.Equal(t, isovalentv1alpha1.ExtLBResourceStatusConditionNotMet, *cluster.Status.Status)

	connectedCondition := cluster.GetStatusCondition(isovalentv1alpha1.ConditionTypeClusterConnected)
	require.NotNil(t, connectedCondition)
	require.Equal(t, metav1.ConditionFalse, connectedCondition.Status)
	require.Equal(t, isovalentv1alpha1.ClusterConnectedReasonConnectionFailed, connectedCondition.Reason)
}

func TestLBK8sBackendClusterReconciler_SecretMissingKubeconfigKey(t *testing.T) {
	scheme := clientgoscheme.Scheme
	require.NoError(t, isovalentv1alpha1.AddToScheme(scheme))

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"wrongkey": []byte("some-data"),
		},
	}

	c := ctrlFakeClient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&isovalentv1alpha1.LBK8sBackendCluster{}).
		WithObjects(secret).
		Build()

	r := &lbK8sBackendClusterReconciler{
		client: c,
		logger: slog.New(slog.DiscardHandler),
	}

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

	require.NoError(t, c.Create(context.Background(), cluster))

	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster"},
	})
	require.NoError(t, err)

	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "test-cluster"}, cluster))
	require.NotNil(t, cluster.Status.Status)
	require.Equal(t, isovalentv1alpha1.ExtLBResourceStatusConditionNotMet, *cluster.Status.Status)

	connectedCondition := cluster.GetStatusCondition(isovalentv1alpha1.ConditionTypeClusterConnected)
	require.NotNil(t, connectedCondition)
	require.Equal(t, metav1.ConditionFalse, connectedCondition.Status)
	require.Equal(t, isovalentv1alpha1.ClusterConnectedReasonConnectionFailed, connectedCondition.Reason)
}

func TestLBK8sBackendClusterReconciler_ClusterNotFound(t *testing.T) {
	scheme := clientgoscheme.Scheme
	require.NoError(t, isovalentv1alpha1.AddToScheme(scheme))

	c := ctrlFakeClient.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&isovalentv1alpha1.LBK8sBackendCluster{}).
		Build()

	r := &lbK8sBackendClusterReconciler{
		client: c,
		logger: slog.New(slog.DiscardHandler),
	}

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent-cluster"},
	})
	require.NoError(t, err)
	require.False(t, result.Requeue)
	require.Zero(t, result.RequeueAfter)
}
