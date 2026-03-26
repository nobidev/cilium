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
	"k8s.io/utils/ptr"
	ctrlFakeClient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

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

	// Check that finalizer was added
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

	// Reconcile should return an error (updateStatusError returns Fail) so the
	// controller retries, but status should still be updated.
	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster"},
	})
	require.Error(t, err)

	// Check that status was updated with error
	var updated isovalentv1alpha1.LBK8sBackendCluster
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "test-cluster"}, &updated))
	require.NotNil(t, updated.Status)
	require.NotNil(t, updated.Status.Status)
	require.Equal(t, isovalentv1alpha1.ExtLBResourceStatusConditionNotMet, *updated.Status.Status)

	// Check that the condition was set
	require.Len(t, updated.Status.Conditions, 1)
	require.Equal(t, isovalentv1alpha1.ConditionTypeClusterConnected, updated.Status.Conditions[0].Type)
	require.Equal(t, metav1.ConditionFalse, updated.Status.Conditions[0].Status)
	require.Contains(t, updated.Status.Conditions[0].Message, "authentication secret")
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

	// With the fake client, when the last finalizer is removed and DeletionTimestamp
	// is set, the object is immediately deleted. Verify the object is gone.
	var updated isovalentv1alpha1.LBK8sBackendCluster
	err = c.Get(context.Background(), types.NamespacedName{Name: "test-cluster"}, &updated)
	require.True(t, k8serrors.IsNotFound(err), "expected object to be deleted after finalizer removal")
}

func TestUpdateCondition(t *testing.T) {
	tests := []struct {
		name           string
		conditions     []metav1.Condition
		conditionType  string
		status         metav1.ConditionStatus
		reason         string
		message        string
		expectedLen    int
		expectedStatus metav1.ConditionStatus
	}{
		{
			name:           "add new condition to empty list",
			conditions:     []metav1.Condition{},
			conditionType:  "Ready",
			status:         metav1.ConditionTrue,
			reason:         "AllGood",
			message:        "Everything is fine",
			expectedLen:    1,
			expectedStatus: metav1.ConditionTrue,
		},
		{
			name: "update existing condition",
			conditions: []metav1.Condition{
				{
					Type:    "Ready",
					Status:  metav1.ConditionFalse,
					Reason:  "NotReady",
					Message: "Something wrong",
				},
			},
			conditionType:  "Ready",
			status:         metav1.ConditionTrue,
			reason:         "AllGood",
			message:        "Everything is fine",
			expectedLen:    1,
			expectedStatus: metav1.ConditionTrue,
		},
		{
			name: "add condition to existing list",
			conditions: []metav1.Condition{
				{
					Type:    "Ready",
					Status:  metav1.ConditionTrue,
					Reason:  "AllGood",
					Message: "Everything is fine",
				},
			},
			conditionType:  "Syncing",
			status:         metav1.ConditionTrue,
			reason:         "Synced",
			message:        "Data synced",
			expectedLen:    2,
			expectedStatus: metav1.ConditionTrue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := updateCondition(tt.conditions, tt.conditionType, tt.status, tt.reason, tt.message)
			require.Len(t, result, tt.expectedLen)

			// Find the condition we updated/added
			var found *metav1.Condition
			for i := range result {
				if result[i].Type == tt.conditionType {
					found = &result[i]
					break
				}
			}
			require.NotNil(t, found)
			require.Equal(t, tt.expectedStatus, found.Status)
			require.Equal(t, tt.reason, found.Reason)
			require.Equal(t, tt.message, found.Message)
		})
	}
}

func TestDiscoverServicesForConfig(t *testing.T) {
	scheme := newTestScheme(t)

	cluster := &isovalentv1alpha1.LBK8sBackendCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster",
		},
	}

	tests := []struct {
		name           string
		services       []corev1.Service
		config         *isovalentv1alpha1.LBK8sBackendClusterServiceDiscoveryConfig
		expectedNames  []string
		expectedErrMsg string
	}{
		{
			name: "filters non-LoadBalancer services",
			services: []corev1.Service{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "lb-svc", Namespace: "default"},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "clusterip-svc", Namespace: "default"},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "nodeport-svc", Namespace: "default"},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort},
				},
			},
			config:        &isovalentv1alpha1.LBK8sBackendClusterServiceDiscoveryConfig{},
			expectedNames: []string{"lb-svc"},
		},
		{
			name: "filters by single namespace",
			services: []corev1.Service{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc2", Namespace: "ns2"},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
				},
			},
			config: &isovalentv1alpha1.LBK8sBackendClusterServiceDiscoveryConfig{
				Namespaces: []string{"ns1"},
			},
			expectedNames: []string{"svc1"},
		},
		{
			name: "filters by multiple namespaces",
			services: []corev1.Service{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc2", Namespace: "ns2"},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc3", Namespace: "ns3"},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
				},
			},
			config: &isovalentv1alpha1.LBK8sBackendClusterServiceDiscoveryConfig{
				Namespaces: []string{"ns1", "ns3"},
			},
			expectedNames: []string{"svc1", "svc3"},
		},
		{
			name: "filters by label selector",
			services: []corev1.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-with-label",
						Namespace: "default",
						Labels:    map[string]string{"expose": "true"},
					},
					Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-without-label",
						Namespace: "default",
					},
					Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
				},
			},
			config: &isovalentv1alpha1.LBK8sBackendClusterServiceDiscoveryConfig{
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"expose": "true"},
				},
			},
			expectedNames: []string{"svc-with-label"},
		},
		{
			name: "excludes services with external IP from another source",
			services: []corev1.Service{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-no-ip", Namespace: "default"},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-with-ip", Namespace: "default"},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
					Status: corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{{IP: "1.2.3.4"}},
						},
					},
				},
			},
			config:        &isovalentv1alpha1.LBK8sBackendClusterServiceDiscoveryConfig{},
			expectedNames: []string{"svc-no-ip"},
		},
		{
			name: "includes services with external IP managed by this cluster",
			services: []corev1.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "svc-managed",
						Namespace:   "default",
						Annotations: map[string]string{k8sBackendClusterAnnotation: "test-cluster"},
					},
					Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
					Status: corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{{IP: "1.2.3.4"}},
						},
					},
				},
			},
			config:        &isovalentv1alpha1.LBK8sBackendClusterServiceDiscoveryConfig{},
			expectedNames: []string{"svc-managed"},
		},
		{
			name: "excludes services with non-ILB loadBalancerClass",
			services: []corev1.Service{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-no-class", Namespace: "default"},
					Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-ilb-class", Namespace: "default"},
					Spec: corev1.ServiceSpec{
						Type:              corev1.ServiceTypeLoadBalancer,
						LoadBalancerClass: ptr.To(LoadBalancerClass),
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-aws-nlb", Namespace: "default"},
					Spec: corev1.ServiceSpec{
						Type:              corev1.ServiceTypeLoadBalancer,
						LoadBalancerClass: ptr.To("service.k8s.aws/nlb"),
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-other-class", Namespace: "default"},
					Spec: corev1.ServiceSpec{
						Type:              corev1.ServiceTypeLoadBalancer,
						LoadBalancerClass: ptr.To("example.com/my-lb"),
					},
				},
			},
			config:        &isovalentv1alpha1.LBK8sBackendClusterServiceDiscoveryConfig{},
			expectedNames: []string{"svc-no-class", "svc-ilb-class"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build fake client with services
			builder := ctrlFakeClient.NewClientBuilder().WithScheme(scheme)
			for i := range tt.services {
				builder = builder.WithObjects(&tt.services[i])
			}
			fakeClient := builder.Build()

			remoteMgr := newTestRemoteClusterManager(slog.New(slog.DiscardHandler))
			r := newLBK8sBackendClusterReconciler(
				slog.New(slog.DiscardHandler),
				fakeClient,
				scheme,
				remoteMgr,
				Config{},
			)

			services, err := r.discoverServicesForConfig(
				context.Background(),
				fakeClient,
				cluster,
				tt.config,
				slog.New(slog.DiscardHandler),
			)

			if tt.expectedErrMsg != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErrMsg)
				return
			}

			require.NoError(t, err)

			// Extract names from discovered services
			var names []string
			for _, svc := range services {
				names = append(names, svc.Name)
			}

			require.ElementsMatch(t, tt.expectedNames, names)
		})
	}
}
