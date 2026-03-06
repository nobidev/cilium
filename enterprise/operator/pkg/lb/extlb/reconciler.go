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
	"fmt"
	"log/slog"
	"slices"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	k8sBackendClusterFinalizer = "lbk8sbackendcluster.isovalent.com/finalizer"
)

type lbK8sBackendClusterReconciler struct {
	logger               *slog.Logger
	client               client.Client
	scheme               *runtime.Scheme
	remoteClusterManager *remoteClusterManager
	config               Config

	// remoteClusterSource is an event source for remote cluster changes
	remoteClusterSource *remoteClusterEventSource
}

// remoteClusterEventSource is a source.Source implementation that queues
// reconcile requests when services or nodes change in remote clusters.
type remoteClusterEventSource struct {
	logger *slog.Logger

	ctx   context.Context
	queue workqueue.TypedRateLimitingInterface[ctrl.Request]
}

func (s *remoteClusterEventSource) Start(
	ctx context.Context,
	queue workqueue.TypedRateLimitingInterface[ctrl.Request],
) error {
	s.ctx = ctx
	s.queue = queue
	return nil
}

func (s *remoteClusterEventSource) onClusterChange(clusterName string) {
	if s.ctx == nil || s.queue == nil {
		// Controller not started yet
		return
	}

	s.logger.Debug("queueing update from remote cluster change",
		logfields.ClusterName, clusterName)
	s.queue.Add(ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name: clusterName,
		},
	})
}

func newLBK8sBackendClusterReconciler(
	logger *slog.Logger,
	client client.Client,
	scheme *runtime.Scheme,
	remoteClusterManager *remoteClusterManager,
	config Config,
) *lbK8sBackendClusterReconciler {
	controllerLogger := logger.With(logfields.Controller, "lbk8sbackendcluster")
	source := &remoteClusterEventSource{
		logger: controllerLogger,
	}

	r := &lbK8sBackendClusterReconciler{
		logger:               controllerLogger,
		client:               client,
		scheme:               scheme,
		remoteClusterManager: remoteClusterManager,
		config:               config,
		remoteClusterSource:  source,
	}

	remoteClusterManager.SetServiceChangeCallback(source.onClusterChange)
	remoteClusterManager.SetDisconnectCallback(source.onClusterChange)

	return r
}

func (r *lbK8sBackendClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&isovalentv1alpha1.LBK8sBackendCluster{}).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findLBK8sBackendClustersForSecret),
		).
		WatchesRawSource(r.remoteClusterSource).
		Complete(r)
}

// findLBK8sBackendClustersForSecret finds all LBK8sBackendCluster resources that
// reference a given Secret.
func (r *lbK8sBackendClusterReconciler) findLBK8sBackendClustersForSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}

	var clusterList isovalentv1alpha1.LBK8sBackendClusterList
	if err := r.client.List(ctx, &clusterList); err != nil {
		r.logger.Error("failed to list LBK8sBackendClusters", logfields.Error, err)
		return nil
	}

	var requests []reconcile.Request
	for _, cluster := range clusterList.Items {
		if cluster.Spec.Authentication.SecretRef.Name == secret.Name &&
			cluster.Spec.Authentication.SecretRef.Namespace == secret.Namespace {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: cluster.Name,
				},
			})
		}
	}
	return requests
}

func (r *lbK8sBackendClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.logger.With(logfields.Resource, req.NamespacedName)

	var cluster isovalentv1alpha1.LBK8sBackendCluster
	if err := r.client.Get(ctx, req.NamespacedName, &cluster); err != nil {
		if k8serrors.IsNotFound(err) {
			// No such cluster, stop the watcher
			r.remoteClusterManager.Stop(req.Name)
			return controllerruntime.Success()
		}
		logger.Error("failed to get LBK8sBackendCluster", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	if !cluster.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, &cluster, logger)
	}

	if !controllerutil.ContainsFinalizer(&cluster, k8sBackendClusterFinalizer) {
		controllerutil.AddFinalizer(&cluster, k8sBackendClusterFinalizer)
		if err := r.client.Update(ctx, &cluster); err != nil {
			logger.Error("failed to add finalizer", logfields.Error, err)
			return controllerruntime.Fail(err)
		}
		return controllerruntime.Success()
	}

	secret, err := r.getAuthSecret(ctx, &cluster)
	if err != nil {
		return r.updateStatusError(ctx, &cluster, logger, "AuthenticationError",
			fmt.Sprintf("failed to get authentication secret: %v", err))
	}

	if err := r.remoteClusterManager.EnsureCluster(ctx, &cluster, secret); err != nil {
		return r.updateStatusError(ctx, &cluster, logger, "ConnectionError",
			fmt.Sprintf("failed to connect to remote cluster: %v", err))
	}

	serviceCount, err := r.countRemoteServices(ctx, &cluster, logger)
	if err != nil {
		return r.updateStatusError(ctx, &cluster, logger, "SyncError",
			fmt.Sprintf("failed to list remote services: %v", err))
	}

	logger.Info("observed LoadBalancer services in remote cluster",
		logfields.ClusterName, cluster.Name,
		logfields.ServiceCount, serviceCount,
	)

	return r.updateStatusSuccess(ctx, &cluster, logger, serviceCount)
}

func (r *lbK8sBackendClusterReconciler) handleDeletion(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	logger *slog.Logger,
) (ctrl.Result, error) {
	logger.Info("handling deletion of LBK8sBackendCluster")

	r.remoteClusterManager.Stop(cluster.Name)

	controllerutil.RemoveFinalizer(cluster, k8sBackendClusterFinalizer)
	if err := r.client.Update(ctx, cluster); err != nil {
		logger.Error("failed to remove finalizer", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	return controllerruntime.Success()
}

func (r *lbK8sBackendClusterReconciler) getAuthSecret(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
) (*corev1.Secret, error) {
	var secret corev1.Secret
	if err := r.client.Get(ctx, types.NamespacedName{
		Name:      cluster.Spec.Authentication.SecretRef.Name,
		Namespace: cluster.Spec.Authentication.SecretRef.Namespace,
	}, &secret); err != nil {
		return nil, err
	}
	return &secret, nil
}

// countRemoteServices counts LoadBalancer services visible from the remote
// cluster via the informer cache.
func (r *lbK8sBackendClusterReconciler) countRemoteServices(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	logger *slog.Logger,
) (int, error) {
	remoteClient, err := r.remoteClusterManager.GetClient(cluster.Name)
	if err != nil {
		return 0, fmt.Errorf("failed to get remote cluster client: %w", err)
	}

	var serviceList corev1.ServiceList
	if err := remoteClient.List(ctx, &serviceList); err != nil {
		return 0, fmt.Errorf("failed to list services: %w", err)
	}

	count := 0
	for _, svc := range serviceList.Items {
		if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			count++
		}
	}

	return count, nil
}

func (r *lbK8sBackendClusterReconciler) updateStatusError(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	logger *slog.Logger,
	reason string,
	message string,
) (ctrl.Result, error) {
	logger.Error("reconciliation error",
		logfields.Reason, reason,
		logfields.Message, message,
	)

	if cluster.Status == nil {
		cluster.Status = &isovalentv1alpha1.LBK8sBackendClusterStatus{}
	}

	status := isovalentv1alpha1.ExtLBResourceStatusConditionNotMet
	cluster.Status.Status = &status
	cluster.Status.Conditions = removeCondition(cluster.Status.Conditions, isovalentv1alpha1.DeprecatedConditionTypeClusterConnected)
	cluster.Status.Conditions = updateCondition(cluster.Status.Conditions,
		isovalentv1alpha1.ConditionTypeClusterConnected,
		metav1.ConditionFalse,
		reason,
		message,
	)

	if err := r.client.Status().Update(ctx, cluster); err != nil {
		logger.Error("failed to update status", logfields.Error, err)
	}

	return ctrl.Result{}, nil
}

func (r *lbK8sBackendClusterReconciler) updateStatusSuccess(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	logger *slog.Logger,
	serviceCount int,
) (ctrl.Result, error) {
	if cluster.Status == nil {
		cluster.Status = &isovalentv1alpha1.LBK8sBackendClusterStatus{}
	}

	now := metav1.Now()
	status := isovalentv1alpha1.ExtLBResourceStatusOK
	cluster.Status.Status = &status
	cluster.Status.LastSyncTime = &now
	cluster.Status.ServicesDiscovered = int32(serviceCount)
	cluster.Status.Conditions = removeCondition(cluster.Status.Conditions, isovalentv1alpha1.DeprecatedConditionTypeClusterConnected)
	cluster.Status.Conditions = updateCondition(cluster.Status.Conditions,
		isovalentv1alpha1.ConditionTypeClusterConnected,
		metav1.ConditionTrue,
		"Connected",
		fmt.Sprintf("Successfully connected and discovered %d LoadBalancer services", serviceCount),
	)

	if err := r.client.Status().Update(ctx, cluster); err != nil {
		logger.Error("failed to update status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	logger.Info("reconciliation successful",
		logfields.ServiceCount, serviceCount,
	)

	return ctrl.Result{}, nil
}

func removeCondition(conditions []metav1.Condition, conditionType string) []metav1.Condition {
	for i, c := range conditions {
		if c.Type == conditionType {
			return slices.Delete(conditions, i, i+1)
		}
	}
	return conditions
}

func updateCondition(conditions []metav1.Condition, conditionType string, status metav1.ConditionStatus, reason, message string) []metav1.Condition {
	now := metav1.Now()
	for i, c := range conditions {
		if c.Type == conditionType {
			if c.Status != status || c.Reason != reason || c.Message != message {
				conditions[i] = metav1.Condition{
					Type:               conditionType,
					Status:             status,
					LastTransitionTime: now,
					Reason:             reason,
					Message:            message,
				}
			}
			return conditions
		}
	}
	return append(conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	})
}
