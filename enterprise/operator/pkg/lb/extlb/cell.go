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

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlRuntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var DefaultConfig = Config{
	ExtLBEnabled: false,
}

// Cell provides controllers for managing connections to backend Kubernetes
// clusters, watching the resources in those clusters, and configuring Isovalent
// Load Balancer resources accordingly. This enables this Cilium cluster to act
// as a load balancer for those backend clusters. For example, to provide
// connectivity for external Services of type LoadBalancer, acting as the Cloud
// Load Balancer for those Services and providing an ExternalIP. May be extended
// in the future to support other types of resources and configuration options.
var Cell = cell.Module(
	"loadbalancer-extlb-controlplane", "The External Load Balancer control plane",

	cell.Config(DefaultConfig),
	cell.Invoke(registerExternalLBReconcilers),
)

type Config struct {
	ExtLBEnabled bool `mapstructure:"loadbalancer-extlb-enabled"`
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("loadbalancer-extlb-enabled", c.ExtLBEnabled, "Enable the External Load Balancer control plane")
}

type reconcilerParams struct {
	cell.In

	Logger  *slog.Logger
	Manager ctrlRuntime.Manager
	Config  Config
}

func registerExternalLBReconcilers(params reconcilerParams) error {
	if !params.Config.ExtLBEnabled {
		return nil
	}

	reconciler := &lbK8sBackendClusterReconciler{
		client: params.Manager.GetClient(),
		logger: params.Logger.With(logfields.Controller, "lbk8sbackendcluster"),
	}

	return reconciler.SetupWithManager(params.Manager)
}

type lbK8sBackendClusterReconciler struct {
	client client.Client
	logger *slog.Logger
}

func (r *lbK8sBackendClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.logger.Info("Setting up LBK8sBackendCluster controller")

	return ctrl.NewControllerManagedBy(mgr).
		For(&isovalentv1alpha1.LBK8sBackendCluster{}).
		Watches(&corev1.Secret{}, r.enqueueLBK8sBackendClusterForSecret()).
		Complete(r)
}

// enqueueLBK8sBackendClusterForSecret returns an event handler that enqueues
// LBK8sBackendClusters when their referenced Secrets change.
//
// TODO: (ajs) Later, we will open Watches on resources within the
// LBK8sBackendCluster. When we do, we will need a cache of connections for each
// backend cluster. When this secret changes we will need to update the
// connection in the cache.
func (r *lbK8sBackendClusterReconciler) enqueueLBK8sBackendClusterForSecret() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, secret client.Object) []reconcile.Request {
		// List all LBK8sBackendClusters and check if any reference this secret
		list := &isovalentv1alpha1.LBK8sBackendClusterList{}
		// TODO (ajs): Confirm that this is cached using the underlying
		// Informer. If not, it probably doesn't scale.
		if err := r.client.List(ctx, list); err != nil {
			r.logger.ErrorContext(ctx, "Failed to list LBK8sBackendClusters", logfields.Error, err)
			return nil
		}

		var reqs []reconcile.Request
		for _, cluster := range list.Items {
			if cluster.Spec.Authentication.SecretRef.Name == secret.GetName() &&
				cluster.Spec.Authentication.SecretRef.Namespace == secret.GetNamespace() {
				reqs = append(reqs, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name: cluster.Name,
					},
				})
			}
		}

		return reqs
	})
}

func (r *lbK8sBackendClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(logfields.Resource, req.Name)
	scopedLog.DebugContext(ctx, "Reconciling LBK8sBackendCluster")

	lbK8sBackendCluster := &isovalentv1alpha1.LBK8sBackendCluster{}
	if err := r.client.Get(ctx, req.NamespacedName, lbK8sBackendCluster); err != nil {
		if k8serrors.IsNotFound(err) {
			scopedLog.DebugContext(ctx, "LBK8sBackendCluster not found, ignoring")
			return controllerruntime.Success()
		}
		return controllerruntime.Fail(err)
	}

	connected, statusMsg, err := r.tryConnect(ctx, lbK8sBackendCluster)
	if err != nil {
		scopedLog.WarnContext(ctx, "Failed to connect to remote cluster", logfields.Error, err)
	}

	if err := r.updateStatus(ctx, lbK8sBackendCluster, connected, statusMsg); err != nil {
		scopedLog.ErrorContext(ctx, "Failed to update LBK8sBackendCluster status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// TODO: (ajs) For now, requeue periodically to check connectivity. In the
	// future, we will have a cache of open connections to each backend cluster,
	// and trigger a re-reconcile when those connections close. At the moment,
	// this is the only way to detected dropped connections.
	return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

func (r *lbK8sBackendClusterReconciler) tryConnect(ctx context.Context, lbK8sBackendCluster *isovalentv1alpha1.LBK8sBackendCluster) (bool, string, error) {
	secretRef := lbK8sBackendCluster.Spec.Authentication.SecretRef
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{
		Name:      secretRef.Name,
		Namespace: secretRef.Namespace,
	}

	if err := r.client.Get(ctx, secretKey, secret); err != nil {
		if k8serrors.IsNotFound(err) {
			return false, fmt.Sprintf("Secret %s/%s not found", secretRef.Namespace, secretRef.Name), err
		}
		return false, fmt.Sprintf("Failed to get Secret %s/%s", secretRef.Namespace, secretRef.Name), err
	}

	kubeconfigData, ok := secret.Data["kubeconfig"]
	if !ok {
		return false, "Secret does not contain 'kubeconfig' key", fmt.Errorf("secret does not contain 'kubeconfig' key")
	}

	clientConfig, err := clientcmd.NewClientConfigFromBytes(kubeconfigData)
	if err != nil {
		return false, "Failed to parse kubeconfig", err
	}

	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return false, "Failed to get REST config", err
	}
	restConfig.Timeout = clusterClientTimeout

	testClient, err := client.New(restConfig, client.Options{})
	if err != nil {
		return false, "Failed to create client", err
	}

	// Test connectivity by listing pods in the remote cluster.
	pods := &corev1.PodList{}
	if err := testClient.List(ctx, pods); err != nil {
		r.logger.WarnContext(ctx, "Failed to list pods in remote cluster", logfields.Error, err)
		return false, "Failed to connect", err
	}

	r.logger.InfoContext(ctx, "Connected to remote cluster",
		logfields.ClusterName, lbK8sBackendCluster.Name,
		logfields.Count, len(pods.Items))

	return true, "Connected to remote cluster", nil
}

func (r *lbK8sBackendClusterReconciler) updateStatus(ctx context.Context, lbK8sBackendCluster *isovalentv1alpha1.LBK8sBackendCluster, connected bool, statusMsg string) error {
	now := metav1.Now()

	if lbK8sBackendCluster.Status == nil {
		lbK8sBackendCluster.Status = &isovalentv1alpha1.LBK8sBackendClusterStatus{}
	}
	lbK8sBackendCluster.Status.LastSyncTime = &now

	connectedConditionStatus := metav1.ConditionFalse
	connectedReason := isovalentv1alpha1.ClusterConnectedReasonConnectionFailed
	if connected {
		connectedConditionStatus = metav1.ConditionTrue
		connectedReason = isovalentv1alpha1.ClusterConnectedReasonConnected
	}

	lbK8sBackendCluster.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeClusterConnected, metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeClusterConnected,
		Status:             connectedConditionStatus,
		Reason:             connectedReason,
		Message:            statusMsg,
		ObservedGeneration: lbK8sBackendCluster.Generation,
		LastTransitionTime: now,
	})

	lbK8sBackendCluster.UpdateResourceStatus()

	return r.client.Status().Update(ctx, lbK8sBackendCluster)
}

const (
	clusterClientTimeout = 10 * time.Second
)
