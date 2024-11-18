/*
Copyright (C) Isovalent, Inc. - All Rights Reserved.

NOTICE: All information contained herein is, and remains the property of
Isovalent Inc and its suppliers, if any. The intellectual and technical
concepts contained herein are proprietary to Isovalent Inc and its suppliers
and may be covered by U.S. and Foreign Patents, patents in process, and are
protected by trade secret or copyright law.  Dissemination of this information
or reproduction of this material is strictly forbidden unless prior written
permission is obtained from Isovalent Inc.
*/

package controller

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"

	"k8s.io/client-go/discovery"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	helmchart "helm.sh/helm/v3/pkg/chart"

	ciliumiov1alpha1 "github.com/isovalent/cilium/olm/api/v1alpha1"
	"github.com/isovalent/cilium/olm/helm"
)

// CiliumConfigReconciler reconciles a CiliumConfig object
type CiliumConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Chart  *helmchart.Chart
}

// TODO: The controller is missing some rights

//+kubebuilder:rbac:groups=cilium.io,resources=ciliumconfigs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cilium.io,resources=ciliumconfigs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cilium.io,resources=ciliumconfigs/finalizers,verbs=update
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=resourcequotas,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete;bind;escalate
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete;bind;escalate
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,resources=ingressclasses,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.17.3/pkg/reconcile
func (r *CiliumConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Get the CiliumConfig
	ccfg := &ciliumiov1alpha1.CiliumConfig{}
	nsn := req.NamespacedName
	err := r.Client.Get(ctx, nsn, ccfg)
	if err != nil {
		// TODO: this does not seem the best UX
		// Deleting the custom resource would completely remove Cilium
		// and possible break the connectivity of all what is running in
		// Kubernetes. We need safeguards, options:
		// - to have the default configuration applied if there is no CiliumConfig
		// and to uninstall only when a very clear attribute is set in CiliumConfig.
		// - to allow the uninstall by removing the custom resource only when an
		// environment variable has been set in the operator deployment.
		if apierrors.IsNotFound(err) {
			// TODO err = UninstallCilium(restConfig, nsn, logger)
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to retrieve CiliumConfig")
		return ctrl.Result{}, err
	}

	// TODO:
	// DefaultPostRendererFunc returns a post-renderer that applies owner references to compatible objects
	// in a helm release manifest. This is the default post-renderer used by ActionClients created with
	// NewActionClientGetter.
	// Owner references are currently not set. This needs to be amended

	hv, err := helm.Values(ccfg)
	logger.V(3).Info("helm", "values", hv)
	if err != nil {
		return ctrl.Result{}, err
	}
	helm.Install(r.Chart, hv, ccfg, logger)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CiliumConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	logger := mgr.GetLogger().WithName("setup")
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&ciliumiov1alpha1.CiliumConfig{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&corev1.Namespace{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ResourceQuota{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&rbacv1.ClusterRole{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&batchv1.Job{}).
		Owns(&batchv1.CronJob{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Owns(&networkingv1.IngressClass{})
	d := discovery.NewDiscoveryClientForConfigOrDie(mgr.GetConfig())
	// TODO: Absence of API should be recorded in the CiliumConfigReconciler struct
	// and used to set a condition in the CiliumConfig custom resource
	// prompting the user to install them and to restart CLife if they want to
	// use the related features, i.e. Gateway API, Prometheus.
	if _, err := d.ServerResourcesForGroupVersion("gateway.networking.k8s.io/v1"); err == nil {
		builder = builder.Owns(&gatewayv1.GatewayClass{})
	} else if !apierrors.IsNotFound(err) {
		logger.Error(err, "Discovery of Gateway API resource definitions failed")
	} else {
		logger.Info("Gateway API resource definitions are not available. Please install the CRDs if you wish to use the Gateway API.")
	}
	if _, err := d.ServerResourcesForGroupVersion("monitoring.coreos.com/v1"); err == nil {
		builder = builder.Owns(&monitoringv1.ServiceMonitor{})
	} else if !apierrors.IsNotFound(err) {
		logger.Error(err, "Discovery of Prometheus resource definitions failed")
	} else {
		logger.Info("Prometheus resource definitions are not available. Please install the CRDs if you wish to use Cilium endpoints for Prometheus.")
	}
	if _, err := d.ServerResourcesForGroupVersion("gateway.networking.k8s.io/v1"); err == nil {
		builder = builder.Owns(&certmanagerv1.Certificate{})
	} else if !apierrors.IsNotFound(err) {
		logger.Error(err, "Discovery of Cert-manager resource definitions failed")
	} else {
		logger.Info("Cert-manager resource definitions are not available. Please install the CRDs if you wish to use Cert-manager to automatically generate TLS certificates.")
	}
	return builder.Complete(r)
}
