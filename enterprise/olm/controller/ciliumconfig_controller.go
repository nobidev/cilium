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
	"fmt"
	"maps"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	amtypes "k8s.io/apimachinery/pkg/types"

	"k8s.io/client-go/discovery"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	helmchart "helm.sh/helm/v3/pkg/chart"

	ciliumiov1alpha1 "github.com/isovalent/cilium/enterprise/olm/api/cilium.io/v1alpha1"
	"github.com/isovalent/cilium/enterprise/olm/helm"
)

const (
	ManagedByLabelKey   = "isovalent.io/managed-by"
	ManagedByLabelValue = "clife"
	VersionLabelKey     = "app.kubernetes.io/version"
)

// CiliumConfigReconciler reconciles a CiliumConfig object
type CiliumConfigReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Chart             *helmchart.Chart
	Namespace         string
	StartingCondition metav1.Condition
	HelmClientGetter  *helm.RESTClientGetter
}

// TODO: Double check that the controller has all the necessary rights and ownership

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
//+kubebuilder:rbac:groups=core,resources=endpoints,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=resourcequotas,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
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
//+kubebuilder:rbac:groups=security.openshift.io,resources=securitycontextconstraints,resourceNames=hostnetwork-v2,verbs=use

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.17.3/pkg/reconcile
func (r *CiliumConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Get the CiliumConfig
	ccfg := &ciliumiov1alpha1.CiliumConfig{}
	nsn := amtypes.NamespacedName{
		Namespace: r.Namespace,
		Name:      req.Name,
	}
	err := r.Client.Get(ctx, nsn, ccfg)
	if err != nil {
		// TODO: this does not seem the best UX
		// Deleting the custom resource would completely remove Cilium
		// and possible break the connectivity of all what is running in
		// Kubernetes. We need safeguards, options:
		// - to have the default configuration applied if there is no CiliumConfig
		// and to uninstall only when a very clear attribute is set in CiliumConfig.
		// - to allow the uninstall by removing the custom resource only when an
		// environment variable has been set in the operator deployment or on the custom resource.
		// note: this is currently happening outside of the reconciliation any way
		// due to the owner references being now set and cascade deletion.
		if apierrors.IsNotFound(err) {
			// TODO Generate an event
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to retrieve CiliumConfig: %w", err)
	}
	// Reinitialize the status with the starting conditions
	conditions := initConditions(r.StartingCondition)

	// Get the helm values
	hv, err := helm.Values(ccfg)
	if err != nil {
		conditions[ciliumiov1alpha1.ValuesErrorsCondition] = metav1.Condition{
			Type:               ciliumiov1alpha1.ValuesErrorsCondition,
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             ciliumiov1alpha1.ValuesNotReadableReason,
			Message:            "values in CiliumConfig cannot not be read, please check that they have been correctly formatted",
		}
		ccfg.Status.Conditions = slices.Collect(maps.Values(conditions))
		if sErr := r.Status().Update(ctx, ccfg); sErr != nil {
			return ctrl.Result{}, fmt.Errorf("unable to update CiliumConfig status: %w, original error: %w", sErr, err)
		}
		return ctrl.Result{}, err
	} else {
		conditions[ciliumiov1alpha1.ValuesErrorsCondition] = metav1.Condition{
			Type:               ciliumiov1alpha1.ValuesErrorsCondition,
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             ciliumiov1alpha1.ValuesReadableReason,
			Message:            "success",
		}
	}
	logger.V(3).Info("helm", "values", hv)

	// Get the current state
	current, err := currentState(ctx, r.Client)
	if err != nil {
		conditions[ciliumiov1alpha1.ProcessingErrorCondition] = metav1.Condition{
			Type:               ciliumiov1alpha1.ProcessingErrorCondition,
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             ciliumiov1alpha1.StateRetrievalProcessingErrorReason,
			Message:            fmt.Sprintf("current state cannot be retrieved: %v", err),
		}
		ccfg.Status.Conditions = slices.Collect(maps.Values(conditions))
		if sErr := r.Status().Update(ctx, ccfg); sErr != nil {
			return ctrl.Result{}, fmt.Errorf("unable to update CiliumConfig status: %w, original error: %w", sErr, err)
		}
		return ctrl.Result{}, err
	}

	// Generate the desired state
	desired, err := helm.Generate(r.HelmClientGetter, r.Chart, hv, ccfg, r.Namespace, logger)
	if err != nil {
		conditions[ciliumiov1alpha1.ProcessingErrorCondition] = metav1.Condition{
			Type:               ciliumiov1alpha1.ProcessingErrorCondition,
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             ciliumiov1alpha1.HelmProcessingErrorReason,
			Message:            fmt.Sprintf("helm cannot generate manifests: %v", err),
		}
		ccfg.Status.Conditions = slices.Collect(maps.Values(conditions))
		if sErr := r.Status().Update(ctx, ccfg); sErr != nil {
			return ctrl.Result{}, fmt.Errorf("unable to update CiliumConfig status: %w, original error: %w", sErr, err)
		}
		return ctrl.Result{}, err
	}

	// Align the current with the desire state
	toApply, toRemove := Diff(desired, current)
	for _, a := range toApply {
		logger.V(3).Info("Applying resource", "kind", a.GetKind(), "namespace", a.GetNamespace(), "name", a.GetName())
		err = r.Patch(ctx, a, client.Apply, client.ForceOwnership, client.FieldOwner("clife"))
		if err != nil {
			conditions[ciliumiov1alpha1.ProcessingErrorCondition] = metav1.Condition{
				Type:               ciliumiov1alpha1.ProcessingErrorCondition,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             ciliumiov1alpha1.APIProcessingErrorReason,
				Message:            fmt.Sprintf("resource could not be applied: %v", err),
			}
			ccfg.Status.Conditions = slices.Collect(maps.Values(conditions))
			if sErr := r.Status().Update(ctx, ccfg); sErr != nil {
				return ctrl.Result{}, fmt.Errorf("unable to update CiliumConfig status: %w, original error: %w", sErr, err)
			}
			return ctrl.Result{}, err
		}
	}
	for _, d := range toRemove {
		logger.V(3).Info("Deleting resource", "kind", d.GetKind(), "namespace", d.GetNamespace(), "name", d.GetName())
		err = r.Client.Delete(ctx, d)
		if err != nil && !apierrors.IsNotFound(err) {
			conditions[ciliumiov1alpha1.ProcessingErrorCondition] = metav1.Condition{
				Type:               ciliumiov1alpha1.ProcessingErrorCondition,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             ciliumiov1alpha1.APIProcessingErrorReason,
				Message:            fmt.Sprintf("resource could not be deleted: %v", err),
			}
			ccfg.Status.Conditions = slices.Collect(maps.Values(conditions))
			if sErr := r.Status().Update(ctx, ccfg); sErr != nil {
				return ctrl.Result{}, fmt.Errorf("unable to update CiliumConfig status: %w, original error: %w", sErr, err)
			}
			return ctrl.Result{}, err
		}
	}
	ccfg.Status.Conditions = slices.Collect(maps.Values(conditions))
	if err := r.Status().Update(ctx, ccfg); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to update CiliumConfig status: %w", err)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CiliumConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	logger := mgr.GetLogger().WithName("setup")
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&ciliumiov1alpha1.CiliumConfig{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&corev1.Namespace{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Endpoints{}).
		Owns(&corev1.ResourceQuota{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.PersistentVolumeClaim{}).
		Owns(&rbacv1.ClusterRole{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&batchv1.Job{}).
		Owns(&batchv1.CronJob{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Owns(&networkingv1.Ingress{}).
		Owns(&networkingv1.IngressClass{})
	d := discovery.NewDiscoveryClientForConfigOrDie(mgr.GetConfig())
	apisMissing := []string{}
	if _, err := d.ServerResourcesForGroupVersion("gateway.networking.k8s.io/v1"); err == nil {
		builder = builder.Owns(&gatewayv1.GatewayClass{})
	} else if !apierrors.IsNotFound(err) {
		logger.Error(err, "Discovery of Gateway API resource definitions failed")
	} else {
		logger.Info("Gateway API resource definitions are not available. Please install the CRDs if you wish to use the Gateway API.")
		apisMissing = append(apisMissing, "Gateway API resource definitions are not available. Please install the CRDs if you wish to use the Gateway API.")
	}
	if _, err := d.ServerResourcesForGroupVersion("monitoring.coreos.com/v1"); err == nil {
		builder = builder.Owns(&monitoringv1.ServiceMonitor{})
	} else if !apierrors.IsNotFound(err) {
		logger.Error(err, "Discovery of Prometheus resource definitions failed")
	} else {
		logger.Info("Prometheus resource definitions are not available. Please install the CRDs if you wish to use Cilium endpoints for Prometheus.")
		apisMissing = append(apisMissing, "Prometheus resource definitions are not available. Please install the CRDs if you wish to use Cilium endpoints for Prometheus.")
	}
	if _, err := d.ServerResourcesForGroupVersion("cert-manager.io/v1"); err == nil {
		builder = builder.Owns(&certmanagerv1.Certificate{})
	} else if !apierrors.IsNotFound(err) {
		logger.Error(err, "Discovery of Cert-manager resource definitions failed")
	} else {
		logger.Info("Cert-manager resource definitions are not available. Please install the CRDs if you wish to use Cert-manager to automatically generate TLS certificates.")
		apisMissing = append(apisMissing, "Cert-manager resource definitions are not available. Please install the CRDs if you wish to use Cert-manager to automatically generate TLS certificates.")
	}
	if len(apisMissing) > 0 {
		r.StartingCondition = metav1.Condition{
			Type:               ciliumiov1alpha1.APINotAvailableCondition,
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             ciliumiov1alpha1.APIMissingReason,
			Message:            fmt.Sprintf("APIs not available: %v", apisMissing),
		}
	} else {
		r.StartingCondition = metav1.Condition{
			Type:               ciliumiov1alpha1.APINotAvailableCondition,
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             ciliumiov1alpha1.APINotMissingReason,
			Message:            "All required APIs are available",
		}
	}
	return builder.Complete(r)
}

// currentState retrieve all the resources managed by the operator and populate a map with them
// the map key is kind/namespace/name
func currentState(ctx context.Context, crClient client.Client) (map[string]*unstructured.Unstructured, error) {
	objects := map[string]*unstructured.Unstructured{}
	opts := client.MatchingLabels{
		ManagedByLabelKey: ManagedByLabelValue,
	}
	gvks := []schema.GroupVersionKind{
		{
			Group:   "",
			Kind:    "NamespaceList",
			Version: "v1",
		},
		{
			Group:   "",
			Kind:    "SecretList",
			Version: "v1",
		},
		{
			Group:   "",
			Kind:    "ConfigMapList",
			Version: "v1",
		},
		{
			Group:   "",
			Kind:    "ServiceList",
			Version: "v1",
		},
		{
			Group:   "",
			Kind:    "EndpointsList",
			Version: "v1",
		},
		{
			Group:   "",
			Kind:    "ResourceQuotaList",
			Version: "v1",
		},
		{
			Group:   "",
			Kind:    "ServiceAccountList",
			Version: "v1",
		},
		{
			Group:   "",
			Kind:    "PersistentVolumeClaimList",
			Version: "v1",
		},
		{
			Group:   "apps",
			Kind:    "DeploymentList",
			Version: "v1",
		},
		{
			Group:   "apps",
			Kind:    "StatefulSetList",
			Version: "v1",
		},
		{
			Group:   "apps",
			Kind:    "DaemonSetList",
			Version: "v1",
		},
		{
			Group:   "rbac.authorization.k8s.io",
			Kind:    "ClusterRoleList",
			Version: "v1",
		},
		{
			Group:   "rbac.authorization.k8s.io",
			Kind:    "ClusterRoleBindingList",
			Version: "v1",
		},
		{
			Group:   "rbac.authorization.k8s.io",
			Kind:    "RoleList",
			Version: "v1",
		},
		{
			Group:   "rbac.authorization.k8s.io",
			Kind:    "RoleBindingList",
			Version: "v1",
		},
		{
			Group:   "batch",
			Kind:    "JobList",
			Version: "v1",
		},
		{
			Group:   "batch",
			Kind:    "CronJobList",
			Version: "v1",
		},
		{
			Group:   "policy",
			Kind:    "PodDisruptionBudgetList",
			Version: "v1",
		},
		{
			Group:   "networking.k8s.io",
			Kind:    "IngressList",
			Version: "v1",
		},
		{
			Group:   "networking.k8s.io",
			Kind:    "IngressClassList",
			Version: "v1",
		},
	}
	// TODO: this does not reconcile optional APIs: Gateway API, Prometheus, cert-manager
	// Optional APIs should be recorded in the struct and queried here depending on their availability.
	for _, gvk := range gvks {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   gvk.Group,
			Kind:    gvk.Kind,
			Version: gvk.Version,
		})
		if err := crClient.List(ctx, list, opts); err != nil {
			return nil, err
		}
		for _, item := range list.Items {
			objects[fmt.Sprintf("%s/%s/%s", item.GetKind(), item.GetNamespace(), item.GetName())] = &item
		}
	}
	return objects, nil
}

// initConditions generates a map with the conditions initialized at the beginning of the reconciliation
func initConditions(startingCondition metav1.Condition) map[string]metav1.Condition {
	conditions := map[string]metav1.Condition{}
	conditions[startingCondition.Type] = startingCondition
	conditions[ciliumiov1alpha1.ValuesErrorsCondition] = metav1.Condition{
		Type:               ciliumiov1alpha1.ValuesErrorsCondition,
		Status:             metav1.ConditionUnknown,
		LastTransitionTime: metav1.Now(),
		Reason:             ciliumiov1alpha1.ValuesNotProcessedReason,
		Message:            "values not yet processed",
	}
	conditions[ciliumiov1alpha1.ProcessingErrorCondition] = metav1.Condition{
		Type:               ciliumiov1alpha1.ProcessingErrorCondition,
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             ciliumiov1alpha1.NoProcessingErrorReason,
		Message:            "success",
	}

	return conditions
}
