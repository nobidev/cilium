//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"context"
	"fmt"
	"slices"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	lbFrontendBackendIndexName = ".spec.routes.http.backend"
)

type standaloneLbReconciler struct {
	logger     logrus.FieldLogger
	client     client.Client
	scheme     *runtime.Scheme
	nodeSource *ciliumNodeSource
	ingestor   *ingestor

	secretsNamespace string
}

func newStandaloneLbReconciler(logger logrus.FieldLogger, client client.Client, scheme *runtime.Scheme, nodeSource *ciliumNodeSource, ingestor *ingestor, secretsNamespace string) *standaloneLbReconciler {
	return &standaloneLbReconciler{
		logger:     logger,
		client:     client,
		scheme:     scheme,
		nodeSource: nodeSource,
		ingestor:   ingestor,

		secretsNamespace: secretsNamespace,
	}
}

// SetupWithManager sets up the controller with the Manager and configures
// the different watches. All the watcher trigger a reconciliation.
func (r *standaloneLbReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &isovalentv1alpha1.LBFrontend{}, lbFrontendBackendIndexName, backendIndexerFunc); err != nil {
		return fmt.Errorf("failed to setup field indexer %q: %w", lbFrontendBackendIndexName, err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		// Watch for changed LBFrontend resources (main resource)
		For(&isovalentv1alpha1.LBFrontend{}).
		// Watch for changed LBBackend resources and trigger LBFrontends that reference the changed backend
		Watches(&isovalentv1alpha1.LBBackend{}, r.enqueueReferencingLBFrontends()).
		// T1 Service resource with OwnerReference to the LBFrontend
		Owns(&corev1.Service{}).
		// T1 Endpoints resource with OwnerReference to the LBFrontend
		Owns(&corev1.Endpoints{}).
		// T2 CiliumEnvoyConfig resource with OwnerReference to the LBFrontend
		Owns(&ciliumv2.CiliumEnvoyConfig{}).
		// CiliumNode changes should trigger a reconciliation of all LBFrontends T1 Endpoints addresses (T2 nodes))
		WatchesRawSource(r.nodeSource.ToSource(r.enqueueAllLBFrontends())).
		Complete(r)
}

// Reconcile implements the main reconciliation loop that gets triggered whenever a StandaloneLB resource or a related resource changes.
func (r *standaloneLbReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	scopedLog := r.logger.WithFields(logrus.Fields{
		logfields.Controller: "LBFrontend",
		logfields.Resource:   req.NamespacedName,
	})

	scopedLog.Info("Reconciling LBFrontend")
	lb := &isovalentv1alpha1.LBFrontend{}
	if err := r.client.Get(ctx, req.NamespacedName, lb); err != nil {
		if !k8serrors.IsNotFound(err) {
			return controllerruntime.Fail(fmt.Errorf("failed to get LBFrontend: %w", err))
		}

		// LBFrontend has been deleted in the meantime
		return controllerruntime.Success()
	}

	// LBFrontend gets deleted via foreground deletion (DeletionTimestamp set)
	// -> abort and wait for the actual deletion to trigger a reconcile
	if lb.GetDeletionTimestamp() != nil {
		scopedLog.Debug("LBFrontend is marked for deletion - waiting for actual deletion")
		return controllerruntime.Success()
	}

	if err := r.createOrUpdateResources(ctx, scopedLog, lb); err != nil {
		if k8serrors.IsForbidden(err) && k8serrors.HasStatusCause(err, corev1.NamespaceTerminatingCause) {
			// The creation of one of the resources failed because the
			// namespace is terminating. The LBFrontend resource itself is also expected
			// to be marked for deletion, but we haven't yet received the
			// corresponding event, so let's not print an error message.
			scopedLog.Info("Aborting reconciliation because namespace is being terminated")
			return controllerruntime.Success()
		}

		return controllerruntime.Fail(fmt.Errorf("failed to reconcile LBFrontend: %w", err))
	}

	// Update the status of LBFrontend
	if err := r.client.Status().Update(ctx, lb); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update LBFrontend status: %w", err))
	}

	return controllerruntime.Success()
}

func (r *standaloneLbReconciler) createOrUpdateResources(ctx context.Context, scopedLogger logrus.FieldLogger, frontend *isovalentv1alpha1.LBFrontend) error {
	//
	// Load dependent resources that have relevant input for the model
	//

	// Try loading any existing T1 Service from a previous reconciliation as this might contain the IP that has been allocated by LB IPAM
	existingT1Service := &corev1.Service{}
	if err := r.client.Get(ctx, client.ObjectKeyFromObject(frontend), existingT1Service); err != nil {
		if !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to get T1 Service: %w", err)
		}

		// Continue if not found
	}

	// Try loading referenced LBBackends (in same namespace)
	backends := []*isovalentv1alpha1.LBBackend{}
	missingBackends := []string{}
	for _, lr := range frontend.Spec.Routes {
		if lr.HTTP == nil {
			continue
		}

		b := &isovalentv1alpha1.LBBackend{}
		if err := r.client.Get(ctx, types.NamespacedName{Namespace: frontend.Namespace, Name: lr.HTTP.Backend}, b); err != nil {
			if !k8serrors.IsNotFound(err) {
				return fmt.Errorf("failed to get referenced LBBackend: %w", err)
			}

			// Continue reconciliation if backends don't exist (yet).
			// But keep track of them to report in log and status later on.
			// Once the missing referenced backends gets created it will trigger a reconciliation
			missingBackends = append(missingBackends, lr.HTTP.Backend)
			continue
		}

		backends = append(backends, b)
	}

	if len(missingBackends) > 0 {
		scopedLogger.
			WithField("backends", missingBackends).
			Debug("Some referenced LBBackends don't exist")
	}

	r.updateBackendsInStatus(frontend, missingBackends)

	//
	// Translate into internal model
	//

	model, err := r.ingestor.ingest(frontend, backends, existingT1Service)
	if err != nil {
		return fmt.Errorf("failed to ingest LBFrontend into model: %w", err)
	}

	r.updateAssignedIpInStatus(model, frontend)

	//
	// T1
	//

	// Build desired resources
	desiredT1Service := r.desiredService(model)

	// TODO: include in model?
	t2NodeIPs, err := r.getT2NodeAddresses(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve T2 node ips: %w", err)
	}

	desiredT1Endpoints, err := r.desiredEndpoints(model, t2NodeIPs)
	if err != nil {
		return err
	}

	// Set controlling ownerreferences
	if err := controllerutil.SetControllerReference(frontend, desiredT1Service, r.scheme); err != nil {
		return fmt.Errorf("failed to set ownerreference on T1 Service: %w", err)
	}

	if err := controllerutil.SetControllerReference(frontend, desiredT1Endpoints, r.scheme); err != nil {
		return fmt.Errorf("failed to set ownerreference on T1 Endpoints: %w", err)
	}

	// Create or update resources
	if err := r.createOrUpdateService(ctx, desiredT1Service); err != nil {
		return err
	}

	if err := r.createOrUpdateEndpoints(ctx, desiredT1Endpoints); err != nil {
		return err
	}

	//
	// T2
	//

	if model.assignedIP == nil {
		// Stop reconciliation as assigned IP is not available yet
		// Any changes on the T1 Service (e.g. LB IPAM setting the loadbalancer ip in the status)
		// will trigger an additional reconciliation.
		return nil
	}

	// Build desired resources
	desiredT2CiliumEnvoyConfig, err := r.desiredCiliumEnvoyConfig(model)
	if err != nil {
		return err
	}

	// Set controlling ownerreferences
	if err := controllerutil.SetControllerReference(frontend, desiredT2CiliumEnvoyConfig, r.scheme); err != nil {
		return fmt.Errorf("failed to set ownerreference on T2 CiliumEnvoyConfig: %w", err)
	}

	// Create or update resources
	if err := r.createOrUpdateCiliumEnvoyConfig(ctx, desiredT2CiliumEnvoyConfig); err != nil {
		return err
	}

	return nil
}

func (r *standaloneLbReconciler) createOrUpdateService(ctx context.Context, desiredService *corev1.Service) error {
	svc := desiredService.DeepCopy()

	result, err := controllerutil.CreateOrUpdate(ctx, r.client, svc, func() error {
		svc.Spec = desiredService.Spec
		svc.OwnerReferences = desiredService.OwnerReferences
		svc.Annotations = desiredService.Annotations
		svc.Labels = desiredService.Labels

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update Service: %w", err)
	}

	r.logger.Debugf("Service %s has been %s", client.ObjectKeyFromObject(svc), result)

	return nil
}

func (r *standaloneLbReconciler) createOrUpdateEndpoints(ctx context.Context, desiredEndpoints *corev1.Endpoints) error {
	if len(desiredEndpoints.Subsets[0].Addresses) != 0 {
		ep := desiredEndpoints.DeepCopy()
		result, err := controllerutil.CreateOrUpdate(ctx, r.client, ep, func() error {
			ep.Subsets = desiredEndpoints.Subsets
			ep.OwnerReferences = desiredEndpoints.OwnerReferences
			ep.Annotations = desiredEndpoints.Annotations
			ep.Labels = desiredEndpoints.Labels

			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to create or update Endpoints: %w", err)
		}

		r.logger.Debugf("Endpoints %s has been %s", client.ObjectKeyFromObject(ep), result)
		return nil
	}

	// Delete invalid Endpoints resource due to zero addresses
	// Prevents following error: subsets[0]: Required value: must specify `addresses` or `notReadyAddresses
	if err := r.client.Delete(ctx, desiredEndpoints); err != nil {
		if !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete endpoint: %w", err)
		}

		return nil
	}

	r.logger.Debugf("Endpoints %s has been deleted due to not having a single address", client.ObjectKeyFromObject(desiredEndpoints))

	return nil
}

func (r *standaloneLbReconciler) createOrUpdateCiliumEnvoyConfig(ctx context.Context, desiredCEC *ciliumv2.CiliumEnvoyConfig) error {
	cec := desiredCEC.DeepCopy()

	result, err := controllerutil.CreateOrUpdate(ctx, r.client, cec, func() error {
		cec.Spec = desiredCEC.Spec
		cec.OwnerReferences = desiredCEC.OwnerReferences
		cec.Annotations = desiredCEC.Annotations
		cec.Labels = desiredCEC.Labels

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update CiliumEnvoyConfig: %w", err)
	}

	r.logger.Debugf("CiliumEnvoyConfig %s has been %s", client.ObjectKeyFromObject(cec), result)

	return nil
}

func backendIndexerFunc(rawObj client.Object) []string {
	backends := []string{}

	// Extract the backend references
	lbFrontend := rawObj.(*isovalentv1alpha1.LBFrontend)
	for _, lr := range lbFrontend.Spec.Routes {
		if lr.HTTP == nil {
			continue
		}

		if slices.Contains(backends, lr.HTTP.Backend) {
			continue
		}

		backends = append(backends, lr.HTTP.Backend)
	}

	return backends
}

func (r *standaloneLbReconciler) enqueueReferencingLBFrontends() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		lbList := isovalentv1alpha1.LBFrontendList{}

		listOps := &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(lbFrontendBackendIndexName, obj.GetName()),
			Namespace:     obj.GetNamespace(),
		}

		if err := r.client.List(ctx, &lbList, listOps); err != nil {
			r.logger.WithError(err).Warn("Failed to list LBFrontends")
			return nil
		}

		result := []reconcile.Request{}

		for _, i := range lbList.Items {
			result = append(result, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: i.Namespace,
					Name:      i.Name,
				},
			})
		}

		return result
	})
}

func (r *standaloneLbReconciler) enqueueAllLBFrontends() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		lbList := isovalentv1alpha1.LBFrontendList{}
		if err := r.client.List(ctx, &lbList); err != nil {
			r.logger.WithError(err).Warn("Failed to list LBFrontends")
			return nil
		}

		result := []reconcile.Request{}

		for _, i := range lbList.Items {
			result = append(result, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: i.Namespace,
					Name:      i.Name,
				},
			})
		}

		return result
	})
}

func (*standaloneLbReconciler) updateAssignedIpInStatus(model *lbFrontend, frontend *isovalentv1alpha1.LBFrontend) {
	ipAssignedCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeIPAssigned,
		Status:             metav1.ConditionFalse,
		Reason:             isovalentv1alpha1.IPAssignedConditionReasonIPPending,
		Message:            "VIP pending",
		ObservedGeneration: frontend.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	if model.assignedIP != nil {
		ipAssignedCondition.Status = metav1.ConditionTrue
		ipAssignedCondition.Reason = isovalentv1alpha1.IPAssignedConditionReasonIPAssigned
		ipAssignedCondition.Message = "VIP assigned"

		frontend.Status.VIP = *model.assignedIP
	}

	upsertCondition(frontend, isovalentv1alpha1.ConditionTypeIPAssigned, ipAssignedCondition)
}

func (*standaloneLbReconciler) updateBackendsInStatus(frontend *isovalentv1alpha1.LBFrontend, missingBackends []string) {
	backendsExistCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeBackendsExist,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.BackendsExistConditionReasonAllBackendsExist,
		Message:            "All referenced backends exist",
		ObservedGeneration: frontend.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	if len(missingBackends) > 0 {
		backendsExistCondition.Status = metav1.ConditionFalse
		backendsExistCondition.Reason = isovalentv1alpha1.BackendsExistConditionReasonMissingBackends
		backendsExistCondition.Message = fmt.Sprintf("There are referenced backends that do not exist: %v", missingBackends)
	}

	upsertCondition(frontend, isovalentv1alpha1.ConditionTypeBackendsExist, backendsExistCondition)
}

func upsertCondition(frontend *isovalentv1alpha1.LBFrontend, conditionType string, condition metav1.Condition) {
	conditionExists := false
	for i, c := range frontend.Status.Conditions {
		if c.Type == conditionType {
			if c.Status != condition.Status ||
				c.Reason != condition.Reason ||
				c.Message != condition.Message ||
				c.ObservedGeneration != condition.ObservedGeneration {
				// transition -> update condition
				frontend.Status.Conditions[i] = condition
			}
			conditionExists = true
			break
		}
	}

	if !conditionExists {
		frontend.Status.Conditions = append(frontend.Status.Conditions, condition)
	}
}
