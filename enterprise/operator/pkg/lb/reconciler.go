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

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
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

type standaloneLbReconciler struct {
	logger     logrus.FieldLogger
	client     client.Client
	scheme     *runtime.Scheme
	nodeSource *ciliumNodeSource
	ingestor   *ingestor
}

func newStandaloneLbReconciler(logger logrus.FieldLogger, client client.Client, scheme *runtime.Scheme, nodeSource *ciliumNodeSource, ingestor *ingestor) *standaloneLbReconciler {
	return &standaloneLbReconciler{
		logger:     logger,
		client:     client,
		scheme:     scheme,
		nodeSource: nodeSource,
		ingestor:   ingestor,
	}
}

// SetupWithManager sets up the controller with the Manager and configures
// the different watches. All the watcher trigger a reconciliation.
func (r *standaloneLbReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Watch for changed IsovalentLb resources (main resource)
		For(&isovalentv1alpha1.IsovalentLB{}).
		// T1 Service resource with OwnerReference to the IsovalentLb
		Owns(&corev1.Service{}).
		// T1 Endpoints resource with OwnerReference to the IsovalentLb
		Owns(&corev1.Endpoints{}).
		// T2 CiliumEnvoyConfig resource with OwnerReference to the IsovalentLb
		Owns(&ciliumv2.CiliumEnvoyConfig{}).
		// CiliumNode changes should trigger a reconciliation of all IsovalentLBs T1 Endpoints addresses (T2 nodes))
		WatchesRawSource(r.nodeSource.ToSource(r.enqueueAllIsovalentLBs())).
		Complete(r)
}

// Reconcile implements the main reconciliation loop that gets triggered whenever a StandaloneLB resource or a related resource changes.
func (r *standaloneLbReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	scopedLog := r.logger.WithFields(logrus.Fields{
		logfields.Controller: "standalone-lb",
		logfields.Resource:   req.NamespacedName,
	})

	scopedLog.Info("Reconciling IsovalentLB")
	lb := &isovalentv1alpha1.IsovalentLB{}
	if err := r.client.Get(ctx, req.NamespacedName, lb); err != nil {
		if !k8serrors.IsNotFound(err) {
			return controllerruntime.Fail(fmt.Errorf("failed to get IsovalentLB: %w", err))
		}

		return controllerruntime.Success()
	}

	// IsovalentLB gets deleted via foreground deletion (DeletionTimestamp set)
	// -> abort and wait for the actual deletion to trigger a reconcile
	if lb.GetDeletionTimestamp() != nil {
		scopedLog.Debug("IsovalentLB is marked for deletion - waiting for actual deletion")
		return controllerruntime.Success()
	}

	if err := r.createOrUpdateResources(ctx, lb); err != nil {
		if k8serrors.IsForbidden(err) && k8serrors.HasStatusCause(err, corev1.NamespaceTerminatingCause) {
			// The creation of one of the resources failed because the
			// namespace is terminating. The IsovalentLb resource itself is also expected
			// to be marked for deletion, but we haven't yet received the
			// corresponding event, so let's not print an error message.
			scopedLog.Info("Aborting reconciliation because namespace is being terminated")
			return controllerruntime.Success()
		}

		return controllerruntime.Fail(fmt.Errorf("failed to reconcile IsovalentLB: %w", err))
	}

	return controllerruntime.Success()
}

func (r *standaloneLbReconciler) createOrUpdateResources(ctx context.Context, lb *isovalentv1alpha1.IsovalentLB) error {
	// Translate into internal model
	lbFrontend, err := r.ingestor.ingest(lb)
	if err != nil {
		return fmt.Errorf("failed to ingest IsovalentLB into model: %w", err)
	}

	// Build desired resources
	desiredT1Service := r.desiredService(lbFrontend)

	desiredT1Endpoints, err := r.desiredEndpoints(ctx, lbFrontend)
	if err != nil {
		return err
	}

	desiredT2CiliumEnvoyConfig, err := r.desiredCiliumEnvoyConfig(lbFrontend)
	if err != nil {
		return err
	}

	// Set controlling ownerreferences
	if err := controllerutil.SetControllerReference(lb, desiredT1Service, r.scheme); err != nil {
		return fmt.Errorf("failed to set ownerreference on T1 Service: %w", err)
	}

	if err := controllerutil.SetControllerReference(lb, desiredT1Endpoints, r.scheme); err != nil {
		return fmt.Errorf("failed to set ownerreference on T1 Endpoints: %w", err)
	}

	if err := controllerutil.SetControllerReference(lb, desiredT2CiliumEnvoyConfig, r.scheme); err != nil {
		return fmt.Errorf("failed to set ownerreference on T2 CiliumEnvoyConfig: %w", err)
	}

	// Create or update resources
	if err := r.createOrUpdateService(ctx, desiredT1Service); err != nil {
		return err
	}

	if err := r.createOrUpdateEndpoints(ctx, desiredT1Endpoints); err != nil {
		return err
	}

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
		svc.Annotations = mergeMap(svc.Annotations, desiredService.Annotations)
		svc.Labels = mergeMap(svc.Labels, desiredService.Labels)

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
			ep.Annotations = mergeMap(ep.Annotations, desiredEndpoints.Annotations)
			ep.Labels = mergeMap(ep.Labels, desiredEndpoints.Labels)

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
		cec.Annotations = mergeMap(cec.Annotations, desiredCEC.Annotations)
		cec.Labels = mergeMap(cec.Labels, desiredCEC.Labels)

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update CiliumEnvoyConfig: %w", err)
	}

	r.logger.Debugf("CiliumEnvoyConfig %s has been %s", client.ObjectKeyFromObject(cec), result)

	return nil
}

// mergeMap merges the content from src into dst. Existing entries are overwritten.
func mergeMap(dst, src map[string]string) map[string]string {
	if src == nil {
		return dst
	}

	if dst == nil {
		dst = map[string]string{}
	}

	for key, value := range src {
		dst[key] = value
	}

	return dst
}

func (r *standaloneLbReconciler) enqueueAllIsovalentLBs() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		lbList := isovalentv1alpha1.IsovalentLBList{}
		if err := r.client.List(ctx, &lbList); err != nil {
			r.logger.WithError(err).Warn("Failed to list IsovalentLBs")
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
