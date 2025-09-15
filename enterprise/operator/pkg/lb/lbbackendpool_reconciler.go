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
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	lbBackendPoolK8sServiceIndexName = ".spec.backends.k8sServiceRef"
)

type lbBackendPoolReconciler struct {
	logger *slog.Logger
	client client.Client
}

func newLbBackendPoolReconciler(logger *slog.Logger, client client.Client) *lbBackendPoolReconciler {
	return &lbBackendPoolReconciler{
		logger: logger,
		client: client,
	}
}

// SetupWithManager sets up the controller with the Manager and configures
// the different watches. All the watcher trigger a reconciliation.
func (r *lbBackendPoolReconciler) SetupWithManager(mgr ctrl.Manager) error {
	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		lbBackendPoolK8sServiceIndexName: func(rawObj client.Object) []string {
			return rawObj.(*isovalentv1alpha1.LBBackendPool).AllReferencedK8sServiceNames()
		},
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &isovalentv1alpha1.LBBackendPool{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	return ctrl.NewControllerManagedBy(mgr).
		// Watch for changed LBBackendPool resources (main resource)
		For(&isovalentv1alpha1.LBBackendPool{}).
		// Watch for changed K8s Service resources and trigger LBBackendPools that reference the changed Service.
		Watches(&corev1.Service{}, r.enqueueReferencingLBBackendPoolsByIndex(lbBackendPoolK8sServiceIndexName)).
		Complete(r)
}

// Reconcile implements the main reconciliation loop that gets triggered whenever a LBBackendPool resource or a related resource changes.
func (r *lbBackendPoolReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, "LBBackendPool",
		logfields.Resource, req.NamespacedName,
	)

	scopedLog.Info("Reconciling LBBackendPool")
	lb := &isovalentv1alpha1.LBBackendPool{}
	if err := r.client.Get(ctx, req.NamespacedName, lb); err != nil {
		if !k8serrors.IsNotFound(err) {
			return controllerruntime.Fail(fmt.Errorf("failed to get LBBackendPool: %w", err))
		}

		scopedLog.Debug("LBBackendPool not found - assuming it has been deleted")

		// LBBackendPool has been deleted in the meantime
		return controllerruntime.Success()
	}

	// LBBackendPool gets deleted via foreground deletion (DeletionTimestamp set)
	// -> abort and wait for the actual deletion to trigger a reconcile
	if lb.GetDeletionTimestamp() != nil {
		scopedLog.Debug("LBBackendPool is marked for deletion - waiting for actual deletion")
		return controllerruntime.Success()
	}

	if err := r.reconcileResources(ctx, lb); err != nil {
		if k8serrors.IsForbidden(err) && k8serrors.HasStatusCause(err, corev1.NamespaceTerminatingCause) {
			// The creation of one of the resources failed because the
			// namespace is terminating. The LBBackendPool resource itself is also expected
			// to be marked for deletion, but we haven't yet received the
			// corresponding event, so let's not print an error message.
			scopedLog.Info("Aborting reconciliation because namespace is being terminated")
			return controllerruntime.Success()
		}

		return controllerruntime.Fail(fmt.Errorf("failed to reconcile LBService: %w", err))
	}

	lb.UpdateResourceStatus()

	// Update the status of LBBackendPool
	if err := r.client.Status().Update(ctx, lb); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update LBBackendPool status: %w", err))
	}

	return controllerruntime.Success()
}

func (r *lbBackendPoolReconciler) reconcileResources(ctx context.Context, lbbp *isovalentv1alpha1.LBBackendPool) error {
	// Try loading relevant K8s Services that are referenced by this LBBackendPool
	// -> can be an empty list
	k8sServices, missingServiceNames, err := r.loadK8sServices(ctx, lbbp)
	if err != nil {
		return fmt.Errorf("failed to load K8s Services: %w", err)
	}

	r.updateAcceptedStatusCondition(lbbp, k8sServices, missingServiceNames)

	return nil
}

func (r *lbBackendPoolReconciler) loadK8sServices(ctx context.Context, lbbp *isovalentv1alpha1.LBBackendPool) ([]*corev1.Service, []string, error) {
	services := []*corev1.Service{}
	missingServices := []string{}

	allReferencedK8sServicesNames := lbbp.AllReferencedK8sServiceNames()

	for _, sName := range allReferencedK8sServicesNames {
		svc := &corev1.Service{}
		if err := r.client.Get(ctx, types.NamespacedName{Namespace: lbbp.Namespace, Name: sName}, svc); err != nil {
			if !k8serrors.IsNotFound(err) {
				return nil, nil, fmt.Errorf("failed to get referenced K8s Service: %w", err)
			}

			// Continue reconciliation if Service don't exist (yet).
			// But keep track of them to report in log and status later on.
			// Once the missing referenced Service gets created it will trigger a reconciliation
			missingServices = append(missingServices, sName)
			continue
		}

		services = append(services, svc)
	}

	return services, missingServices, nil
}

func (r *lbBackendPoolReconciler) enqueueReferencingLBBackendPoolsByIndex(indexName string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		lbbpList := isovalentv1alpha1.LBBackendPoolList{}

		listOps := &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexName, obj.GetName()),
			Namespace:     obj.GetNamespace(),
		}

		if err := r.client.List(ctx, &lbbpList, listOps); err != nil {
			r.logger.Warn("Failed to list LBBackendPools", logfields.Error, err)
			return nil
		}

		result := []reconcile.Request{}

		for _, i := range lbbpList.Items {
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

func (r *lbBackendPoolReconciler) updateAcceptedStatusCondition(lbbp *isovalentv1alpha1.LBBackendPool, k8sServices []*corev1.Service, missingK8sServiceNames []string) {
	backendPoolValidCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeBackendAccepted,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.BackendAcceptedConditionReasonValid,
		Message:            "BackendPool is valid and accepted",
		ObservedGeneration: lbbp.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	invalidMessages := []string{}

	if valid, invalidMessage := r.validateMaglevTableSizePrime(lbbp); !valid {
		invalidMessages = append(invalidMessages, invalidMessage)
	}

	if valid, invalidMessage := r.validateK8sServiceRefs(lbbp, k8sServices, missingK8sServiceNames); !valid {
		invalidMessages = append(invalidMessages, invalidMessage)
	}

	if valid, invalidMessage := r.validateHealthChecks(lbbp); !valid {
		invalidMessages = append(invalidMessages, invalidMessage)
	}

	if len(invalidMessages) > 0 {
		backendPoolValidCondition.Status = metav1.ConditionFalse
		backendPoolValidCondition.Reason = isovalentv1alpha1.BackendAcceptedConditionReasonInvalid
		backendPoolValidCondition.Message = fmt.Sprintf("BackendPool is invalid: %v", strings.Join(invalidMessages, "\n"))
	}

	lbbp.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeBackendAccepted, backendPoolValidCondition)
}

func (r *lbBackendPoolReconciler) validateMaglevTableSizePrime(lbbp *isovalentv1alpha1.LBBackendPool) (bool, string) {
	if lbbp.Spec.Loadbalancing != nil && lbbp.Spec.Loadbalancing.Algorithm.ConsistentHashing != nil && lbbp.Spec.Loadbalancing.Algorithm.ConsistentHashing.Algorithm != nil && lbbp.Spec.Loadbalancing.Algorithm.ConsistentHashing.Algorithm.Maglev.TableSize != nil {
		desiredMaglevTableSize := *lbbp.Spec.Loadbalancing.Algorithm.ConsistentHashing.Algorithm.Maglev.TableSize

		if !big.NewInt(int64(desiredMaglevTableSize)).ProbablyPrime(1) {
			return false, fmt.Sprintf(".spec.loadBalancing.algorithm.consistentHashing.algorithm.maglev.tableSize %d is not prime", desiredMaglevTableSize)
		}
	}

	return true, ""
}

func (r *lbBackendPoolReconciler) validateK8sServiceRefs(lbbp *isovalentv1alpha1.LBBackendPool, k8sServices []*corev1.Service, missingK8sServiceNames []string) (bool, string) {
	if len(missingK8sServiceNames) > 0 {
		return false, fmt.Sprintf("There are referenced K8s Services that do not exist: %v", missingK8sServiceNames)
	}

	svcs := map[string]*corev1.Service{}

	for _, s := range k8sServices {
		svcs[s.Name] = s
	}

	for _, b := range lbbp.Spec.Backends {
		if b.K8sServiceRef != nil && b.K8sServiceRef.Name != "" {
			portFound := false
			if s, ok := svcs[b.K8sServiceRef.Name]; ok {
				for _, sp := range s.Spec.Ports {
					if sp.Port == b.Port {
						portFound = true
						break
					}
				}
			}

			if !portFound {
				return false, fmt.Sprintf("The backend port %d doesn't exist on the referenced K8s Service %q", b.Port, b.K8sServiceRef.Name)
			}
		}
	}

	return true, ""
}

func (r *lbBackendPoolReconciler) validateHealthChecks(lbbp *isovalentv1alpha1.LBBackendPool) (bool, string) {
	if lbbp.Spec.HealthCheck.HTTP != nil {
		if lbbp.Spec.HealthCheck.HTTP.Send != nil {
			if valid, message := r.validateHealthCheckPayloadEncoding(lbbp.Spec.HealthCheck.HTTP.Send); !valid {
				return valid, fmt.Sprintf("The HTTP health check send is invalid: %s", message)
			}
		}

		for _, hcp := range lbbp.Spec.HealthCheck.HTTP.Receive {
			if valid, message := r.validateHealthCheckPayloadEncoding(hcp); !valid {
				return valid, fmt.Sprintf("One HTTP health check receive is invalid: %s", message)
			}
		}

	} else if lbbp.Spec.HealthCheck.TCP != nil {
		if lbbp.Spec.HealthCheck.TCP.Send != nil {
			if valid, message := r.validateHealthCheckPayloadEncoding(lbbp.Spec.HealthCheck.TCP.Send); !valid {
				return valid, fmt.Sprintf("The TCP health check send is invalid: %s", message)
			}
		}

		for _, hcp := range lbbp.Spec.HealthCheck.TCP.Receive {
			if valid, message := r.validateHealthCheckPayloadEncoding(hcp); !valid {
				return valid, fmt.Sprintf("One TCP health check receive is invalid: %s", message)
			}
		}

	}

	return true, ""
}

func (r *lbBackendPoolReconciler) validateHealthCheckPayloadEncoding(payload *isovalentv1alpha1.HealthCheckPayload) (bool, string) {
	switch {
	case payload.Text != nil:
		if _, err := hex.DecodeString(*payload.Text); err != nil {
			return false, "non hex encoded text payload defined"
		}
	}

	return true, ""
}
