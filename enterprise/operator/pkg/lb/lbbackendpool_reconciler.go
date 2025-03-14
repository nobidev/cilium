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
	"log/slog"
	"math/big"
	"strings"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
	return ctrl.NewControllerManagedBy(mgr).
		// Watch for changed LBBackendPool resources (main resource)
		For(&isovalentv1alpha1.LBBackendPool{}).
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

	r.updateAcceptedStatusCondition(lb)

	lb.UpdateResourceStatus()

	// Update the status of LBBackendPool
	if err := r.client.Status().Update(ctx, lb); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update LBBackendPool status: %w", err))
	}

	return controllerruntime.Success()
}

func (r *lbBackendPoolReconciler) updateAcceptedStatusCondition(lbbp *isovalentv1alpha1.LBBackendPool) {
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
