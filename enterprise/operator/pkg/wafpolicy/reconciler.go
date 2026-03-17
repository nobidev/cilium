//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package wafpolicy

import (
	"context"
	"fmt"
	"log/slog"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type reconciler struct {
	logger *slog.Logger
	client client.Client
}

func newReconciler(logger *slog.Logger, client client.Client) *reconciler {
	return &reconciler{
		logger: logger,
		client: client,
	}
}

func (r *reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&isovalentv1alpha1.IsovalentWAFPolicy{}).
		Complete(r)
}

func (r *reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, "IsovalentWAFPolicy",
		logfields.Resource, req.NamespacedName,
	)

	scopedLog.Debug("Reconciling IsovalentWAFPolicy")
	policy := &isovalentv1alpha1.IsovalentWAFPolicy{}
	if err := r.client.Get(ctx, req.NamespacedName, policy); err != nil {
		if !k8serrors.IsNotFound(err) {
			return controllerruntime.Fail(fmt.Errorf("failed to get IsovalentWAFPolicy: %w", err))
		}

		scopedLog.Debug("IsovalentWAFPolicy not found - assuming it has been deleted")
		return controllerruntime.Success()
	}

	if policy.GetDeletionTimestamp() != nil {
		scopedLog.Debug("IsovalentWAFPolicy is marked for deletion - waiting for actual deletion")
		return controllerruntime.Success()
	}

	condition := Condition(policy, Validate(policy))
	if !SetCondition(policy, condition) {
		return controllerruntime.Success()
	}

	if err := r.client.Status().Update(ctx, policy); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update IsovalentWAFPolicy status: %w", err))
	}

	return controllerruntime.Success()
}
