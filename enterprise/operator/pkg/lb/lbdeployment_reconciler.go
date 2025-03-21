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
	"strings"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type lbDeploymentReconciler struct {
	logger *slog.Logger
	client client.Client
}

func newLBDeploymentReconciler(logger *slog.Logger, client client.Client) *lbDeploymentReconciler {
	return &lbDeploymentReconciler{
		logger: logger,
		client: client,
	}
}

// SetupWithManager sets up the controller with the Manager and configures
// the different watches. All the watcher trigger a reconciliation.
func (r *lbDeploymentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Watch for changed LBDeployment resources (main resource)
		For(&isovalentv1alpha1.LBDeployment{}).
		Complete(r)
}

// Reconcile implements the main reconciliation loop that gets triggered whenever a LBDeployment resource or a related resource changes.
func (r *lbDeploymentReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, "LBDeployment",
		logfields.Resource, req.NamespacedName,
	)

	scopedLog.Info("Reconciling LBDeployment")
	la := &isovalentv1alpha1.LBDeployment{}
	if err := r.client.Get(ctx, req.NamespacedName, la); err != nil {
		if !k8serrors.IsNotFound(err) {
			return controllerruntime.Fail(fmt.Errorf("failed to get LBDeployment: %w", err))
		}

		scopedLog.Debug("LBDeployment not found - assuming it has been deleted")

		// LBDeployment has been deleted in the meantime
		return controllerruntime.Success()
	}

	// LBDeployment gets deleted via foreground deletion (DeletionTimestamp set)
	// -> abort and wait for the actual deletion to trigger a reconcile
	if la.GetDeletionTimestamp() != nil {
		scopedLog.Debug("LBDeployment is marked for deletion - waiting for actual deletion")
		return controllerruntime.Success()
	}

	r.updateAcceptedStatusCondition(la)

	la.UpdateResourceStatus()

	// Update the status of LBDeployment
	if err := r.client.Status().Update(ctx, la); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update LBDeployment status: %w", err))
	}

	return controllerruntime.Success()
}

func (r *lbDeploymentReconciler) updateAcceptedStatusCondition(lbd *isovalentv1alpha1.LBDeployment) {
	condition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeDeploymentAccepted,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.DeploymentAcceptedConditionReasonValid,
		Message:            "Deployment is valid and accepted",
		ObservedGeneration: lbd.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	invalidMessages := []string{}

	if valid, labelIssueMessages := r.validateLabelSelectors(lbd); !valid {
		invalidMessages = append(invalidMessages, labelIssueMessages...)
	}

	if len(invalidMessages) > 0 {
		condition.Status = metav1.ConditionFalse
		condition.Reason = isovalentv1alpha1.DeploymentAcceptedConditionReasonInvalid
		condition.Message = fmt.Sprintf("Deployment is invalid: %v", strings.Join(invalidMessages, "\n"))
	}

	lbd.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeDeploymentAccepted, condition)
}

func (r *lbDeploymentReconciler) validateLabelSelectors(lbd *isovalentv1alpha1.LBDeployment) (bool, []string) {
	labelIssues := []string{}

	if lbd.Spec.Services.LabelSelector != nil {
		if _, err := slim_metav1.LabelSelectorAsSelector(lbd.Spec.Services.LabelSelector); err != nil {
			labelIssues = append(labelIssues, fmt.Sprintf("Invalid service labelselector: %s", err))
		}
	}

	if lbd.Spec.Nodes.LabelSelectors != nil {
		if _, err := slim_metav1.LabelSelectorAsSelector(&lbd.Spec.Nodes.LabelSelectors.T1); err != nil {
			labelIssues = append(labelIssues, fmt.Sprintf("Invalid T1 node labelselector: %s", err))
		}

		if _, err := slim_metav1.LabelSelectorAsSelector(&lbd.Spec.Nodes.LabelSelectors.T2); err != nil {
			labelIssues = append(labelIssues, fmt.Sprintf("Invalid T2 node labelselector: %s", err))
		}
	}

	return len(labelIssues) == 0, labelIssues
}
