//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ingresspolicy

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/ciliumenvoyconfig/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

const (
	k8sAPIGroupCiliumEnvoyConfigV2 = "cilium/v2::CiliumEnvoyConfig"
)

// Cell provides support for the CEC Ingress Policy
var Cell = cell.Module(
	"cec-ingress-policy",
	"Ingress Policy for CiliumEnvoyConfig",

	cell.Invoke(registerCECK8sReconciler),
	cell.ProvidePrivate(newIngressPolicyManager),
)

type reconcilerParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Health    cell.Health

	K8sResourceSynced *synced.Resources
	K8sAPIGroups      *synced.APIGroups

	Config       types.CECPolicyConfig
	CECResources resource.Resource[*ciliumv2.CiliumEnvoyConfig]

	IngressPolicyManager Updater
}

type cecReconciler struct {
	logger *slog.Logger

	k8sResourceSynced *synced.Resources
	k8sAPIGroups      *synced.APIGroups

	cecSynced atomic.Bool

	ingressPolicyManager Updater
}

func registerCECK8sReconciler(params reconcilerParams) {
	if !option.Config.EnableL7Proxy || !option.Config.EnableEnvoyConfig ||
		params.Config.Mode != types.CECPolicyModeDedicated {
		return
	}

	reconciler := newCECReconciler(params)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reconciler.registerResourceWithSyncFn(ctx, k8sAPIGroupCiliumEnvoyConfigV2, func() bool {
		return reconciler.cecSynced.Load()
	})
	params.JobGroup.Add(job.Observer("cec-resource-events", reconciler.handleCECEvent, params.CECResources))
}

func newCECReconciler(params reconcilerParams) *cecReconciler {
	return &cecReconciler{
		logger:               params.Logger,
		k8sResourceSynced:    params.K8sResourceSynced,
		k8sAPIGroups:         params.K8sAPIGroups,
		ingressPolicyManager: params.IngressPolicyManager,
	}
}

func (r *cecReconciler) registerResourceWithSyncFn(ctx context.Context, resource string, syncFn func() bool) {
	if r.k8sResourceSynced != nil && r.k8sAPIGroups != nil {
		r.k8sResourceSynced.BlockWaitGroupToSyncResources(ctx.Done(), nil, syncFn, resource)
		r.k8sAPIGroups.AddAPI(resource)
	}
}

func (r *cecReconciler) handleCECEvent(ctx context.Context, event resource.Event[*ciliumv2.CiliumEnvoyConfig]) error {
	scopedLogger := r.logger.With(
		logfields.K8sNamespace, event.Key.Namespace,
		logfields.CiliumEnvoyConfigName, event.Key.Name,
	)

	var err error

	switch event.Kind {
	case resource.Sync:
		scopedLogger.Debug("Received CiliumEnvoyConfig sync event")
		r.cecSynced.Store(true)
	case resource.Upsert:
		scopedLogger.Debug("Received CiliumEnvoyConfig upsert event")
		err = r.ingressPolicyManager.EnsureIngressPolicy(ctx, resource.NewKey(event.Object), event.Object.Labels)
	case resource.Delete:
		scopedLogger.Debug("Received CiliumEnvoyConfig delete event")
		err = r.ingressPolicyManager.DeleteIngressPolicy(ctx, resource.NewKey(event.Object), event.Object.Labels)
	}

	event.Done(err)
	return err
}
