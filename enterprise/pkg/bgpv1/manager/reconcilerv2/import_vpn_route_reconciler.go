// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
)

type importVPNRouteReconcilerOut struct {
	cell.Out

	Reconciler reconcilerv2.StateReconciler `group:"bgp-state-reconciler-v2"`
}

func newImportVPNRouteStateReconciler(
	enterpriseConfig Config,
	reconciler *importVPNRouteReconciler,
	legacyReconciler *legacyImportVPNRouteReconciler,
) importVPNRouteReconcilerOut {
	if enterpriseConfig.EnableLegacySRv6Responder {
		return importVPNRouteReconcilerOut{
			Reconciler: legacyReconciler,
		}
	}
	return importVPNRouteReconcilerOut{
		Reconciler: reconciler,
	}
}

type importVPNRouteReconciler struct{}

type importVPNRouteReconcilerIn struct {
	cell.In
}

func newImportVPNRouteReconciler() *importVPNRouteReconciler {
	return &importVPNRouteReconciler{}
}

func (r *importVPNRouteReconciler) Name() string {
	return ImportedVPNRouteReconcilerName
}

func (r *importVPNRouteReconciler) Priority() int {
	return ImportedVPNRouteReconcilerPriority
}

func (r *importVPNRouteReconciler) Reconcile(ctx context.Context, p reconcilerv2.StateReconcileParams) error {
	return nil
}
