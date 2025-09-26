// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package status

import (
	"context"
	"fmt"
	"iter"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/operator/pkg/evpn"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
)

type k8sReconciler struct {
	config   config.Config
	pnsTable statedb.RWTable[tables.PrivateNetworkStatus]
	cs       client.Clientset
}

type k8sReconcilerIn struct {
	cell.In

	Config     config.Config
	EVPNConfig evpn.Config
	PNSTable   statedb.RWTable[tables.PrivateNetworkStatus]
	CS         client.Clientset
}

var _ reconciler.Operations[tables.PrivateNetworkStatus] = &k8sReconciler{}

func newK8sReconciler(in k8sReconcilerIn) *k8sReconciler {
	return &k8sReconciler{
		config:   in.Config,
		pnsTable: in.PNSTable,
		cs:       in.CS,
	}
}

func (r *k8sReconciler) register(params reconciler.Params, config config.Config) (reconciler.Reconciler[tables.PrivateNetworkStatus], error) {
	if !config.Enabled {
		return nil, nil
	}
	return reconciler.Register(
		params,
		r.pnsTable,
		func(pns tables.PrivateNetworkStatus) tables.PrivateNetworkStatus {
			return pns
		},
		func(pns tables.PrivateNetworkStatus, status reconciler.Status) tables.PrivateNetworkStatus {
			pns.Status = status
			return pns
		},
		func(pns tables.PrivateNetworkStatus) reconciler.Status {
			return pns.Status
		},
		r,
		nil,
		reconciler.WithoutPruning(),
		reconciler.WithRefreshing(time.Hour, rate.NewLimiter(50, 1)),
	)
}

func (r *k8sReconciler) desiredPrivateNetworkStatus(current *v1alpha1.PrivateNetworkStatus, pns tables.PrivateNetworkStatus) *v1alpha1.PrivateNetworkStatus {
	var desired *v1alpha1.PrivateNetworkStatus

	if current != nil {
		desired = current.DeepCopy()
	} else {
		desired = &v1alpha1.PrivateNetworkStatus{}
	}

	r.updateVNIStatus(pns, desired)

	return desired
}

func (r *k8sReconciler) updateVNIStatus(pns tables.PrivateNetworkStatus, status *v1alpha1.PrivateNetworkStatus) {
	if pns.VNI.AllocatedVNI.IsValid() {
		status.VNI = ptr.To(pns.VNI.AllocatedVNI.AsUint32())
	} else {
		// This also covers the cleanup when VNI allocation is disabled
		// as the RequestedVNI is not set in that case.
		status.VNI = nil
	}

	if pns.VNI.RequestedVNI.IsValid() {
		condition := metav1.Condition{
			Type: v1alpha1.PrivateNetworkCondTypeVNIConflict,
		}
		if pns.VNI.HasVNIConflict {
			condition.Status = metav1.ConditionTrue
			condition.Reason = v1alpha1.PrivateNetworkCondReasonHasVNIConflict
			condition.Message = "Private Network has VNI conflict"
		} else {
			condition.Status = metav1.ConditionFalse
			condition.Reason = v1alpha1.PrivateNetworkCondReasonHasNoVNIConflict
			condition.Message = "Private Network has no VNI conflict"
		}
		meta.SetStatusCondition(&status.Conditions, condition)
	} else {
		// This also covers the cleanup when VNI allocation is disabled
		// as the RequestedVNI is not set in that case.
		meta.RemoveStatusCondition(&status.Conditions, v1alpha1.PrivateNetworkCondTypeVNIConflict)
	}
}

func (r *k8sReconciler) Update(ctx context.Context, _ statedb.ReadTxn, _ statedb.Revision, pns tables.PrivateNetworkStatus) error {
	current := pns.OrigResource.Status
	desired := r.desiredPrivateNetworkStatus(current, pns)

	if current != nil && current.DeepEqual(desired) {
		// Skip update if nothing changed
		return nil
	}

	cpy := pns.OrigResource.DeepCopy()
	cpy.Status = desired

	if _, err := r.cs.IsovalentV1alpha1().ClusterwidePrivateNetworks().UpdateStatus(ctx, cpy, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to update status of ClusterwidePrivateNetwork %s: %w", pns.Name, err)
	}

	return nil
}

func (r *k8sReconciler) Delete(_ context.Context, _ statedb.ReadTxn, _ statedb.Revision, _ tables.PrivateNetworkStatus) error {
	// We don't need to handle delete because deleting object from
	// private-network-state table means that the private network is being
	// deleted.
	return nil
}

func (r *k8sReconciler) Prune(ctx context.Context, rtxn statedb.ReadTxn, pnss iter.Seq2[tables.PrivateNetworkStatus, statedb.Revision]) error {
	return nil
}
