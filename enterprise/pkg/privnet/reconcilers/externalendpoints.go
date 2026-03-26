// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	daemonK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/k8s"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

var ExternalEndpointsCell = cell.Group(
	cell.ProvidePrivate(
		tables.NewExternalEndpointsTable,

		newExternalEndpoints,
	),

	cell.Invoke(
		// Reflects PrivateNetworkExternalEndpoints into the StateDB table
		(*ExternalEndpoints).registerK8sReflector,
		// Writes the PrivateNetworkExternalEndpoints status
		(*ExternalEndpoints).registerK8sStatusReconciler,
	),
)

// ExternalEndpoints reconciles various things related to PrivateNetworkExternalEndpoints.
// See the individual methods for details.
type ExternalEndpoints struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db  *statedb.DB
	tbl statedb.RWTable[*tables.ExternalEndpoint]
}

func newExternalEndpoints(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB    *statedb.DB
	Table statedb.RWTable[*tables.ExternalEndpoint]
}) *ExternalEndpoints {
	return &ExternalEndpoints{
		log: in.Log,
		jg:  in.JobGroup,
		cfg: in.Config,
		db:  in.DB,
		tbl: in.Table,
	}
}

type externalEndpointK8sReflector struct {
	db *statedb.DB

	endpoints  statedb.RWTable[*tables.ExternalEndpoint]
	namespaces statedb.Table[daemonK8s.Namespace]
}

// parsePrivateNetworkExternalEndpoint parses a K8s PrivateNetworkExternalEndpoint into tables.ExternalEndpoint
func (e *externalEndpointK8sReflector) parsePrivateNetworkExternalEndpoint(
	txn statedb.ReadTxn,
	pnee *iso_v1alpha1.PrivateNetworkExternalEndpoint,
) (*tables.ExternalEndpoint, error) {
	var activatedAt time.Time
	if !pnee.Spec.Inactive {
		if !pnee.Status.ActivatedAt.IsZero() {
			// Extract activatedAt timestamp from status if present
			activatedAt = pnee.Status.ActivatedAt.Time
		} else {
			// Otherwise assume this is a fresh PrivateNetworkExternalEndpoint
			activatedAt = time.Now()
		}
	}

	endpointStatus := reconciler.StatusPending()
	k8sStatus := reconciler.StatusPending()

	macAddr, err := mac.ParseMAC(pnee.Spec.Interface.MAC)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MAC address: %w", err)
	}

	var ipv4Addr netip.Addr
	if pnee.Spec.Interface.Addressing.IPv4 != "" {
		ipv4Addr, err = netip.ParseAddr(pnee.Spec.Interface.Addressing.IPv4)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IPv4 address: %w", err)
		}
	}

	var ipv6Addr netip.Addr
	if pnee.Spec.Interface.Addressing.IPv6 != "" {
		ipv6Addr, err = netip.ParseAddr(pnee.Spec.Interface.Addressing.IPv6)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IPv6 address: %w", err)
		}
	}

	if !ipv4Addr.IsValid() && !ipv6Addr.IsValid() {
		return nil, fmt.Errorf("neither IPv4 (%q) nor IPv6 addresses are valid (%q)",
			pnee.Spec.Interface.Addressing.IPv4,
			pnee.Spec.Interface.Addressing.IPv6)
	}

	var namespaceLabels map[string]string
	ns, _, hasNamespaceLabels := e.namespaces.Get(txn, daemonK8s.NamespaceByName(pnee.Namespace))
	if hasNamespaceLabels {
		namespaceLabels = ns.Labels
	} else {
		// We cannot create the endpoint without namespace labels.
		// The endpoint status will be set to pending once the namespace
		// has been discovered.
		endpointStatus = reconciler.StatusDone()
	}

	return &tables.ExternalEndpoint{
		NamespacedName: k8sTypes.NamespacedName{
			Name:      pnee.Name,
			Namespace: pnee.Namespace,
		},
		UID:                pnee.UID,
		ResourceVersion:    pnee.ResourceVersion,
		K8sLabels:          pnee.Labels,
		K8sNamespaceLabels: namespaceLabels,

		Network:     tables.NetworkName(pnee.Spec.Interface.Network),
		IPv4:        ipv4Addr,
		IPv6:        ipv6Addr,
		MAC:         macAddr,
		ActivatedAt: activatedAt,

		EndpointStatus: endpointStatus,
		K8sStatus:      k8sStatus,
	}, nil
}

// handleNamespaceChange updates the labels of every external endpoint in said namespace.
// [wtx] needs to be a write transaction on e.endpoints.
func (e *externalEndpointK8sReflector) handleNamespaceChange(wtx statedb.WriteTxn, ns daemonK8s.Namespace) {
	for ep := range e.endpoints.Prefix(wtx, tables.ExternalEndpointsByNamespace(ns.Name)) {
		if ep.K8sNamespaceLabels != nil && maps.Equal(ep.K8sNamespaceLabels, ns.Labels) {
			continue
		}

		// Update the external endpoint labels and trigger an endpoint reconciler update
		newEP := *ep
		newEP.K8sNamespaceLabels = ns.Labels
		newEP.EndpointStatus = reconciler.StatusPending()
		e.endpoints.Insert(wtx, &newEP)
	}
}

// registerK8sReflector registers the reflector which reads PrivateNetworkExternalEndpoints from K8s and writes them
// into the [tables.ExternalEndpoint] StateDB table.
func (e *ExternalEndpoints) registerK8sReflector(in struct {
	cell.In

	Client     client.Clientset
	CRDSync    promise.Promise[k8sSynced.CRDSync]
	Namespaces statedb.Table[daemonK8s.Namespace]
}) error {
	if !e.cfg.EnabledAsBridge() {
		return nil
	}

	if !in.Client.IsEnabled() {
		return errors.New("private networks requires Kubernetes support to be enabled")
	}

	r := externalEndpointK8sReflector{
		db:         e.db,
		endpoints:  e.tbl,
		namespaces: in.Namespaces,
	}

	// Start a job that watches for namespace updates to add namespace labels to the external endpoints
	wtx := e.db.WriteTxn(e.tbl)
	nsInitialized := e.tbl.RegisterInitializer(wtx, "namespaces-initialized")
	wtx.Commit()
	e.jg.Add(job.OneShot("external-endpoints-namespace-watch", func(ctx context.Context, health cell.Health) error {
		wtx := e.db.WriteTxn(in.Namespaces)
		changeIter, _ := in.Namespaces.Changes(wtx)
		wtx.Commit()

		initDone := false
		for {
			wtx = e.db.WriteTxn(e.tbl)
			changes, watch := changeIter.Next(wtx)
			for change := range changes {
				if change.Deleted {
					continue // endpoints will be deleted by reflector below
				}
				r.handleNamespaceChange(wtx, change.Object)
			}

			var initWatch <-chan struct{}
			if !initDone {
				init, nw := in.Namespaces.Initialized(wtx)
				switch {
				case !init:
					initWatch = nw
				default:
					initDone = true
					nsInitialized(wtx)
				}
			}

			wtx.Commit()
			select {
			case <-ctx.Done():
				return nil
			case <-watch:
			case <-initWatch:
			}
		}
	}))

	// Register a reflector that parses the K8s PrivateNetworkExternalEndpoints
	return k8s.RegisterReflector(e.jg, e.db, k8s.ReflectorConfig[*tables.ExternalEndpoint]{
		Name:  "to-table",
		Table: e.tbl,
		ListerWatcher: k8sUtils.ListerWatcherFromTyped(
			in.Client.IsovalentV1alpha1().PrivateNetworkExternalEndpoints(corev1.NamespaceAll),
		),
		CRDSync: in.CRDSync,
		Transform: func(txn statedb.ReadTxn, obj any) (*tables.ExternalEndpoint, bool) {
			pnee, ok := obj.(*iso_v1alpha1.PrivateNetworkExternalEndpoint)
			if !ok {
				return nil, false
			}

			extEp, err := r.parsePrivateNetworkExternalEndpoint(txn, pnee)
			if err != nil {
				e.log.Warn("failed to parse private network external endpoint",
					logfields.Name, pnee.Name,
					logfields.K8sNamespace, pnee.Namespace,
					logfields.Error, err,
				)
				return nil, false
			}

			return extEp, true
		},
		Merge: func(old *tables.ExternalEndpoint, new *tables.ExternalEndpoint) *tables.ExternalEndpoint {
			// Avoid re-triggering the reconcilers if no relevant fields have changed
			if new.ActivatedAt.Equal(old.ActivatedAt) {
				// ActivatedAt is already up to date, no need to reconcile the K8s status
				new.K8sStatus = old.K8sStatus
				if maps.Equal(new.K8sLabels, old.K8sLabels) &&
					maps.Equal(new.K8sNamespaceLabels, old.K8sNamespaceLabels) {
					// Labels and ActivatedAt have both not changed, no need to update the local endpoint
					new.EndpointStatus = old.EndpointStatus
				}
			}

			// Emit error if immutable fields changed (this should be rejected by K8s, but just in case)
			if old.UID == new.UID &&
				(old.Network != new.Network ||
					old.IPv4 != new.IPv4 ||
					old.IPv6 != new.IPv6 ||
					!bytes.Equal(old.MAC, new.MAC)) {
				e.log.Error("Ignoring change to immutable field(s) in PrivateNetworkExternalEndpoint",
					logfields.K8sNamespace, new.Namespace,
					logfields.Name, new.Name,
				)
			}

			return new
		},
	})
}

// externalEndpointK8sReconcilerOps implements reconciler.Operations to reconcile
// the status field of PrivateNetworkExternalEndpoint resources based on the
// [tables.ExternalEndpoint] table.
type externalEndpointK8sReconcilerOps struct {
	client client.Clientset
}

// Update implements reconciler.Operations.
// Please note that tables.ExternalEndpoint has multiple reconcilers status fields, so ensure that [obj] is not modified.
func (e *externalEndpointK8sReconcilerOps) Update(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, obj *tables.ExternalEndpoint) error {
	client := e.client.IsovalentV1alpha1().PrivateNetworkExternalEndpoints(obj.Namespace)
	ipStr := func(addr netip.Addr) string {
		if !addr.IsValid() {
			return ""
		}
		return addr.String()
	}
	pnee := &iso_v1alpha1.PrivateNetworkExternalEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:            obj.Name,
			Namespace:       obj.Namespace,
			ResourceVersion: obj.ResourceVersion,
			Labels:          obj.K8sLabels, // workaround for script test bug
			UID:             obj.UID,       // workaround for script test bug
		},
		// The object spec (and labels) are ignored by K8s when doing UpdateStatus.
		// However, our script test framework has a bug where it does not ignore
		// them and will replace them in the object tracker, so set them anyway.
		Spec: iso_v1alpha1.PrivateNetworkExternalEndpointSpec{
			Inactive: obj.ActivatedAt.IsZero(),
			Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
				Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
					IPv4: ipStr(obj.IPv4),
					IPv6: ipStr(obj.IPv6),
				},
				MAC:     obj.MAC.String(),
				Network: string(obj.Network),
			},
		},
		Status: iso_v1alpha1.PrivateNetworkExternalEndpointStatus{
			ActivatedAt: metav1.NewMicroTime(obj.ActivatedAt),
		},
	}
	_, err := client.UpdateStatus(ctx, pnee, metav1.UpdateOptions{})
	return err
}

// Delete implements reconciler.Delete.
func (e *externalEndpointK8sReconcilerOps) Delete(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, obj *tables.ExternalEndpoint) error {
	return nil // nothing to do
}

// Prune implements reconciler.Prune.
func (e *externalEndpointK8sReconcilerOps) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*tables.ExternalEndpoint, statedb.Revision]) error {
	return nil // pruning is disabled
}

// registerK8sStatusReconciler registers the reconciler which reconcile the status field of
// PrivateNetworkExternalEndpoint resources. This is needed to persist the ActivatedAt timestamp
// across node reboots, as we cannot rely on the filesystem to store this information like we do
// for regular endpoints.
func (e *ExternalEndpoints) registerK8sStatusReconciler(client client.Clientset, params reconciler.Params) error {
	if !e.cfg.EnabledAsBridge() {
		return nil
	}

	if !client.IsEnabled() {
		return errors.New("private networks requires Kubernetes support to be enabled")
	}

	ops := &externalEndpointK8sReconcilerOps{
		client: client,
	}
	_, err := reconciler.Register(
		// params
		params,
		// table
		e.tbl,
		// clone
		func(e *tables.ExternalEndpoint) *tables.ExternalEndpoint {
			// shallow copy is enough for reconciler
			cpy := *e
			return &cpy
		},
		// setStatus
		func(e *tables.ExternalEndpoint, s reconciler.Status) *tables.ExternalEndpoint {
			e.K8sStatus = s
			return e
		},
		// getStatus
		func(e *tables.ExternalEndpoint) reconciler.Status {
			return e.K8sStatus
		},
		// ops
		ops,
		// batchOps
		nil,
		// options
		reconciler.WithoutPruning(),
	)
	return err
}
