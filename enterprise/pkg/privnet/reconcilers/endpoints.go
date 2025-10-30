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
	"context"
	"errors"
	"iter"
	"log/slog"
	"maps"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/promise"
)

var EndpointsCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite Endpoints table.
		tables.NewEndpointsTable,

		// Provides a k8s.SharedListerWatcher for private network endpoint slices
		newEndpointSliceSharedListerWatcher,

		// Provides the reconciler handling private network endpoints.
		newEndpoints,
	),

	cell.Provide(
		// Provides the ReadOnly PrivateNetworks table.
		statedb.RWTable[tables.Endpoint].ToTable,

		// Provides the object to observe endpoint events from clustermesh.
		observers.NewPrivateNetworkEndpoints,
	),

	cell.Invoke(
		// Registers the k8s to table reflector.
		(*Endpoints).registerK8sReflector,

		// Registers the clustermesh to table reflector.
		(*Endpoints).registerClusterMeshReflector,
	),
)

// Endpoints is the reconciler for private network endpoints.
type Endpoints struct {
	log *slog.Logger
	jg  job.Group

	cfg   config.Config
	cname tables.ClusterName

	db  *statedb.DB
	tbl statedb.RWTable[tables.Endpoint]
}

func newEndpoints(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config      config.Config
	ClusterInfo cmtypes.ClusterInfo

	DB    *statedb.DB
	Table statedb.RWTable[tables.Endpoint]
}) (*Endpoints, error) {
	reconciler := &Endpoints{
		log:   in.Log,
		jg:    in.JobGroup,
		cfg:   in.Config,
		cname: tables.ClusterName(in.ClusterInfo.Name),
		db:    in.DB,
		tbl:   in.Table,
	}

	if !in.Config.Enabled {
		return reconciler, nil
	}

	return reconciler, nil
}

func (ep *Endpoints) registerK8sReflector(sync promise.Promise[synced.CRDSync], listerWatcher endpointSliceSharedListerWatcher) error {
	if !ep.cfg.Enabled {
		return nil
	}

	cfg := k8s.ReflectorConfig[tables.Endpoint]{
		Name:                "to-table", // the full name will be "job-k8s-reflector-privnet-endpoints-to-table"
		Table:               ep.tbl,
		SharedListerWatcher: listerWatcher,
		MetricScope:         "PrivateNetworkEndpointSlices",
		CRDSync:             sync,

		// Make sure we o not delete the entries discovered via Cluster Mesh.
		QueryAll: func(txn statedb.ReadTxn, tbl statedb.Table[tables.Endpoint]) iter.Seq2[tables.Endpoint, statedb.Revision] {
			return ep.tbl.Prefix(txn, tables.EndpointsByCluster(ep.cname))
		},

		TransformMany: func(txn statedb.ReadTxn, deleted bool, obj any) (toInsert, toDelete iter.Seq[tables.Endpoint]) {
			slice, ok := obj.(*iso_v1alpha1.PrivateNetworkEndpointSlice)
			if !ok {
				return nil, nil
			}

			source := tables.Source{
				Cluster:   string(ep.cname),
				Namespace: slice.GetNamespace(),
				Name:      slice.GetName(),
			}

			stale := ep.tbl.Prefix(txn, tables.EndpointsBySource(source))
			if deleted {
				return nil, statedb.ToSeq(stale)
			}

			current := make(map[tables.EndpointKey]tables.Endpoint)
			for endpoint := range tables.EndpointsFromEndpointSlice(ep.log, ep.cname, slice) {
				current[endpoint.Key()] = endpoint
			}

			filter := func(ep tables.Endpoint) bool {
				_, ok := current[ep.Key()]
				return !ok
			}

			return maps.Values(current), statedb.ToSeq(statedb.Filter(stale, filter))
		},
	}

	return k8s.RegisterReflector(ep.jg, ep.db, cfg)
}

func (ep *Endpoints) registerClusterMeshReflector(obs *observers.PrivateNetworkEndpoints) {
	if !ep.cfg.Enabled {
		return
	}

	wtx := ep.db.WriteTxn(ep.tbl)
	finish := ep.tbl.RegisterInitializer(wtx, "clustermesh")
	wtx.Commit()

	ep.jg.Add(
		job.Observer(
			"clustermesh-privnet-endpoints-to-table",
			func(ctx context.Context, buf observers.EndpointEvents) error {
				wtx := ep.db.WriteTxn(ep.tbl)

				for _, ev := range buf {
					switch ev.EventKind {
					case resource.Upsert:
						// Endpoints are keyed by cluster, network name and PIP inside
						// etcd, so it is possible that all other fields are updated without
						// changing the key. However, this table uses a different primary
						// key, so we need to explicitly delete the old version, if present.
						for other := range ep.tbl.Prefix(wtx, tables.EndpointsByPIP(ev.Object.IP)) {
							if other.Source.Cluster == ev.Object.Source.Cluster &&
								other.Network.Name == ev.Object.Network.Name {
								ep.tbl.Delete(wtx, other)
							}
						}

						ep.tbl.Insert(wtx, tables.Endpoint{Endpoint: ev.Object})
					case resource.Delete:
						ep.tbl.Delete(wtx, tables.Endpoint{Endpoint: ev.Object})
					case resource.Sync:
						finish(wtx)
					}
				}

				wtx.Commit()
				return nil
			}, obs,
		),
	)
}

type endpointSliceSharedListerWatcher k8s.SharedListerWatcher

func newEndpointSliceSharedListerWatcher(in struct {
	cell.In

	Config   config.Config
	JobGroup job.Group
	Client   client.Clientset
}) (endpointSliceSharedListerWatcher, error) {
	if !in.Config.Enabled {
		return nil, nil
	}

	if !in.Client.IsEnabled() {
		return nil, errors.New("private networks requires Kubernetes support to be enabled")
	}

	epSlices := in.Client.IsovalentV1alpha1().PrivateNetworkEndpointSlices(metav1.NamespaceAll)
	listerWatcher := utils.ListerWatcherFromTyped(epSlices)
	return k8s.NewSharedListerWatcher("privnet-endpointslices", in.JobGroup, listerWatcher), nil
}
