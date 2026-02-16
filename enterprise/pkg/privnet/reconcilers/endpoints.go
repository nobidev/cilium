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
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

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
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	cslices "github.com/cilium/cilium/pkg/slices"
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
		// Provides the ReadOnly Endpoints table.
		statedb.RWTable[tables.Endpoint].ToTable,

		// Provides the object to observe endpoint events from clustermesh.
		observers.NewPrivateNetworkEndpoints,
	),

	cell.Invoke(
		// Registers the k8s to table reflector.
		(*Endpoints).registerK8sReflector,

		// Registers the clustermesh to table reflector.
		(*Endpoints).registerClusterMeshReflector,

		// Registers reconciler that updates subnet assignment on subnet changes.
		(*Endpoints).registerSubnetAssignmentReconciler,
	),
)

// Endpoints is the reconciler for private network endpoints.
type Endpoints struct {
	log *slog.Logger
	jg  job.Group

	cfg   config.Config
	cname tables.ClusterName

	db      *statedb.DB
	tbl     statedb.RWTable[tables.Endpoint]
	subnets statedb.Table[tables.Subnet]
}

func newEndpoints(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config      config.Config
	ClusterInfo cmtypes.ClusterInfo

	DB      *statedb.DB
	Table   statedb.RWTable[tables.Endpoint]
	Subnets statedb.Table[tables.Subnet]
}) *Endpoints {
	return &Endpoints{
		log:     in.Log,
		jg:      in.JobGroup,
		cfg:     in.Config,
		cname:   tables.ClusterName(in.ClusterInfo.Name),
		db:      in.DB,
		tbl:     in.Table,
		subnets: in.Subnets,
	}
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

			return ep.mapEndpointsToSubnet(txn, maps.Values(current)), statedb.ToSeq(statedb.Filter(stale, filter))
		},
	}

	return k8s.RegisterReflector(ep.jg, ep.db, cfg)
}

func (ep *Endpoints) mapEndpointsToSubnet(txn statedb.ReadTxn, in iter.Seq[tables.Endpoint]) iter.Seq[tables.Endpoint] {
	type key struct {
		Network  tables.NetworkName
		Endpoint string
	}

	type value struct {
		Subnet tables.SubnetName
		IPs    []netip.Addr
	}

	var mappings = make(map[key]value)

	for endpoint := range in {
		k := key{tables.NetworkName(endpoint.Network.Name), endpoint.Name}
		v := mappings[k]

		v.IPs = append(v.IPs, endpoint.Network.IP)
		mappings[k] = v
	}

	for k, v := range mappings {
		sn, _ := tables.FindSubnetForIPs(ep.subnets, txn, k.Network, v.IPs...)
		v.Subnet = sn.Name
		mappings[k] = v
	}

	return cslices.MapIter(in,
		func(in tables.Endpoint) tables.Endpoint {
			in.Subnet = mappings[key{tables.NetworkName(in.Network.Name), in.Name}].Subnet
			return in
		})
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
						for other := range ep.tbl.List(wtx, tables.EndpointsByPIP(ev.Object.IP)) {
							if other.Source.Cluster == ev.Object.Source.Cluster &&
								other.Network.Name == ev.Object.Network.Name {
								ep.tbl.Delete(wtx, other)
							}
						}

						ep.tbl.Insert(wtx, tables.Endpoint{Endpoint: ev.Object})

						// We enforce the invariant that all endpoint with the same source and name are in the same subnet or no subnet.
						// We just added an endpoint that might have a conflict with another endpoint.
						ep.enforceSubnetConsistency(wtx, ev.Object.Source, ev.Object.Name)
					case resource.Delete:
						ep.tbl.Delete(wtx, tables.Endpoint{Endpoint: ev.Object})
						// We enforce the invariant that all endpoint with the same source and name are in the same subnet or no subnet.
						// We just removed an endpoint that might have conflicted with another endpoint. Check if they can now be assigned
						// to a subnet.
						ep.enforceSubnetConsistency(wtx, ev.Object.Source, ev.Object.Name)
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

func (ep *Endpoints) registerSubnetAssignmentReconciler() {
	if !ep.cfg.Enabled {
		return
	}

	wtx := ep.db.WriteTxn(ep.tbl)
	initialized := ep.tbl.RegisterInitializer(wtx, "subnet-assignment-initialized")
	wtx.Commit()

	ep.jg.Add(job.OneShot("assign-subnets-to-endpoints", func(ctx context.Context, _ cell.Health) error {
		var initDone bool

		txn := ep.db.WriteTxn(ep.subnets)
		changeIter, _ := ep.subnets.Changes(txn)
		txn.Commit()

		for {
			var initWatch <-chan struct{}
			txn := ep.db.WriteTxn(ep.tbl)
			changes, watch := changeIter.Next(txn)

			for change := range changes {
				ep.log.Debug("Processing table event",
					logfields.Table, ep.subnets.Name(),
					logfields.Event, change,
				)

				type epSourceName struct {
					source tables.Source
					name   string
				}
				enforcedEps := sets.Set[epSourceName]{}
				enforceSubnetConsistencyForPrefix := func(prefix iter.Seq2[tables.Endpoint, statedb.Revision]) {
					for e := range prefix {
						key := epSourceName{
							source: e.Source,
							name:   e.Name,
						}
						// check if we have already checked this endpoint name to avoid redundant work
						if !enforcedEps.Has(key) {
							ep.enforceSubnetConsistency(txn, e.Source, e.Name)
							enforcedEps.Insert(key)
						}
					}
				}

				sub := change.Object
				if change.Deleted {
					// Reassign things
					enforceSubnetConsistencyForPrefix(ep.tbl.Prefix(txn, tables.EndpointsByNetworkSubnet(sub.Network, sub.Name)))
				} else {
					// Check if we can adopt some endpoints
					enforceSubnetConsistencyForPrefix(ep.tbl.Prefix(txn, tables.EndpointsByNetworkSubnet(sub.Network, "")))
					// Check if we need to orphan some endpoints
					enforceSubnetConsistencyForPrefix(ep.tbl.Prefix(txn, tables.EndpointsByNetworkSubnet(sub.Network, sub.Name)))
				}
			}

			// In order to be able to propagate initialization, we need to check if the upstream
			// tables have already been initialized
			if !initDone {
				init, nw := ep.subnets.Initialized(txn)

				switch {
				case !init:
					initWatch = nw
				default:
					initDone = true
					initialized(txn)
				}
			}

			txn.Commit()

			// Wait until there's new changes to consume
			select {
			case <-ctx.Done():
				return nil
			case <-watch:
			case <-initWatch:
			}
		}
	}))
}

// enforceSubnetConsistency enforces the invariant that all endpoint with the provided source and name are in the same subnet or no subnet.
//
// In general there should be at most 2 endpoints per source/name. One IPv4 and one IPv6 address. Both should end
// up in the same subnet. If there are more than 2 endpoints per source/name, this likely indicates some consistency
// issues, for example because we observe the endpoint updates out of order. We still enforce the invariable in that case.
func (ep *Endpoints) enforceSubnetConsistency(txn statedb.WriteTxn, source tables.Source, name string) {
	conflict := false
	var network tables.NetworkName
	var subnet tables.Subnet
	toInsert := []tables.Endpoint{}

	for e := range ep.tbl.Prefix(txn, tables.EndpointsBySourceAndName(source, name)) {
		toInsert = append(toInsert, e)
		switch {
		case conflict:
			// If we already saw a conflict, we'll orphan all endpoints anyways, skip checks
		case network == "":
			// If we have not seen a subnet/network yet. This only happens for the first endpoint.
			// Check what subnet this endpoint belongs to.
			network = tables.NetworkName(e.Network.Name)
			var ok bool
			subnet, ok = tables.FindSubnetForIPs(ep.subnets, txn, tables.NetworkName(e.Network.Name), e.Network.IP)
			if !ok {
				// endpoint does not match any subnet - we'll orphan all endpoints
				conflict = true
			}
		default:
			// We've already seen another endpoint - check that this endpoint is also in the same network and subnet
			if tables.NetworkName(e.Network.Name) != network ||
				(!subnet.CIDRv4.Contains(e.Network.IP) && !subnet.CIDRv6.Contains(e.Network.IP)) {
				conflict = true
			}
		}
	}

	var subnetName tables.SubnetName
	if !conflict {
		subnetName = subnet.Name
	}

	for _, e := range toInsert {
		// Only trigger insert if subnet changed
		if e.Subnet != subnetName {
			e.Subnet = subnetName
			ep.tbl.Insert(txn, e)
		}
	}
}
