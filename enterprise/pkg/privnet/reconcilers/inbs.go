//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconcilers

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/health"
	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nomgr "github.com/cilium/cilium/pkg/node/manager"
)

var INBsCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite INBs table.
		tables.NewINBsTable,

		// Provides the reconciler handling private network INBs.
		newINBs,

		// Provides the function selecting the active INB index given a set of
		// candidates. Can be overridden to obtain stable selections for testing.
		(*INBs).newDefaultActiveIndexFunc,
	),

	cell.Provide(
		// Provides the ReadOnly INBs table.
		statedb.RWTable[tables.INB].ToTable,

		// Provides the object to observe node events.
		observers.NewNodes,
	),

	cell.Invoke(
		// Registers the privnet to INBs table reconciler.
		(*INBs).registerPrivateNetworksReconciler,

		// Registers the nodes to INBs table reconciler. Besides ClusterMesh
		// nodes, we also observe the local ones, to support the possible
		// use-case of a subset of nodes from the local cluster being INBs.
		(*INBs).registerNodesObserver,

		// Registers the health to INBs table reconciler.
		(*INBs).registerHealthObserver,
	),

	cell.DecorateAll(
		// Override the NodeManager, so that we can intercept the node events.
		// Ideally we'd just watch the nodes table, but that's not yet available,
		// so we need to be a bit more creative...
		// Related: cilium/cilium#41744
		overrideNodeManager,
	),
)

// INBs is a reconciler that handles the reconciliation of INB information,
// providing support for high availability (HA) and sharding of INBs.
// This component is responsible for automatically discovering the set of INB
// nodes matched by and available for each private network, reacting to and
// propagating health status changes, and promoting one of the healthy INBs
// as active for each network.
type INBs struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db       *statedb.DB
	networks statedb.Table[tables.PrivateNetwork]
	tbl      statedb.RWTable[tables.INB]

	nodes   *observers.Nodes
	checker health.Checker

	// pninit and noinit respectively track the initialization of the table from
	// private networks and nodes, so that we can break the health observer circular
	// dependency on initializers (as it adds itself an initializer).
	pninit, noinit chan struct{}

	// byCluster caches the node selectors for each network by cluster name.
	// This structure is not protected by a dedicated mutex as only accessed
	// inside a write transaction, which already ensures serialization.
	byCluster map[tables.ClusterName]map[tables.NetworkName]labels.Selector
}

func newINBs(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB       *statedb.DB
	Networks statedb.Table[tables.PrivateNetwork]
	Table    statedb.RWTable[tables.INB]

	Nodes   *observers.Nodes
	Checker health.Checker
}) *INBs {
	return &INBs{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,

		db:       in.DB,
		networks: in.Networks,
		tbl:      in.Table,

		nodes:   in.Nodes,
		checker: in.Checker,

		pninit: make(chan struct{}),
		noinit: make(chan struct{}),

		byCluster: make(map[tables.ClusterName]map[tables.NetworkName]labels.Selector),
	}
}

func (i *INBs) registerPrivateNetworksReconciler() {
	// We currently assume that an INB node plays that role for all locally-known
	// private networks. In other words, it cannot select other INBs for a specifc
	// private network, which means that we can save some work by not reconciling
	// the INBs table on the INBs themselves.
	if !i.cfg.Enabled || i.cfg.EnabledAsBridge() {
		return
	}

	wtx := i.db.WriteTxn(i.tbl)
	initialized := i.tbl.RegisterInitializer(wtx, "private-networks")
	wtx.Commit()

	// This job watches the upstream private networks table and populates the INBs table from that
	i.jg.Add(
		job.OneShot(
			"privnet-to-inbs",
			func(ctx context.Context, health cell.Health) error {
				health.OK("Starting")

				var initDone bool

				wtx := i.db.WriteTxn(i.networks)
				changeIter, _ := i.networks.Changes(wtx)
				wtx.Commit()

				for {
					var initWatch <-chan struct{}
					wtx := i.db.WriteTxn(i.tbl)
					changes, watch := changeIter.Next(wtx)

					for change := range changes {
						if change.Deleted {
							i.deleteINBsForNetwork(wtx, change.Object.Name)
						} else {
							i.upsertINBsForNetwork(wtx, change.Object)
						}
					}

					if !initDone {
						init, nw := i.networks.Initialized(wtx)

						switch {
						case !init:
							initWatch = nw
						default:
							initDone = true
							initialized(wtx)
							close(i.pninit)
						}
					}

					wtx.Commit()
					health.OK("Reconciliation completed")

					// Wait until there's new changes to consume
					select {
					case <-ctx.Done():
						return nil
					case <-watch:
					case <-initWatch:
					}
				}
			},
		),
	)
}

func (i *INBs) registerNodesObserver() {
	// We currently assume that an INB node plays that role for all locally-known
	// private networks. In other words, it cannot select other INBs for a specifc
	// private network, which means that we can save some work by not reconciling
	// the INBs table on the INBs themselves.
	if !i.cfg.Enabled || i.cfg.EnabledAsBridge() {
		return
	}

	wtx := i.db.WriteTxn(i.tbl)
	initialized := i.tbl.RegisterInitializer(wtx, "nodes")
	wtx.Commit()

	i.jg.Add(
		job.Observer(
			"nodes-to-inbs",
			func(ctx context.Context, buf observers.NodeEvents) error {
				wtx := i.db.WriteTxn(i.tbl)

				for _, ev := range buf {
					switch ev.EventKind {
					case resource.Upsert:
						i.upsertINBsForNode(wtx, ev.Object)
					case resource.Delete:
						i.deleteINBsForNode(wtx, ev.Object)
					case resource.Sync:
						initialized(wtx)
						close(i.noinit)
					}
				}

				wtx.Commit()
				return nil
			}, i.nodes,
		),
	)
}

func (i *INBs) registerHealthObserver(activeINBIndexFunc ActiveINBIndexFunc) {
	// We currently assume that an INB node plays that role for all locally-known
	// private networks. In other words, it cannot select other INBs for a specifc
	// private network, which means that we can save some work by not reconciling
	// the INBs table on the INBs themselves.
	if !i.cfg.Enabled || i.cfg.EnabledAsBridge() {
		return
	}

	wtx := i.db.WriteTxn(i.tbl)
	initialized := i.tbl.RegisterInitializer(wtx, "health-checker")
	wtx.Commit()

	heinit := make(chan struct{})
	i.jg.Add(
		job.Observer(
			"health-to-inbs",
			func(ctx context.Context, buf health.Events) error {
				wtx := i.db.WriteTxn(i.tbl)

				for _, ev := range buf {
					switch ev.EventKind {
					case health.EventKindUpsert:
						i.updateINBState(wtx, ev.Object)
					case health.EventKindSync:
						close(heinit)
					}
				}

				wtx.Commit()
				return nil
			}, i.checker,
		),

		job.OneShot(
			"health-initialized",
			func(ctx context.Context, health cell.Health) error {
				health.OK("Waiting for initialization")

				for _, init := range []<-chan struct{}{i.pninit, i.noinit} {
					select {
					case <-init:
					case <-ctx.Done():
						return nil
					}
				}

				health.OK("Initialized")
				i.checker.Synced()
				return nil
			},
		),

		job.OneShot(
			"active-reconciler",
			i.activeINBsReconciliationFunc(activeINBIndexFunc, heinit, initialized),
		),
	)
}

func (i *INBs) upsertINBsForNetwork(wtx statedb.WriteTxn, privnet tables.PrivateNetwork) {
	var (
		watermark  = i.tbl.Revision(wtx)
		maybeStale = sets.New[tables.ClusterName]()
	)

	// Iterate over all candidate clusters, and upsert new INBs as appropriate.
	for cluster, selector := range privnet.INBs.Selectors {
		byNetwork := i.byCluster[cluster]
		if byNetwork == nil {
			byNetwork = make(map[tables.NetworkName]labels.Selector)
			i.byCluster[cluster] = byNetwork
		}

		// Check whether the selector did actually change, to avoid doing unnecessary work.
		current, found := byNetwork[privnet.Name]
		if found {
			// Selectable (i.e., the second parameter) is guaranteed to be always
			// true, as [labels.Nothing] selectors are discarded.
			creqs, _ := current.Requirements()
			nreqs, _ := selector.Requirements()

			if slices.EqualFunc(creqs, nreqs, labels.Requirement.Equal) {
				continue
			}
		}

		byNetwork[privnet.Name] = selector

		// Given that the selector changed, there may be stale entries to be removed.
		maybeStale.Insert(cluster)

		// Upsert any node that may be now matched by the new selectors.
		for _, node := range i.nodes.List(cluster) {
			if node.ValidAndSelectedBy(selector) {
				inb := tables.INB{
					Network: privnet.Name,
					Node: tables.INBNode{
						Cluster: node.Cluster,
						Name:    node.Name,
						IP:      node.IP,
					},
				}

				i.checker.Register(inb.Node, inb.Network)
				i.tbl.Modify(wtx, inb, func(old, new tables.INB) tables.INB {
					// Preserve the previous state, in case the IP did not change.
					// The other fields are either fixed (i.e., part of the primary
					// key), or status related.
					if old.Node.IP == new.Node.IP {
						return old
					}
					return new
				})
			}
		}
	}

	// Iterate over all known clusters, and remove the stale entries if no longer
	// referenced by this private network.
	for cluster, byNetwork := range i.byCluster {
		if _, found := privnet.INBs.Selectors[cluster]; !found {
			// The given cluster is not a candidate for this network.
			if _, found := byNetwork[privnet.Name]; found {
				// The given cluster used to be a candidate for this network,
				// so we need to delete the possible stale entries.
				maybeStale.Insert(cluster)

				delete(byNetwork, privnet.Name)
				if len(byNetwork) == 0 {
					delete(i.byCluster, cluster)
				}
			}
		}
	}

	if maybeStale.Len() == 0 {
		return
	}

	// There may be stale INB entries to be removed.
	for inb, rev := range i.tbl.Prefix(wtx, tables.INBsByNetwork(privnet.Name)) {
		// The object revision is greater than the watermark if it has just been
		// upserted as part of this function.
		if maybeStale.Has(inb.Node.Cluster) && rev <= watermark {
			i.checker.Unregister(inb.Node, inb.Network)
			i.tbl.Delete(wtx, inb)
		}
	}
}

func (i *INBs) deleteINBsForNetwork(wtx statedb.WriteTxn, privnet tables.NetworkName) {
	for cluster, byNetwork := range i.byCluster {
		delete(byNetwork, privnet)
		if len(byNetwork) == 0 {
			delete(i.byCluster, cluster)
		}
	}

	for inb := range i.tbl.Prefix(wtx, tables.INBsByNetwork(privnet)) {
		i.checker.Unregister(inb.Node, inb.Network)
		i.tbl.Delete(wtx, inb)
	}
}

func (i *INBs) upsertINBsForNode(wtx statedb.WriteTxn, node *types.Node) {
	var watermark = i.tbl.Revision(wtx)

	// Iterate over all private networks that selected this cluster, and verify
	// whether the node selector does match.
	for network, selector := range i.byCluster[node.Cluster] {
		if node.ValidAndSelectedBy(selector) {
			inb := tables.INB{
				Network: network,
				Node: tables.INBNode{
					Cluster: node.Cluster,
					Name:    node.Name,
					IP:      node.IP,
				},
			}

			i.checker.Register(inb.Node, inb.Network)
			i.tbl.Modify(wtx, inb, func(old, new tables.INB) tables.INB {
				// Preserve the previous state, in case the IP did not change.
				// The other fields are either fixed (i.e., part of the primary
				// key), or status related.
				if old.Node.IP == new.Node.IP {
					return old
				}
				return new
			})
		}
	}

	// Delete any possible stale entries, e.g., in case the node labels changed.
	for inb, rev := range i.tbl.Prefix(wtx, tables.INBsByNode(node.Cluster, node.Name)) {
		// The object revision is greater than the watermark if it has just been
		// upserted as part of this function.
		if rev <= watermark {
			i.checker.Unregister(inb.Node, inb.Network)
			i.tbl.Delete(wtx, inb)
		}
	}
}

func (i *INBs) deleteINBsForNode(wtx statedb.WriteTxn, node *types.Node) {
	for inb := range i.tbl.Prefix(wtx, tables.INBsByNode(node.Cluster, node.Name)) {
		i.checker.Unregister(inb.Node, inb.Network)
		i.tbl.Delete(wtx, inb)
	}
}

func (i *INBs) updateINBState(wtx statedb.WriteTxn, ev *health.Event) {
	inb, _, found := i.tbl.Get(wtx, tables.INBByNodeAndNetwork(ev.Node.Cluster, ev.Node.Name, ev.Network))
	if !found || inb.Node.IP != ev.Node.IP {
		// The event is stale, as the entry no longer exists, or the node IP changed.
		return
	}

	if !inb.Update(ev.State) {
		// The state did not change, no reason to perform an update.
		return
	}

	i.tbl.Insert(wtx, inb)
}

// ActiveINBIndexFunc returns the index of the candidate INB selected as active.
type ActiveINBIndexFunc = func(candidates []tables.INB) int

func (i *INBs) activeINBsReconciliationFunc(activeIndexFunc ActiveINBIndexFunc, wait <-chan struct{}, initialized func(statedb.WriteTxn)) job.OneShotFunc {
	return func(ctx context.Context, health cell.Health) error {
		health.OK("Waiting for initialization")
		select {
		case <-wait:
		case <-ctx.Done():
			return nil
		}
		health.OK("Initialized")

		for {
			var (
				promotedCount int

				wtx      = i.db.WriteTxn(i.tbl)
				watchset = statedb.NewWatchSet()
			)

			privnets, watch := i.networks.AllWatch(wtx)
			watchset.Add(watch)

			for privnet := range privnets {
				_, _, watch, found := i.tbl.GetWatch(wtx, tables.INBsByNetworkAndRole(privnet.Name, tables.INBRoleActive))

				// There's already an active INB for this network, so nothing to do there.
				// Add the watch channel to the set, so that we wake up when its state changed.
				if found {
					watchset.Add(watch)
					continue
				}

				iter, watch := i.tbl.ListWatch(wtx, tables.INBsByNetworkAndRole(privnet.Name, tables.INBRoleStandby))
				standby := statedb.Collect(iter)

				// No standby candidate found. Add the watch channel to the set, so that we wake
				// up again once one standby candidate appears.
				if len(standby) == 0 {
					watchset.Add(watch)
					continue
				}

				// Pick one of the standby INBs, and promote it to active.
				idx := activeIndexFunc(standby)

				promoted := standby[idx]
				if err := promoted.Activate(); err != nil {
					i.log.Error("BUG: failed promoting standby INB to active",
						logfields.Error, err,
						logfields.Network, privnet.Name,
						logfields.Node, promoted.Node,
						logfields.State, promoted.Health,
					)
					continue
				}
				_, _, watch, _ = i.tbl.InsertWatch(wtx, promoted)

				// We want to wake-up if the currently active INB is no longer so.
				watchset.Add(watch)

				i.checker.Activate(promoted.Node, promoted.Network)
				promotedCount++
			}

			if initialized != nil {
				initialized(wtx)
				initialized = nil
				wtx.Commit()
			} else if promotedCount > 0 {
				wtx.Commit()
			} else {
				// We didn't update anything, so no need to commit.
				wtx.Abort()
			}

			if promotedCount > 0 {
				health.OK(fmt.Sprintf("Reconciliation completed, promoted INB for %d networks", promotedCount))
			}

			_, err := watchset.Wait(ctx, SettleTime)
			if err != nil {
				return nil
			}
		}
	}
}

func (i *INBs) newDefaultActiveIndexFunc() ActiveINBIndexFunc {
	return func(candidates []tables.INB) int {
		return rand.IntN(len(candidates))
	}
}

// overrideNodeManager is to be used via [cell.DecorateAll] to override the [NodeManager].
// It is not a method of [*INBs] as it would require to use [Provide] instead of [ProvidePrivate].
func overrideNodeManager(cfg config.Config, nm nomgr.NodeManager, obs *observers.Nodes) nomgr.NodeManager {
	// Keep the upstream NodeManager if we are not going to observe the events.
	if !cfg.Enabled || cfg.EnabledAsBridge() {
		return nm
	}

	return obs
}
