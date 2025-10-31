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
	"iter"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	notypes "github.com/cilium/cilium/pkg/node/types"
)

var MapEntriesCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite MapEntries table.
		tables.NewMapEntriesTable,

		// Provides the reconciler handling private network map entries.
		newMapEntries,
	),

	cell.Provide(
		// Provides the ReadOnly MapEntries table.
		statedb.RWTable[*tables.MapEntry].ToTable,
	),

	cell.Invoke(
		// Registers the reconciler
		(*MapEntries).registerReconciler,
	),
)

// MapEntries is a reconciler which watches the private networks,
// endpoints and routes tables and populates the map entries table.
type MapEntries struct {
	log *slog.Logger
	jg  job.Group

	cfg   config.Config
	local tables.INBNode

	db        *statedb.DB
	networks  statedb.Table[tables.PrivateNetwork]
	endpoints statedb.Table[tables.Endpoint]
	routes    statedb.Table[tables.Route]
	inbs      statedb.Table[tables.INB]
	actnets   statedb.Table[tables.ActiveNetwork]
	tbl       statedb.RWTable[*tables.MapEntry]

	// knownNetworks is not protected by a mutex as access is serialized by write transactions.
	knownNetworks map[tables.NetworkName]tables.SlimPrivateNetwork

	// inbWatchesTracker tracks the associations between each watch channel and corresponding network
	// names. It is not protected by a mutex as access is serialized by write transactions.
	inbWatchesTracker watchesTracker
}

func newMapEntries(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config      config.Config
	ClusterInfo cmtypes.ClusterInfo

	DB        *statedb.DB
	Networks  statedb.Table[tables.PrivateNetwork]
	Endpoints statedb.Table[tables.Endpoint]
	Routes    statedb.Table[tables.Route]
	INBs      statedb.Table[tables.INB]
	ActNets   statedb.Table[tables.ActiveNetwork]
	Table     statedb.RWTable[*tables.MapEntry]
}) (*MapEntries, error) {
	reconciler := &MapEntries{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,
		local: tables.INBNode{
			Cluster: tables.ClusterName(in.ClusterInfo.Name),
			Name:    tables.NodeName(notypes.GetName()),
		},

		db:        in.DB,
		networks:  in.Networks,
		endpoints: in.Endpoints,
		routes:    in.Routes,
		inbs:      in.INBs,
		actnets:   in.ActNets,
		tbl:       in.Table,

		knownNetworks:     make(map[tables.NetworkName]tables.SlimPrivateNetwork),
		inbWatchesTracker: newWatchesTracker(),
	}

	return reconciler, nil
}

func (m *MapEntries) registerReconciler() {
	if !m.cfg.Enabled {
		return
	}

	wtx := m.db.WriteTxn(m.tbl)
	initialized := m.tbl.RegisterInitializer(wtx, "mapentries-initialized")
	wtx.Commit()

	// This job watches the upstream endpoints, private networks and routes table
	// and pushes endpoint and routes entries into the downstream map entries table
	m.jg.Add(job.OneShot("populate-mapentries-table", func(ctx context.Context, _ cell.Health) error {
		var (
			initDone bool
			watchset = statedb.NewWatchSet()
			closed   []<-chan struct{}
			err      error
		)

		// getActiveINB returns the active INB for the given network (if any),
		// and registers the corresponding watch channel into the trackers.
		getActiveINB := func(txn statedb.ReadTxn, network tables.NetworkName) tables.INBNode {
			inb, _, watch, _ := m.inbs.GetWatch(txn, tables.INBsByNetworkAndRole(network, tables.INBRoleActive))
			m.inbWatchesTracker.Register(watch, network)
			watchset.Add(watch)
			return inb.Node
		}

		txn := m.db.WriteTxn(m.networks, m.endpoints, m.routes, m.actnets)
		epsChangeIter, _ := m.endpoints.Changes(txn)
		netChangeIter, _ := m.networks.Changes(txn)
		rtsChangeIter, _ := m.routes.Changes(txn)
		actChangeIter, _ := m.actnets.Changes(txn)
		txn.Commit()

		for {
			txn := m.db.WriteTxn(m.tbl)
			netChanges, netWatch := netChangeIter.Next(txn)
			epsChanges, epsWatch := epsChangeIter.Next(txn)
			rtsChanges, rtsWatch := rtsChangeIter.Next(txn)
			actChanges, actWatch := actChangeIter.Next(txn)
			watchset.Add(netWatch, epsWatch, rtsWatch, actWatch)

			// Handle network change events
			upsertedNetworks := make(sets.Set[tables.NetworkName])
			removedNetworks := make(sets.Set[tables.NetworkName])

			for netChange := range netChanges {
				m.log.Debug("Processing table event",
					logfields.Table, m.networks.Name(),
					logfields.Event, netChange,
				)

				network := netChange.Object.Name
				if netChange.Deleted {
					if err := m.deleteAllNetworkEntries(txn, network); err != nil {
						txn.Abort()
						return err
					}
					removedNetworks.Insert(network)
				} else {
					// We need to process all endpoints and routes both if this
					// is the first time that we see this network, and if something
					// in the network spec changed (e.g., INB, interface), to adapt
					// all entries accordingly. Still, let's try to be a bit smart
					// and skip updates that do not modify any relevant field.
					// The deletion of possible stale entries is deferred to the
					// processing of the corresponding endpoint/route deletion
					// events, which are not filtered out below.
					slim := netChange.Object.ToSlim(getActiveINB(txn, network))
					if !m.skipNetworkEvent(slim) {
						if err := m.upsertAllNetworkEntries(txn, slim); err != nil {
							txn.Abort()
							return err
						}
						upsertedNetworks.Insert(network)
					}
				}
			}

			// Handle changes of the active INBs.
			for network := range m.inbWatchesTracker.Iter(closed) {
				if upsertedNetworks.Has(network) {
					// We already processed this network.
					continue
				}

				slim, found := m.knownNetworks[network]
				if !found {
					// The network no longer exists, so nothing to do here.
					continue
				}

				slim.ActiveINB = getActiveINB(txn, network)
				if !m.skipNetworkEvent(slim) {
					if err := m.upsertAllNetworkEntries(txn, slim); err != nil {
						txn.Abort()
						return err
					}
					upsertedNetworks.Insert(network)
				}
			}

			// Handle route change events
			for rtChange := range rtsChanges {
				// Skip change event if it was already handled in {upsert,delete}AllNetworkEntries
				if skipChangeEvent(rtChange, rtChange.Object.Network, upsertedNetworks, removedNetworks) {
					continue
				}

				m.log.Debug("Processing table event",
					logfields.Table, m.routes.Name(),
					logfields.Event, rtChange,
				)

				if rtChange.Deleted {
					if err := m.deleteRoute(txn, rtChange.Object); err != nil {
						txn.Abort()
						return err
					}
				} else {
					if err := m.upsertRoute(txn, rtChange.Object); err != nil {
						txn.Abort()
						return err
					}
				}
			}

			// Handle endpoint change events
			for epChange := range epsChanges {
				// Skip change event if it was already handled in {upsert,delete}AllNetworkEntries
				epNetwork := tables.NetworkName(epChange.Object.Network.Name)
				if skipChangeEvent(epChange, epNetwork, upsertedNetworks, removedNetworks) {
					continue
				}

				m.log.Debug("Processing table event",
					logfields.Table, m.endpoints.Name(),
					logfields.Event, epChange,
				)

				// handleEndpointChange recomputes the active endpoint, and updates it
				// as appropriate, hence taking care of both upsertion and deletion.
				err := m.handleEndpointChange(txn, epChange.Object)
				if err != nil {
					txn.Abort()
					return err
				}
			}

			// Handle active networks change events
			for actChange := range actChanges {
				// Skip change event if the network has already been handled above.
				// Regardless of whether the network got added or removed, we are
				// guaranteed that all corresponding endpoints have already been
				// processed, and [L2Announce] has already been set correctly.
				network := actChange.Object.Network
				if upsertedNetworks.Has(network) || removedNetworks.Has(network) {
					continue
				}

				m.log.Debug("Processing table event",
					logfields.Table, m.actnets.Name(),
					logfields.Event, actChange,
				)

				query := tables.EndpointsByNetworkNode(network, actChange.Object.Node)
				for endpoint := range m.endpoints.List(txn, query) {
					// Process the endpoint again, to update [L2Announce] as appropriate.
					// We assume that it is unlikely that the given endpoint also changed
					// and got already processed in this reconciliation round. Hence, we
					// don't explicitly track them to avoid increasing complexity further,
					// as the performance benefits would be minimal.
					err := m.handleEndpointChange(txn, endpoint)
					if err != nil {
						txn.Abort()
						return err
					}
				}
			}

			// In order to be able to propagate initialization, we need to check if the upstream
			// tables have already been initialized
			if !initDone {
				netInit, nw := m.networks.Initialized(txn)
				epsInit, ew := m.endpoints.Initialized(txn)
				rtsInit, rw := m.routes.Initialized(txn)
				inbInit, iw := m.inbs.Initialized(txn)
				actInit, aw := m.actnets.Initialized(txn)

				switch {
				case !netInit:
					watchset.Add(nw)
				case !epsInit:
					watchset.Add(ew)
				case !rtsInit:
					watchset.Add(rw)
				case !inbInit:
					watchset.Add(iw)
				case !actInit:
					watchset.Add(aw)
				default:
					initDone = true
					initialized(txn)
				}
			}

			txn.Commit()

			closed, err = watchset.Wait(ctx, SettleTime)
			if err != nil {
				return nil
			}
		}
	}))
}

// handleEndpointChange deals with both added and deleted endpoints. It does this by
// determining the active endpoint for the given endpoints network IP. If there is no
// longer any active endpoint (e.g. because ep was deleted or changed to become inactive),
// the corresponding entry is deleted. On the other hand, if there is a (new) active
// endpoint, the new active endpoint is inserted.
func (m *MapEntries) handleEndpointChange(txn statedb.WriteTxn, ep tables.Endpoint) error {
	privNet, found := m.knownNetworks[tables.NetworkName(ep.Network.Name)]
	if !found {
		// We don't know anything yet about this private network
		return nil
	}

	// We do not short-circuit the processing of external endpoints advertised by
	// non-active INBs at this point, as it is technically possible to mutate the
	// node name and/or the external flag of the endpoint, which would lead to
	// incorrect entries in the mapentries table. Instead, let's go through the
	// normal processing, short-circuiting below if the desired entry matches the
	// one already currently present. This also avoids the need for a special
	// logic to handle the change of the active INB.

	// Try to find a new active endpoint for the given (net, netIP) pair
	activeEp := m.determineActiveEndpointForNetworkIP(txn, privNet, ep.Network.IP)

	// Check if there already is an existing entry in the table for the endpoint to be upserted
	current, _, found := m.tbl.Get(txn, tables.MapEntryByKey(ep.ToMapEntryKey()))

	// No desired active endpoint, ensure the entry is not present in the NAT table.
	if activeEp == nil {
		m.log.Debug("No active endpoint for event", logfields.Event, ep)
		if found {
			err := m.deleteEndpointEntry(txn, privNet, current)
			return err
		}
		return nil
	}

	// Skip any further logic if the to-be-upserted entry is already present
	desired := activeEp.ToMapEntry(privNet, m.cfg.EnabledAsBridge(), m.shouldL2Announce(txn, ep))
	if found && current.Equal(desired) {
		return nil
	}

	// Remove entries which share the PodIP with the new activeEP
	for conflictingEntry := range m.findConflictingNATEntriesForActiveEP(txn, *activeEp) {
		m.log.Warn("Found map entry with conflicting Pod-IP. Removing old entry.",
			logfields.New, desired,
			logfields.Old, conflictingEntry,
		)
		err := m.deleteEndpointEntry(txn, privNet, conflictingEntry)
		if err != nil {
			return err
		}

		// Note: The deletion of the conflicting entry above could potentially promote
		// another endpoint as the active one for the deleted Net-IP (which in turn
		// could cause conflicts, thus causing a cascade of updates).
		// We currently internationally do not perform a cascading updates here,
		// because it complicates the logic and conflicting Pod-IPs are likely going
		// to be very rare. This may be revisited if we see the above warning being
		// emitted often.
	}

	// Upsert map entry for active endpoint
	return m.insertEndpointEntry(txn, desired)
}

// determineActiveEndpointForNetworkIP checks the endpoint table to find the active endpoint for the given
// network IP. The active endpoint is the one with the most recent "activatedAt" timestamp, filtering out
// the ones advertised by non-active INBs.
func (m *MapEntries) determineActiveEndpointForNetworkIP(txn statedb.ReadTxn, network tables.SlimPrivateNetwork, networkIP netip.Addr) (active *tables.Endpoint) {
	for ep := range m.endpoints.List(txn, tables.EndpointsByNetworkIP(network.Name, networkIP)) {
		if ep.ActivatedAt.IsZero() {
			continue // skip inactive endpoints
		}

		if m.shouldSkipExternalEndpoint(ep, network) {
			continue // skip external endpoints advertised by non-active INBs.
		}

		if active == nil || ep.ActivatedAt.After(active.ActivatedAt) {
			active = &ep
		}
	}

	return active
}

// shouldSkipExternalEndpointSkip returns whether a given external endpoint should
// be skipped, that is if either this network has no active INB, or the endpoint
// is not advertised by the currently active INB. This function always returns
// false if the endpoint is not external, as well as for the external endpoints
// advertised by the local node.
func (m *MapEntries) shouldSkipExternalEndpoint(ep tables.Endpoint, privnet tables.SlimPrivateNetwork) bool {
	return ep.Flags.External &&
		(!privnet.ActiveINB.IP.IsValid() ||
			tables.ClusterName(ep.Source.Cluster) != privnet.ActiveINB.Cluster ||
			tables.NodeName(ep.NodeName) != privnet.ActiveINB.Name) &&
		(tables.ClusterName(ep.Source.Cluster) != m.local.Cluster ||
			tables.NodeName(ep.NodeName) != m.local.Name)
}

// shouldL2Announce returns whether the local node should announce the given endpoint
// on the egress facing interface. This happens on INB nodes only, if the node hosting
// the endpoint promoted us as active for that network.
func (m *MapEntries) shouldL2Announce(txn statedb.ReadTxn, ep tables.Endpoint) bool {
	if !m.cfg.EnabledAsBridge() || ep.Flags.External {
		return false
	}

	_, _, active := m.actnets.Get(txn, tables.ActiveNetworkByKey(
		tables.WorkloadNode{
			Cluster: tables.ClusterName(ep.Source.Cluster),
			Name:    tables.NodeName(ep.NodeName),
		}, tables.NetworkName(ep.Network.Name),
	))

	return active
}

// findConflictingNATEntriesForActiveEP checks the endpoint table to find all endpoints
// that share the same P-IP with the provided activeEP.
func (m *MapEntries) findConflictingNATEntriesForActiveEP(txn statedb.ReadTxn, activeEP tables.Endpoint) iter.Seq[*tables.MapEntry] {
	return func(yield func(*tables.MapEntry) bool) {
		conflictingEPsForPIP := m.endpoints.List(txn, tables.EndpointsByPIP(activeEP.IP))
		for conflictingEP := range conflictingEPsForPIP {
			if conflictingEP.Equal(activeEP) {
				continue // activeEP does not conflict with itself
			}

			// At this stage, we've found an endpoint entry with a conflicting PIP.
			// But only if the conflicting endpoint is active (i.e. it has a corresponding map table entry) do we
			// need to report the conflicting entry (i.e. have the caller remove it).
			conflictingEntry, _, found := m.tbl.Get(txn, tables.MapEntryByKey(conflictingEP.ToMapEntryKey()))
			if found {
				yield(conflictingEntry)
			}
		}
	}
}

// upsertAllNetworkEntries queries the upstream endpoints and routes tables and performs an
// upsert operation for each endpoint and route which belongs to the given network.
func (m *MapEntries) upsertAllNetworkEntries(txn statedb.WriteTxn, network tables.SlimPrivateNetwork) error {
	// Store the updated network information into the local cache.
	m.knownNetworks[network.Name] = network

	for ep := range m.endpoints.Prefix(txn, tables.EndpointsByNetwork(network.Name)) {
		err := m.handleEndpointChange(txn, ep)
		if err != nil {
			return err
		}
	}

	for rt := range m.routes.Prefix(txn, tables.RouteByNetwork(network.Name)) {
		err := m.upsertRoute(txn, rt)
		if err != nil {
			return err
		}
	}

	return nil
}

// deleteAllNetworkEntries deletes all map entries associated with the given network
func (m *MapEntries) deleteAllNetworkEntries(txn statedb.WriteTxn, privNetName tables.NetworkName) error {
	delete(m.knownNetworks, privNetName)
	for entry := range m.tbl.Prefix(txn, tables.MapEntriesByNetwork(privNetName)) {
		_, _, err := m.tbl.Delete(txn, entry)
		if err != nil {
			return err
		}
	}
	return nil
}

// skipNetworkUpdate determines if the two networks are identical from the MapEntries
// reconciler point of view, and the event can be skipped.
func (m *MapEntries) skipNetworkEvent(current tables.SlimPrivateNetwork) bool {
	// * The network name is the primary key, so it cannot change.
	// * We do not care about the INBs selectors.
	// * We only care about the interface ID, not its name or the reconciliation status.
	// * Route and subnet changes are already processed via the dedicated table.
	old, ok := m.knownNetworks[current.Name]
	return ok && old == current
}

// skipChangeEvent is called for endpoint and route change events to determine if
// it can safely be skipped to avoid duplicated work
func skipChangeEvent[T any](changeEvent statedb.Change[T], network tables.NetworkName,
	upsertedNetworks, removedNetworks sets.Set[tables.NetworkName]) bool {
	// If the network of this change event has just been removed, then we can skip
	// handling the change event:
	//  - If `change` is an upsert event, we can no longer add it to the
	//    downstream table without its network.
	//  - If `change` is a delete event, it was already removed from the
	//    downstream table, as we removed all entries in deleteAllNetworkEntries
	if removedNetworks.Has(network) {
		return true
	}

	// If the network of this change event has just been added, then we can skip
	// handling of upsert events (but not deletion events):
	//  - If `change` is an upsert event, then we already added it to the
	//    downstream table when in upsertAllNetworkEntries.
	//  - If `change` is a delete event, then we still need to process it,
	//    as it not handled in upsertAllNetworkEntries.
	if !changeEvent.Deleted && upsertedNetworks.Has(network) {
		return true
	}

	return false
}

// insertEndpointEntry inserts the provided active endpoint entry from the table. If the
// new endpoint entry shadows a route entry with the same target, then we remove that
// route entry.
func (m *MapEntries) insertEndpointEntry(txn statedb.WriteTxn, epEntry *tables.MapEntry) error {
	// Check if there is a route entry (static or DCN) with the same target and delete it
	for _, routeType := range []tables.MapEntryType{tables.MapEntryTypeDCNRoute, tables.MapEntryTypeStaticRoute} {
		routeEntry, _, found := m.tbl.Get(txn,
			tables.MapEntryByTypeNetworkCIDR(epEntry.Target.NetworkName, routeType, epEntry.Target.CIDR),
		)
		if found {
			// delete conflicting route entry
			m.log.Debug("Inserted endpoint entry shadows route entry",
				logfields.Endpoint, epEntry,
				logfields.Route, routeEntry,
			)
			_, _, err := m.tbl.Delete(txn, routeEntry)
			if err != nil {
				return err
			}
			break
		}
	}

	// Upsert the endpoint entry
	_, _, err := m.tbl.Insert(txn, epEntry)
	return err
}

// deleteEndpointEntry deletes the map table entry associated with an endpoint. It checks
// if the deleted endpoint entry shadowed a route entry with the same /32 or /128 target,
// and re-inserts that route entry if so.
func (m *MapEntries) deleteEndpointEntry(txn statedb.WriteTxn, privNet tables.SlimPrivateNetwork, epEntry *tables.MapEntry) error {
	// Delete the endpoint entry
	_, _, err := m.tbl.Delete(txn, epEntry)
	if err != nil {
		return err
	}

	// Check if there is a route entry with the same target
	route, _, found := m.routes.Get(txn, tables.RouteByNetworkAndDestination(privNet.Name, epEntry.Target.CIDR))
	if found {
		// Insert the route entry which is now un-shadowed
		routeEntry := route.ToMapEntry(privNet, m.cfg.EnabledAsBridge())
		if routeEntry == nil {
			return nil
		}
		m.log.Debug("Deleted endpoint entry un-shadows route entry",
			logfields.Endpoint, epEntry,
			logfields.Route, routeEntry,
		)
		_, _, err = m.tbl.Insert(txn, routeEntry)
		if err != nil {
			return err
		}
	}

	return nil
}

// upsertRoute inserts a new route entry into the table. If an endpoint entry with the same target
// already exists, we skip the insertion as the endpoint entry should take precedence.
func (m *MapEntries) upsertRoute(txn statedb.WriteTxn, route tables.Route) error {
	privNet, found := m.knownNetworks[route.Network]
	if !found {
		// We don't know anything yet about this private network
		return nil
	}

	// If this is a /32 or /128 route, then we do not want to upsert it if there is an
	// endpoint entry with the same key, as endpoints should take precedence
	if route.Destination.IsSingleIP() {
		ep, _, found := m.endpoints.Get(txn, tables.EndpointsByNetworkIP(route.Network, route.Destination.Addr()))
		if found {
			m.log.Debug("Inserted route entry is shadowed by endpoint entry",
				logfields.Endpoint, ep.Endpoint,
				logfields.Route, route,
			)
			return nil
		}
	}

	// Synthesize map entry from route spec and upsert it
	desired := route.ToMapEntry(privNet, m.cfg.EnabledAsBridge())

	// Skip insert if entry already exists (this ensures downstream consumers are not woken up unnecessarily)
	current, _, found := m.tbl.Get(txn,
		tables.MapEntryByTypeNetworkCIDR(route.Network, route.MapEntryType(), route.Destination),
	)

	if desired == nil {
		if found {
			// Delete the stale entry, most likely because there's no longer an
			// active INB for this network.
			_, _, err := m.tbl.Delete(txn, current)
			return err
		}
		return nil
	}

	if found && current.Equal(desired) {
		return nil
	}

	_, _, err := m.tbl.Insert(txn, desired)
	return err
}

// deleteRoute deletes a route entry from the table. As route entry have lower
// precedence than endpoint entries and the deletion query only considers route type entries,
// we do not have to check the endpoint table as we do in upsertRoute.
func (m *MapEntries) deleteRoute(txn statedb.WriteTxn, route tables.Route) error {
	entry, _, found := m.tbl.Get(txn,
		tables.MapEntryByTypeNetworkCIDR(route.Network, route.MapEntryType(), route.Destination),
	)
	if !found {
		return nil
	}

	_, _, err := m.tbl.Delete(txn, entry)
	return err
}

// watchesTracker tracks the associations between each watch channel and the
// corresponding network names. The same channel may be associated with multiple
// networks, e.g., in case no active INB is found.
type watchesTracker map[<-chan struct{}][]tables.NetworkName

func newWatchesTracker() watchesTracker {
	return make(watchesTracker)
}

// Register registers an watch channel to network name association.
func (tracker watchesTracker) Register(watch <-chan struct{}, network tables.NetworkName) {
	tracker[watch] = append(tracker[watch], network)
}

// Iter returns an iterator over all networks matching one of the closed channels.
func (tracker watchesTracker) Iter(closed []<-chan struct{}) iter.Seq[tables.NetworkName] {
	return func(yield func(tables.NetworkName) bool) {
		for _, watch := range closed {
			networks, found := tracker[watch]

			// The watch channel is not in our cache. This is expected if closed
			// includes other channels as well, such as initialization ones.
			if !found {
				continue
			}

			delete(tracker, watch)
			for _, network := range networks {
				if !yield(network) {
					return
				}
			}
		}
	}
}
