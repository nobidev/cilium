//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package rib

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/container/bitlpm"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// The RIB consists of a collection of CIDRTries per-VRF. The key is the IP
// prefix and the value is a "destination" which is a collection of routes that
// shares the same prefix. The reason we have a collection of routes is because
// we can have multiple routes for the same prefix but different owners (e.g.
// different BGP Instances). This structure allows route owners to update/delete
// their routes without conflicting with other owners. The RIB takes care of
// selecting the "best" route out of the multiple routes. Therefore, only the
// best route will be installed in the data plane.
type RIB struct {
	mutex      lock.RWMutex
	vrfTries   map[uint32]*bitlpm.CIDRTrie[*Destination]
	dataPlanes []DataPlane
}

// DataPlane is the interface for the data plane. The data plane is responsible
// for installing the best route in the kernel. The RIB will call the DataPlane
// when there is a change in the best route.
type DataPlane interface {
	// ProcessUpdate processes the RIB update. The given update is the
	// result of a best path selection and contains the old and new best
	// paths.
	ProcessUpdate(u *RIBUpdate)

	// ForEach iterates over all routes from the data plane. This is used
	// by RIB to initialize the RIB with the routes that are already
	// installed in the data plane.
	ForEach(cb func(uint32, *Route))
}

// DataPlaneIn is a shorthand for request DataPlanes
type DataPlaneIn struct {
	cell.In

	DataPlanes []DataPlane `group:"rib-dataplane"`
}

// DataPlaneOut is a shorthand for providing DataPlanes
type DataPlaneOut struct {
	cell.Out

	DataPlane DataPlane `group:"rib-dataplane"`
}

// nopDataPlane is a no-op implementation of the DataPlane interface. It is
// used when there's no data plane provided.
type nopDataPlane struct{}

func (nopDataPlane) ProcessUpdate(_ *RIBUpdate) {}

func (nopDataPlane) ForEach(_ func(uint32, *Route)) {}

func newNopDataPlane() DataPlane {
	return &nopDataPlane{}
}

// RIBUpdate is the update for the RIB
type RIBUpdate struct {
	VRFID   uint32
	OldBest *Route
	NewBest *Route
}

type in struct {
	cell.In

	DataPlanes []DataPlane `group:"rib-dataplane"`
}

func New(in in) *RIB {
	activeDataPlanes := []DataPlane{}
	if len(in.DataPlanes) == 0 {
		// Provide a no-op data plane if none is provided. Otherwise,
		// calling the data plane will panic.
		activeDataPlanes = append(activeDataPlanes, &nopDataPlane{})
	} else {
		// Filter out nil data planes
		for _, dp := range in.DataPlanes {
			if dp == nil {
				continue
			}
			activeDataPlanes = append(activeDataPlanes, dp)
		}
	}
	return &RIB{
		vrfTries:   make(map[uint32]*bitlpm.CIDRTrie[*Destination]),
		dataPlanes: activeDataPlanes,
	}
}

// UpsertRoute inserts or updates a route in the RIB. If the route already
// exists, it updates the route. The route is considered the same if the
// isSameRoute function returns true. Please see the comment for the
// isSameRoute function for more details about the criteria. If the route
// doesn't exist, it creates a new route.
func (r *RIB) UpsertRoute(vrfID uint32, newRoute Route) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Find the trie for the VRF. If it doesn't exist, create a new one.
	trie, found := r.vrfTries[vrfID]
	if !found {
		trie = bitlpm.NewCIDRTrie[*Destination]()
		r.vrfTries[vrfID] = trie
	}

	// Find an existing destination for the prefix. If it doesn't exist,
	// create a new one.
	dest, found := trie.ExactLookup(newRoute.Prefix)
	if !found {
		dest = &Destination{routes: []*Route{}}
		trie.Upsert(newRoute.Prefix, dest)
	}

	// Find an existing route. If it exists, update it. If it doesn't, add
	// it.
	updated := false
	for i, route := range dest.routes {
		if r.isSameRoute(route, &newRoute) {
			dest.routes[i] = &newRoute
			updated = true
			break
		}
	}
	if !updated {
		dest.routes = append(dest.routes, &newRoute)
	}

	newBest, changed := r.selectBestPath(dest)
	if changed {
		update := &RIBUpdate{
			VRFID:   vrfID,
			OldBest: dest.best,
			NewBest: newBest,
		}
		dest.best = newBest
		for _, dp := range r.dataPlanes {
			dp.ProcessUpdate(update)
		}
	}
}

// DeleteRoute deletes a route from the RIB. If the route doesn't exist,
// it does nothing. The route is considered the same if the isSameRoute
// function returns true. Please see the comment for the isSameRoute
// function for more details about the criteria.
func (r *RIB) DeleteRoute(vrfID uint32, route Route) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.deleteRoute(vrfID, route)
}

func (r *RIB) deleteRoute(vrfID uint32, route Route) {
	trie, found := r.vrfTries[vrfID]
	if !found {
		return
	}

	dest, found := trie.ExactLookup(route.Prefix)
	if !found {
		return
	}

	for i, rt := range dest.routes {
		if r.isSameRoute(rt, &route) {
			dest.routes = append(dest.routes[:i], dest.routes[i+1:]...)
			break
		}
	}

	if len(dest.routes) == 0 {
		// Delete destination from trie if there are no routes left.
		trie.Delete(route.Prefix)

		// Delete trie for this VRF if there are no destinations left.
		if trie.Len() == 0 {
			delete(r.vrfTries, vrfID)
		}
	}

	newBest, changed := r.selectBestPath(dest)
	if changed {
		update := &RIBUpdate{
			VRFID:   vrfID,
			OldBest: dest.best,
			NewBest: newBest,
		}
		dest.best = newBest
		for _, dp := range r.dataPlanes {
			dp.ProcessUpdate(update)
		}
	}
}

// ListRoutes returns all the routes for a given owner. The returned routes are
// trie of Routes indexed by the VRF ID.
func (r *RIB) ListRoutes(owner string) map[uint32]*bitlpm.CIDRTrie[*Route] {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.listRoutes(owner)
}

func (r *RIB) listRoutes(owner string) map[uint32]*bitlpm.CIDRTrie[*Route] {
	vrfRoutes := map[uint32]*bitlpm.CIDRTrie[*Route]{}
	for vrfID, trie := range r.vrfTries {
		routes := bitlpm.NewCIDRTrie[*Route]()
		trie.ForEach(func(prefix netip.Prefix, dest *Destination) bool {
			for _, route := range dest.routes {
				if route.Owner == owner {
					routes.Upsert(route.Prefix, route)
				}
			}
			return true
		})
		if routes.Len() > 0 {
			vrfRoutes[vrfID] = routes
		}
	}
	return vrfRoutes
}

func (r *RIB) forEach(cb func(uint32, netip.Prefix, *Destination) bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	vrfIDs := make([]uint32, 0, len(r.vrfTries))
	for vrfID := range r.vrfTries {
		vrfIDs = append(vrfIDs, vrfID)
	}
	slices.Sort(vrfIDs)

	for _, vrfID := range vrfIDs {
		r.vrfTries[vrfID].ForEach(func(prefix netip.Prefix, dest *Destination) bool {
			return cb(vrfID, prefix, dest)
		})
	}
}

// DeleteRoutesByOwner deletes all the routes for a given owner
func (r *RIB) DeleteRoutesByOwner(owner string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// It is not safe to delete node from trie while iterating over it, so
	// we first collect all routes to delete and then delete them.
	vrfRoutes := r.listRoutes(owner)
	for vrfID, trie := range vrfRoutes {
		trie.ForEach(func(prefix netip.Prefix, route *Route) bool {
			r.deleteRoute(vrfID, *route)
			return true
		})
	}
}

// ListBestRoutes returns a map of VRF IDs to CIDRTrie of best routes
func (r *RIB) ListBestRoutes() map[uint32]*bitlpm.CIDRTrie[*Route] {
	bestRoutes := make(map[uint32]*bitlpm.CIDRTrie[*Route])

	r.forEach(func(vrfID uint32, prefix netip.Prefix, dest *Destination) bool {
		if dest.best != nil {
			if _, ok := bestRoutes[vrfID]; !ok {
				bestRoutes[vrfID] = bitlpm.NewCIDRTrie[*Route]()
			}
			bestRoutes[vrfID].Upsert(prefix, dest.best)
		}
		return true
	})

	return bestRoutes
}

// Best path selection algorithm. First, it compares the Admin Distance of the
// Protocol. If the Admin Distance is the same, it compares the alphebetical
// order of the Owner (this should break ties because we cannot have two routes
// with the same prefix and the same owner).
func (r *RIB) selectBestPath(dest *Destination) (*Route, bool) {
	var best *Route
	for _, rt := range dest.routes {
		if best == nil {
			best = rt
		} else if rt.Protocol.AdminDistance() < best.Protocol.AdminDistance() {
			best = rt
		} else if rt.Protocol.AdminDistance() == best.Protocol.AdminDistance() && strings.Compare(rt.Owner, best.Owner) < 0 {
			best = rt
		}
	}
	return best, !best.Equal(dest.best)
}

// isSameRoute reports whether given two routes are the "same" from the RIB's
// perspective.
func (r *RIB) isSameRoute(a, b *Route) bool {
	// Currently, the route is considered the "same" if the owner is the
	// same. In the future, we may want to add more criteria to support
	// more complex use cases.
	return a.Owner == b.Owner
}

// Destination is a container of routes that share the same VRF + prefix
type Destination struct {
	best   *Route
	routes []*Route
}

// Route represents a single route to a destination
type Route struct {
	// Prefix is the destination prefix for the route
	Prefix netip.Prefix

	// Owner is the owner of the route. This value can be used to
	// differentiate between routes that share the same prefix but are
	// owned by different entities (e.g. different BGP instances). In the
	// typical RIB implementation, Protocol == Owner, but in our case, we
	// may have multiple instances for the same protocol (e.g. multiple BGP
	// instances). That's why we need to distinguish between the two.
	Owner string

	// Protocol is the protocol that originated the route. This value is used
	// to determine the administrative distance of the route. The RIB uses
	// the administrative distance to select the best route out of multiple
	// routes that share the same prefix.
	Protocol Protocol

	// NextHop is the next hop for the route. This value is primarily used
	// by the data plane to install the route. The RIB doesn't use this
	// value for anything at this point. Once we implement the proper
	// nexthop tracking and reachability checking, the RIB will use this.
	NextHop NextHop
}

func (r0 *Route) Equal(r1 *Route) bool {
	if r0 == nil || r1 == nil {
		return false
	}
	if r0.Prefix != r1.Prefix {
		return false
	}
	if r0.Owner != r1.Owner {
		return false
	}
	if r0.Protocol != r1.Protocol {
		return false
	}
	return r0.NextHop.Equal(r1.NextHop)
}

// VRFRoute is a pair of VRF ID and Route
type VRFRoute struct {
	VRFID uint32
	Route Route
}

const (
	// OwnerUnknown is a special owner value that indicates that the owner
	// is unknown. This is mainly used for routes that are restored from
	// the data plane at startup and we don't know the owner of the route.
	OwnerUnknown = "unknown"
)

type Protocol uint8

const (
	ProtocolUnknown Protocol = iota
	ProtocolIBGP
	ProtocolEBGP
	ProtocolKubernetes
)

func (p Protocol) String() string {
	switch p {
	case ProtocolIBGP:
		return "iBGP"
	case ProtocolEBGP:
		return "eBGP"
	case ProtocolKubernetes:
		return "Kubernetes"
	default:
		return "unknown"
	}
}

// These AD values are taken from the FRR's (Zebra's) implementation.
// https://docs.frrouting.org/en/latest/zebra.html#administrative-distance
func (p Protocol) AdminDistance() uint8 {
	switch p {
	case ProtocolIBGP:
		return 200
	case ProtocolEBGP:
		return 20
	case ProtocolKubernetes:
		// We treat Kubernetes like a static route. FRR uses 1 for
		// static routes, but we use 10 to leave some room for future
		// protocols.
		return 10
	default:
		return 255
	}
}

// NextHop is the next hop for a route. This is an interface that can be
// implemented by different types of next hops (e.g. device, IP, tunnel,
// blackhole, etc). Don't implement a new type of next hop outside of this
// package. The RIB may want to use it for next hop tracking in the future, so
// the RIB must be aware of all NextHop implementation. This unexported
// isNextHop method is a safe guard for that.
type NextHop interface {
	isNextHop()

	// String returns a string representation of the nexthop. This will be
	// used to display nexthop in the Hive Script. The string must be
	// started with the type of the next hop and followed by the
	// type-specific parameters. It must be a single line and short enough
	// to fit in a terminal window.
	String() string

	// Equal returns true if the two nexthops are equal
	Equal(NextHop) bool
}

type HEncaps struct {
	Segments []types.SID
}

func (*HEncaps) isNextHop() {}

func (n0 *HEncaps) Equal(_n1 NextHop) bool {
	if n0 == nil || _n1 == nil {
		return false
	}
	n1, ok := _n1.(*HEncaps)
	if !ok {
		return false
	}
	if len(n0.Segments) != len(n1.Segments) {
		return false
	}
	for i, s := range n0.Segments {
		if s != n1.Segments[i] {
			return false
		}
	}
	return true
}

func (s *HEncaps) String() string {
	segments := make([]string, len(s.Segments))
	for i, s := range s.Segments {
		segments[i] = s.String()
	}
	return fmt.Sprintf("H.Encaps %v", segments)
}

type EndDT4 struct {
	VRFID uint32
}

func (*EndDT4) isNextHop() {}

func (n0 *EndDT4) Equal(_n1 NextHop) bool {
	if n0 == nil || _n1 == nil {
		return false
	}
	n1, ok := _n1.(*EndDT4)
	if !ok {
		return false
	}
	return n0.VRFID == n1.VRFID
}

func (s *EndDT4) String() string {
	return fmt.Sprintf("End.DT4 vrf %d", s.VRFID)
}

type VXLANEncap struct {
	VNI         vni.VNI
	VTEPIP      netip.Addr
	InnerDstMAC net.HardwareAddr
}

func (*VXLANEncap) isNextHop() {}

func (n0 *VXLANEncap) Equal(_n1 NextHop) bool {
	if n0 == nil || _n1 == nil {
		return false
	}
	n1, ok := _n1.(*VXLANEncap)
	if !ok {
		return false
	}
	return n0.VNI == n1.VNI && n0.VTEPIP == n1.VTEPIP && bytes.Equal(n0.InnerDstMAC, n1.InnerDstMAC)
}

func (s *VXLANEncap) String() string {
	return fmt.Sprintf("VXLANEncap vni %d vtep %s inner-dst-mac %s", s.VNI, s.VTEPIP, s.InnerDstMAC)
}

// This type is defined for making GC trigger channel injectable in Hive. This
// is for making testing easier. When the testing/synctest is GA, we may want
// to remove this type and call time.After directly within scheduleInitialGC.
type gcChFn func() <-chan time.Time

// restoreRoutes is called from the Start hook before any other route owners
// start to write to the RIB. It first fetches all routes from the data planes.
// This will be done with the blocking call so that we can guarantee that the
// RIB is filled before any route owner starts writing to it.
//
// The routes read from data planes will have unknown owner and unknown
// protocol (max AD), so it will always lose the best path selection. The route
// owners will then write their routes to the RIB over the time, which will be
// selected as the best paths.
//
// Then after a given timeout, the garbage collection job will deletes all
// routes with unknown owners. This leaves the "active" routes written by the
// route owners, but removes all the "stale" routes from the data plane.
//
// This approach is not optimal. It has a risk that if the owners are not fully
// synced to the RIB before the garbage collection job runs, it may make the
// traffic disruption. If we could wait for all the owners to sync their routes
// to the RIB, we could avoid this timeout-based approach. However, the
// complexity here is the route owners are dynamic (e.g. BGP Instances are
// configurable by CRD, certain owners may have configuration flags to turn
// them on and off), so it's not trivial to wait for "all" of them. That's why
// we ended up with this simpler approach.
//
// Inspired by the Zebra's graceful-restart feature (-K option).
// https://docs.frrouting.org/en/latest/zebra.html#cmdoption-zebra-K
func scheduleInitialGC(lc cell.Lifecycle, jg job.Group, r *RIB, fn gcChFn) {
	lc.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			restoreRoutes(r)
			return nil
		},
	})

	// Make sure the count down starts here.
	ch := fn()

	jg.Add(job.OneShot("initial-gc", func(ctx context.Context, health cell.Health) error {
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
		r.DeleteRoutesByOwner(OwnerUnknown)
		return nil
	}))
}

func restoreRoutes(r *RIB) {
	for _, dp := range r.dataPlanes {
		// r.UpsertRoute may call dataplane.ProcessUpdate. Calling
		// dataPlane.ProcessUpdate while iterating over the trie is not safe,
		// so we need to collect all routes first and then call UpsertRoute for
		// each of them.
		routes := []RIBUpdate{}

		dp.ForEach(func(vrfID uint32, route *Route) {
			route.Owner = OwnerUnknown
			route.Protocol = ProtocolUnknown
			routes = append(routes, RIBUpdate{
				VRFID:   vrfID,
				NewBest: route,
			})
		})

		for _, update := range routes {
			r.UpsertRoute(update.VRFID, *update.NewBest)
		}
	}
}
