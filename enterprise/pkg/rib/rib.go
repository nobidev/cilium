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
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/container/bitlpm"
	"github.com/cilium/cilium/pkg/lock"
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
	mutex     lock.RWMutex
	vrfTries  map[uint32]*bitlpm.CIDRTrie[*Destination]
	dataPlane DataPlane
}

// DataPlane is the interface for the data plane. The data plane is responsible
// for installing the best route in the kernel. The RIB will call the DataPlane
// when there is a change in the best route.
type DataPlane interface {
	// ProcessUpdate processes the RIB update. The given update is the
	// result of a best path selection and contains the old and new best
	// paths.
	ProcessUpdate(u *RIBUpdate)
}

// RIBUpdate is the update for the RIB
type RIBUpdate struct {
	VRFID   uint32
	OldBest *Route
	NewBest *Route
}

type in struct {
	cell.In

	DataPlane DataPlane
}

func New(in in) *RIB {
	return &RIB{
		vrfTries:  make(map[uint32]*bitlpm.CIDRTrie[*Destination]),
		dataPlane: in.DataPlane,
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
		r.dataPlane.ProcessUpdate(update)
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
		r.dataPlane.ProcessUpdate(update)
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

func (r *RIB) ForEach(cb func(uint32, netip.Prefix, *Destination) bool) {
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
		} else if strings.Compare(rt.Owner, best.Owner) < 0 {
			best = rt
		}
	}
	return best, best != dest.best
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

type Protocol uint8

const (
	ProtocolUnknown Protocol = iota
	ProtocolIBGP
	ProtocolEBGP
)

func (p Protocol) String() string {
	switch p {
	case ProtocolIBGP:
		return "iBGP"
	case ProtocolEBGP:
		return "eBGP"
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
}

type HEncaps struct {
	Segments []types.SID
}

func (*HEncaps) isNextHop() {}

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

func (s *EndDT4) String() string {
	return fmt.Sprintf("End.DT4 vrf %d", s.VRFID)
}
