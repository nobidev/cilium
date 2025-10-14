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
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

type testNextHop struct {
	differentiator int
}

func (m *testNextHop) isNextHop() {}

func (m *testNextHop) String() string {
	return "test"
}

func (m0 *testNextHop) Equal(_m1 NextHop) bool {
	if m0 == nil || _m1 == nil {
		return false
	}
	m1, ok := _m1.(*testNextHop)
	if !ok {
		return false
	}
	return m0.differentiator == m1.differentiator
}

type vrfRoute struct {
	vrfID uint32
	route Route
}

type testDataPlane struct {
	mu              lock.RWMutex
	initialRoutes   []*vrfRoute
	receivedUpdates []*RIBUpdate
}

func (m *testDataPlane) ProcessUpdate(u *RIBUpdate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.receivedUpdates = append(m.receivedUpdates, u)
}

func (m *testDataPlane) ForEach(cb func(uint32, *Route)) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, vrfRoute := range m.initialRoutes {
		cb(vrfRoute.vrfID, &vrfRoute.route)
	}
}

func (m *testDataPlane) Clear() {
	m.receivedUpdates = nil
}

func TestRIB_UpsertRoute(t *testing.T) {
	t.Run("Same prefix with different VRF", func(t *testing.T) {
		rib := New(in{DataPlane: &testDataPlane{}})

		route := &Route{
			Prefix:   netip.MustParsePrefix("192.168.1.0/24"),
			Owner:    "owner0",
			Protocol: ProtocolEBGP,
			NextHop:  &testNextHop{},
		}

		rib.UpsertRoute(1, *route)
		rib.UpsertRoute(2, *route)

		routes := rib.ListRoutes("owner0")[1]
		_, found := routes.ExactLookup(route.Prefix)
		require.Equal(t, uint(1), routes.Len())
		require.True(t, found, "Route not found in VRF 1")

		routes = rib.ListRoutes("owner0")[2]
		_, found = routes.ExactLookup(route.Prefix)
		require.Equal(t, uint(1), routes.Len())
		require.True(t, found, "Route not found in VRF 2")
	})
	t.Run("Same VRF and prefix with same owner", func(t *testing.T) {
		rib := New(in{DataPlane: &testDataPlane{}})

		route := &Route{
			Prefix:   netip.MustParsePrefix("192.168.1.0/24"),
			Owner:    "owner0",
			Protocol: ProtocolEBGP,
			NextHop:  &testNextHop{},
		}

		// These upserts should not duplicate the route
		rib.UpsertRoute(1, *route)
		rib.UpsertRoute(1, *route)

		routes := rib.ListRoutes("owner0")[1]
		require.Equal(t, uint(1), routes.Len())
	})
	t.Run("Same VRF and prefix with different owner", func(t *testing.T) {
		rib := New(in{DataPlane: &testDataPlane{}})

		route0 := &Route{
			Prefix:   netip.MustParsePrefix("192.168.1.0/24"),
			Owner:    "owner0",
			Protocol: ProtocolEBGP,
			NextHop:  &testNextHop{},
		}

		route1 := &Route{
			Prefix:   netip.MustParsePrefix("192.168.1.0/24"),
			Owner:    "owner1",
			Protocol: ProtocolEBGP,
			NextHop:  &testNextHop{},
		}

		// These upserts should end up with two routes in the same destination
		rib.UpsertRoute(1, *route0)
		rib.UpsertRoute(1, *route1)

		routes := rib.ListRoutes("owner0")[1]
		require.Equal(t, uint(1), routes.Len())

		routes = rib.ListRoutes("owner1")[1]
		require.Equal(t, uint(1), routes.Len())
	})
}

func TestRIB_DeleteRoute(t *testing.T) {
	t.Run("Delete existing route", func(t *testing.T) {
		rib := New(in{DataPlane: &testDataPlane{}})

		route := &Route{
			Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
			Owner:   "owner0",
			NextHop: &testNextHop{},
		}

		rib.UpsertRoute(1, *route)
		require.Equal(t, uint(1), rib.ListRoutes("owner0")[1].Len())

		rib.DeleteRoute(1, *route)
		require.Nil(t, rib.ListRoutes("owner0")[1])
	})
	t.Run("Delete existing route in different VRF", func(t *testing.T) {
		rib := New(in{DataPlane: &testDataPlane{}})

		route := &Route{
			Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
			Owner:   "owner0",
			NextHop: &testNextHop{},
		}

		rib.UpsertRoute(1, *route)
		require.Equal(t, uint(1), rib.ListRoutes("owner0")[1].Len())

		rib.DeleteRoute(0, *route)
		require.Equal(t, uint(1), rib.ListRoutes("owner0")[1].Len())
	})
	t.Run("Delete existing route in with different owner", func(t *testing.T) {
		rib := New(in{DataPlane: &testDataPlane{}})

		route0 := &Route{
			Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
			Owner:   "owner0",
			NextHop: &testNextHop{},
		}
		route1 := &Route{
			Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
			Owner:   "owner1",
			NextHop: &testNextHop{},
		}

		rib.UpsertRoute(1, *route0)
		rib.UpsertRoute(1, *route1)
		require.Equal(t, uint(1), rib.ListRoutes("owner0")[1].Len())
		require.Equal(t, uint(1), rib.ListRoutes("owner1")[1].Len())

		rib.DeleteRoute(0, *route0)
		require.Equal(t, uint(1), rib.ListRoutes("owner1")[1].Len())
	})
}

func TestRIB_ListRoutes(t *testing.T) {
	t.Run("List routes with same owners", func(t *testing.T) {
		rib := New(in{DataPlane: &testDataPlane{}})

		route0 := Route{
			Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
			Owner:   "owner0",
			NextHop: &testNextHop{},
		}
		route1 := Route{
			Prefix:  netip.MustParsePrefix("192.168.2.0/24"),
			Owner:   "owner0",
			NextHop: &testNextHop{},
		}

		rib.UpsertRoute(1, route0)
		rib.UpsertRoute(1, route1)

		routes := rib.ListRoutes("owner0")[1]
		require.Equal(t, uint(2), routes.Len())

		_, found0 := routes.ExactLookup(route0.Prefix)
		_, found1 := routes.ExactLookup(route1.Prefix)
		require.True(t, found0, "Route0 not found in VRF 1")
		require.True(t, found1, "Route1 not found in VRF 1")
	})
	t.Run("List routes with different owners", func(t *testing.T) {
		rib := New(in{DataPlane: &testDataPlane{}})

		route0 := Route{
			Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
			Owner:   "owner0",
			NextHop: &testNextHop{},
		}
		route1 := Route{
			Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
			Owner:   "owner1",
			NextHop: &testNextHop{},
		}

		rib.UpsertRoute(1, route0)
		rib.UpsertRoute(1, route1)

		routes := rib.ListRoutes("owner0")[1]
		_, found := routes.ExactLookup(route0.Prefix)
		require.Equal(t, uint(1), routes.Len())
		require.True(t, found, "Route0 not found in VRF 1")

		routes = rib.ListRoutes("owner1")[1]
		_, found = routes.ExactLookup(route0.Prefix)
		require.Equal(t, uint(1), routes.Len())
		require.True(t, found, "Route1 not found in VRF 1")
	})
}

func TestRIB_selectBestPath(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.1.0/24")

	route0 := &Route{
		Prefix:   prefix,
		Protocol: ProtocolEBGP,
		Owner:    "owner1",
		NextHop:  &testNextHop{},
	}
	route1 := &Route{
		Prefix:   prefix,
		Protocol: ProtocolIBGP,
		Owner:    "owner0",
		NextHop:  &testNextHop{},
	}
	route2 := &Route{
		Prefix:   prefix,
		Protocol: ProtocolIBGP,
		Owner:    "owner2",
		NextHop:  &testNextHop{},
	}

	tests := []struct {
		name         string
		dest         *Destination
		expectedBest *Route
	}{
		{
			name: "First route is the best",
			dest: &Destination{
				best:   nil,
				routes: []*Route{route0},
			},
			expectedBest: route0,
		},
		{
			name: "Smaller Admin Distance wins",
			dest: &Destination{
				best: route1,
				routes: []*Route{
					route1,
					route0,
				},
			},
			expectedBest: route0,
		},
		{
			name: "Smaller Admin Distance wins, no change",
			dest: &Destination{
				best: route0,
				routes: []*Route{
					route0,
					route1,
				},
			},
			expectedBest: route0,
		},
		{
			name: "Same Admin Distance, smaller instance name wins",
			dest: &Destination{
				best: route2,
				routes: []*Route{
					route2,
					route1,
				},
			},
			expectedBest: route1,
		},
		{
			name: "Same Admin Distance, smaller instance name wins, no change",
			dest: &Destination{
				best: route1,
				routes: []*Route{
					route1,
					route2,
				},
			},
			expectedBest: route1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			best, changed := New(in{DataPlane: &testDataPlane{}}).selectBestPath(tt.dest)
			require.Equal(t, tt.expectedBest, best, "Unexpected best route")
			require.Equal(t, changed, best != tt.dest.best, "Unexpected change in best route")
		})
	}
}

func TestRIB_DataPlaneIntegration(t *testing.T) {
	dataPlane := &testDataPlane{}
	rib := New(in{DataPlane: dataPlane})

	route0 := &Route{
		Prefix:   netip.MustParsePrefix("192.168.1.0/24"),
		Protocol: ProtocolIBGP,
		Owner:    "owner0",
		NextHop:  &testNextHop{},
	}
	route1 := &Route{
		Prefix:   netip.MustParsePrefix("192.168.1.0/24"),
		Protocol: ProtocolEBGP,
		Owner:    "owner1",
		NextHop:  &testNextHop{},
	}
	route2 := &Route{
		Prefix:   netip.MustParsePrefix("192.168.1.0/24"),
		Protocol: ProtocolEBGP,
		Owner:    "owner1",
		NextHop: &testNextHop{
			differentiator: 1,
		},
	}

	t.Run("Initial route", func(t *testing.T) {
		rib.UpsertRoute(1, *route0)
		require.Len(t, dataPlane.receivedUpdates, 1)
		require.Nil(t, dataPlane.receivedUpdates[0].OldBest)
		require.Equal(t, route0, dataPlane.receivedUpdates[0].NewBest)
		dataPlane.Clear()
	})

	t.Run("New best route", func(t *testing.T) {
		rib.UpsertRoute(1, *route1)
		require.Len(t, dataPlane.receivedUpdates, 1)
		require.Equal(t, route0, dataPlane.receivedUpdates[0].OldBest)
		require.Equal(t, route1, dataPlane.receivedUpdates[0].NewBest)
		dataPlane.Clear()
	})

	t.Run("Update nexthop of the current best route", func(t *testing.T) {
		rib.UpsertRoute(1, *route2)
		require.Len(t, dataPlane.receivedUpdates, 1)
		require.Equal(t, route1, dataPlane.receivedUpdates[0].OldBest)
		require.Equal(t, route2, dataPlane.receivedUpdates[0].NewBest)
		dataPlane.Clear()
	})

	t.Run("Delete best route", func(t *testing.T) {
		rib.DeleteRoute(1, *route2)
		require.Len(t, dataPlane.receivedUpdates, 1)
		require.Equal(t, route2, dataPlane.receivedUpdates[0].OldBest)
		require.Equal(t, route0, dataPlane.receivedUpdates[0].NewBest)
		dataPlane.Clear()
	})

	t.Run("Delete final route", func(t *testing.T) {
		rib.DeleteRoute(1, *route0)
		require.Len(t, dataPlane.receivedUpdates, 1)
		require.Equal(t, route0, dataPlane.receivedUpdates[0].OldBest)
		require.Nil(t, dataPlane.receivedUpdates[0].NewBest)
		dataPlane.Clear()
	})
}

func TestRIB_DeleteRoutesByOwner(t *testing.T) {
	dataPlane := &testDataPlane{}
	rib := New(in{DataPlane: dataPlane})

	vrfID := uint32(1)
	route0 := &Route{
		Prefix:   netip.MustParsePrefix("192.168.1.0/24"),
		Owner:    "owner0",
		Protocol: ProtocolIBGP,
	}
	route1 := &Route{
		Prefix:   netip.MustParsePrefix("192.168.2.0/24"),
		Owner:    "owner0",
		Protocol: ProtocolIBGP,
	}
	route2 := &Route{
		Prefix:   netip.MustParsePrefix("192.168.3.0/24"),
		Owner:    "owner1",
		Protocol: ProtocolEBGP,
	}

	rib.UpsertRoute(vrfID, *route0)
	rib.UpsertRoute(vrfID, *route1)
	rib.UpsertRoute(vrfID, *route2)

	// Ensure routes exist on the RIB
	require.Equal(t, uint(2), rib.ListRoutes("owner0")[vrfID].Len())
	require.Equal(t, uint(1), rib.ListRoutes("owner1")[vrfID].Len())

	// Delete routes for owner0
	rib.DeleteRoutesByOwner("owner0")

	// Ensure all routes for owner0 are deleted
	require.Empty(t, rib.ListRoutes("owner0"))

	// Ensure owner1's route is still present
	require.Equal(t, uint(1), rib.ListRoutes("owner1")[vrfID].Len())

	// Ensure dataplane is getting the updates. We don't need to
	// check the content of the updates here because internally
	// DeleteRoutesByOwner uses DeleteRoute which is already tested.
	//
	// 3 new routes + 2 deleted routes = 5 updates
	require.Len(t, dataPlane.receivedUpdates, 5)

}

func TestRIB_InitialGC(t *testing.T) {
	ch := make(chan time.Time)

	logger := hivetest.Logger(t)

	initialRoutes := []*vrfRoute{
		{
			vrfID: 1,
			route: Route{
				Prefix:   netip.MustParsePrefix("10.0.0.0/24"),
				Owner:    "owner0",
				Protocol: ProtocolIBGP,
				NextHop:  &testNextHop{},
			},
		},
		{
			vrfID: 2,
			route: Route{
				Prefix:   netip.MustParsePrefix("fd00::/64"),
				Owner:    "owner1",
				Protocol: ProtocolEBGP,
				NextHop:  &testNextHop{},
			},
		},
	}

	var Rib *RIB

	Hive := hive.New(
		cell.Module(
			"test",
			"test module",
			cell.Provide(
				New,
				func() DataPlane {
					return &testDataPlane{
						initialRoutes: initialRoutes,
					}
				},
				func() gcChFn {
					return func() <-chan time.Time {
						return ch
					}
				},
			),
			cell.Invoke(
				scheduleInitialGC,
				func(r *RIB) {
					Rib = r
				},
			),
		),
	)

	err := Hive.Start(logger, context.TODO())
	require.NoError(t, err, "Failed to start Hive")
	t.Cleanup(func() {
		Hive.Stop(logger, context.TODO())
	})

	// Now the DataPlane.ForEach should be called at the Invoke hook. At
	// this point, we should only have the initial routes in the RIB with
	// unknown owner and protocol.
	bestRoutes := Rib.ListBestRoutes()

	require.Contains(t, bestRoutes, uint32(1), "VRF 1 should have routes")
	require.Contains(t, bestRoutes, uint32(2), "VRF 2 should have routes")

	vrf1 := bestRoutes[1]
	vrf2 := bestRoutes[2]

	require.Equal(t, uint(1), vrf1.Len(), "VRF 1 should have one route")
	require.Equal(t, uint(1), vrf2.Len(), "VRF 2 should have one route")

	rt1, found := vrf1.ExactLookup(netip.MustParsePrefix("10.0.0.0/24"))
	require.True(t, found, "VRF 1 should have route")
	require.Equal(t, OwnerUnknown, rt1.Owner, "VRF 1 route should have unknown owner")
	require.Equal(t, ProtocolUnknown, rt1.Protocol, "VRF 1 route should have unknown protocol")

	rt2, found := vrf2.ExactLookup(netip.MustParsePrefix("fd00::/64"))
	require.True(t, found, "VRF 2 should have route")
	require.Equal(t, OwnerUnknown, rt2.Owner, "VRF 2 route should have unknown owner")
	require.Equal(t, ProtocolUnknown, rt2.Protocol, "VRF 2 route should have unknown protocol")

	// Insert route for VRF 1 only. This should win the best path selection.
	// We don't update VRF 2's route, so it should remain unchanged.
	Rib.UpsertRoute(1, Route{
		Prefix:   netip.MustParsePrefix("10.0.0.0/24"),
		Owner:    "owner0",
		Protocol: ProtocolIBGP,
		NextHop:  &testNextHop{},
	})

	// Now we can trigger the initial GC. This should sweep the VRF 2 route
	// and the route with unknown owner and protocol for VRF 1.
	close(ch)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		bestRoutes := Rib.ListBestRoutes()

		if !assert.Contains(ct, bestRoutes, uint32(1), "VRF 1 should still have routes") {
			return
		}
		if !assert.NotContains(ct, bestRoutes, uint32(2), "VRF 2 should not have routes") {
			return
		}

		vrf1 := bestRoutes[1]
		if !assert.Equal(ct, uint(1), vrf1.Len(), "VRF 1 should have one route") {
			return
		}

		rt1, found := vrf1.ExactLookup(netip.MustParsePrefix("10.0.0.0/24"))
		if !assert.True(ct, found, "VRF 1 should have route") {
			return
		}
		if !assert.Equal(ct, "owner0", rt1.Owner, "VRF 1 route should have unknown owner") {
			return
		}
		if !assert.Equal(ct, ProtocolIBGP, rt1.Protocol, "VRF 1 route should have IBGP protocol") {
			return
		}
	}, time.Second*5, time.Millisecond*100, "Initial GC did not run")
}
