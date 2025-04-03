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
	"net/netip"
	"testing"

	require "github.com/stretchr/testify/require"
)

type testNextHop struct{}

func (m testNextHop) isNextHop() {}

func TestRIB_UpsertRoute(t *testing.T) {
	t.Run("Same prefix with different VRF", func(t *testing.T) {
		rib := New()

		route := &Route{
			Prefix:   netip.MustParsePrefix("192.168.1.0/24"),
			Owner:    "owner0",
			Protocol: ProtocolEBGP,
			NextHop:  testNextHop{},
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
		rib := New()

		route := &Route{
			Prefix:   netip.MustParsePrefix("192.168.1.0/24"),
			Owner:    "owner0",
			Protocol: ProtocolEBGP,
			NextHop:  testNextHop{},
		}

		// These upserts should not duplicate the route
		rib.UpsertRoute(1, *route)
		rib.UpsertRoute(1, *route)

		routes := rib.ListRoutes("owner0")[1]
		require.Equal(t, uint(1), routes.Len())
	})
	t.Run("Same VRF and prefix with different owner", func(t *testing.T) {
		rib := New()

		route0 := &Route{
			Prefix:   netip.MustParsePrefix("192.168.1.0/24"),
			Owner:    "owner0",
			Protocol: ProtocolEBGP,
			NextHop:  testNextHop{},
		}

		route1 := &Route{
			Prefix:   netip.MustParsePrefix("192.168.1.0/24"),
			Owner:    "owner1",
			Protocol: ProtocolEBGP,
			NextHop:  testNextHop{},
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
		rib := New()

		route := &Route{
			Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
			Owner:   "owner0",
			NextHop: testNextHop{},
		}

		rib.UpsertRoute(1, *route)
		require.Equal(t, uint(1), rib.ListRoutes("owner0")[1].Len())

		rib.DeleteRoute(1, *route)
		require.Nil(t, rib.ListRoutes("owner0")[1])
	})
	t.Run("Delete existing route in different VRF", func(t *testing.T) {
		rib := New()

		route := &Route{
			Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
			Owner:   "owner0",
			NextHop: testNextHop{},
		}

		rib.UpsertRoute(1, *route)
		require.Equal(t, uint(1), rib.ListRoutes("owner0")[1].Len())

		rib.DeleteRoute(0, *route)
		require.Equal(t, uint(1), rib.ListRoutes("owner0")[1].Len())
	})
	t.Run("Delete existing route in with different owner", func(t *testing.T) {
		rib := New()

		route0 := &Route{
			Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
			Owner:   "owner0",
			NextHop: testNextHop{},
		}
		route1 := &Route{
			Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
			Owner:   "owner1",
			NextHop: testNextHop{},
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
		rib := New()

		route0 := Route{
			Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
			Owner:   "owner0",
			NextHop: testNextHop{},
		}
		route1 := Route{
			Prefix:  netip.MustParsePrefix("192.168.2.0/24"),
			Owner:   "owner0",
			NextHop: testNextHop{},
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
		rib := New()

		route0 := Route{
			Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
			Owner:   "owner0",
			NextHop: testNextHop{},
		}
		route1 := Route{
			Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
			Owner:   "owner1",
			NextHop: testNextHop{},
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
