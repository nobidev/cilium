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
	"maps"
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
)

func TestOps(t *testing.T) {
	rib := New(in{DataPlanes: []DataPlane{&testDataPlane{}}})
	testOwner0 := "test-owner0"
	testOwner1 := "test-owner1"

	ops := NewOps(rib, testOwner0)

	vrfRoute0 := VRFRoute{
		VRFID: 1,
		Route: Route{
			Prefix:  netip.MustParsePrefix("10.0.0.0/24"),
			Owner:   testOwner0,
			NextHop: &testNextHop{},
		},
	}
	vrfRoute1 := VRFRoute{
		VRFID: 1,
		Route: Route{
			Prefix:  netip.MustParsePrefix("10.0.1.0/24"),
			Owner:   testOwner0,
			NextHop: &testNextHop{},
		},
	}
	vrfRoute2 := VRFRoute{
		VRFID: 1,
		Route: Route{
			Prefix:  netip.MustParsePrefix("10.0.2.0/24"),
			Owner:   testOwner0,
			NextHop: &testNextHop{},
		},
	}
	vrfRoute3 := VRFRoute{
		VRFID: 1,
		Route: Route{
			Prefix:  netip.MustParsePrefix("10.0.3.0/24"),
			Owner:   testOwner1, // Unrelated owner
			NextHop: &testNextHop{},
		},
	}

	t.Run("Update", func(t *testing.T) {
		err := ops.Update(context.TODO(), nil, 0, vrfRoute0)
		require.NoError(t, err)

		err = ops.Update(context.TODO(), nil, 0, vrfRoute1)
		require.NoError(t, err)

		err = ops.Update(context.TODO(), nil, 0, vrfRoute2)
		require.NoError(t, err)

		err = ops.Update(context.TODO(), nil, 0, vrfRoute3)
		require.NoError(t, err)

		trie := rib.ListRoutes(testOwner0)[1]

		_, found := trie.ExactLookup(vrfRoute0.Route.Prefix)
		require.True(t, found)

		_, found = trie.ExactLookup(vrfRoute1.Route.Prefix)
		require.True(t, found)

		_, found = trie.ExactLookup(vrfRoute2.Route.Prefix)
		require.True(t, found)

		_, found = trie.ExactLookup(vrfRoute3.Route.Prefix)
		require.False(t, found, "Route with different owner should be ignored")
	})

	t.Run("Delete", func(t *testing.T) {
		err := ops.Delete(context.TODO(), nil, 0, vrfRoute2)
		require.NoError(t, err)

		trie := rib.ListRoutes(testOwner0)[1]

		_, found := trie.ExactLookup(vrfRoute2.Route.Prefix)
		require.False(t, found, "Route should have been deleted")
	})

	t.Run("Prune", func(t *testing.T) {
		desiredRoutes := maps.All(map[VRFRoute]statedb.Revision{
			vrfRoute0: 0,
		})

		err := ops.Prune(context.TODO(), nil, desiredRoutes)
		require.NoError(t, err)

		trie := rib.ListRoutes(testOwner0)[1]

		_, found := trie.ExactLookup(vrfRoute1.Route.Prefix)
		require.False(t, found, "Route should have been deleted")

		_, found = trie.ExactLookup(vrfRoute0.Route.Prefix)
		require.True(t, found, "Route should have been left")
	})
}
