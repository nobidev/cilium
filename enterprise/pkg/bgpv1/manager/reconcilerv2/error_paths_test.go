// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgp/types"
)

func TestErrorPathStore(t *testing.T) {
	familyIPv4Unicast := types.Family{
		Afi:  types.AfiIPv4,
		Safi: types.SafiUnicast,
	}
	familyIPv6Unicast := types.Family{
		Afi:  types.AfiIPv6,
		Safi: types.SafiUnicast,
	}
	v4Path0 := ErrorPath{
		ErrorPathKey: ErrorPathKey{
			nlri:         "10.0.0.0/24",
			neighborAddr: netip.MustParseAddr("192.168.0.1"),
		},
		Error: fmt.Errorf("test error 0"),
	}
	v4Path1 := ErrorPath{
		ErrorPathKey: ErrorPathKey{
			nlri:         "10.0.0.0/24",
			neighborAddr: netip.MustParseAddr("192.168.0.2"),
		},
		Error: fmt.Errorf("test error 1"),
	}
	v6Path0 := ErrorPath{
		ErrorPathKey: ErrorPathKey{
			nlri:         "fd00::/64",
			neighborAddr: netip.MustParseAddr("2001:db8::1"),
		},
		Error: fmt.Errorf("test error 0"),
	}

	t.Run("CRUD", func(t *testing.T) {
		store := newErrorPathStore()

		// New path
		store.Update(
			"instance0",
			familyIPv4Unicast,
			map[ErrorPathKey]ErrorPath{
				v4Path0.ErrorPathKey: v4Path0,
			},
		)

		// Get the inserted path
		path, found := store.Get("instance0", familyIPv4Unicast, v4Path0.ErrorPathKey)
		require.True(t, found, "Cannot get inserted path")
		require.Equal(t, v4Path0, path, "Retrieved path does not match inserted path")

		store.Update(
			"instance0",
			familyIPv4Unicast,
			map[ErrorPathKey]ErrorPath{
				v4Path1.ErrorPathKey: v4Path1,
			},
		)

		// Get the updated path
		path, found = store.Get("instance0", familyIPv4Unicast, v4Path1.ErrorPathKey)
		require.True(t, found, "Cannot get inserted path")
		require.Equal(t, v4Path1, path, "Retrieved path does not match inserted path")

		// Old path should have been replaced with the new path as
		// Update replaces all paths for the instance and family.
		_, found = store.Get("instance0", familyIPv4Unicast, v4Path0.ErrorPathKey)
		require.False(t, found, "Old path should have been replaced and not found")

		// Insert multiple paths to test multipath scenario
		store.Update(
			"instance0",
			familyIPv4Unicast,
			map[ErrorPathKey]ErrorPath{
				v4Path0.ErrorPathKey: v4Path0,
				v4Path1.ErrorPathKey: v4Path1,
			},
		)

		// Get both paths. We should see both paths.
		path, found = store.Get("instance0", familyIPv4Unicast, v4Path0.ErrorPathKey)
		require.True(t, found, "Cannot get inserted path")
		require.Equal(t, v4Path0, path, "Retrieved path does not match inserted path")

		path, found = store.Get("instance0", familyIPv4Unicast, v4Path1.ErrorPathKey)
		require.True(t, found, "Cannot get inserted path")
		require.Equal(t, v4Path1, path, "Retrieved path does not match inserted path")

		// Insert a path for the different family to make sure the
		// delete onlt deletes paths for the specified family
		store.Update(
			"instance0",
			familyIPv6Unicast,
			map[ErrorPathKey]ErrorPath{
				v6Path0.ErrorPathKey: v6Path0,
			},
		)

		// Delete paths for instance0 and familyIPv4Unicast
		store.Delete("instance0", familyIPv4Unicast)

		// All v4 paths should be deleted
		_, found = store.Get("instance0", familyIPv4Unicast, v4Path0.ErrorPathKey)
		require.False(t, found, "v4Path0 should have been deleted")
		_, found = store.Get("instance0", familyIPv4Unicast, v4Path1.ErrorPathKey)
		require.False(t, found, "v4Path1 should have been deleted")

		// v6 path should still be present
		path, found = store.Get("instance0", familyIPv6Unicast, v6Path0.ErrorPathKey)
		require.True(t, found, "v6Path0 should not have been deleted")
		require.Equal(t, v6Path0, path, "Retrieved path does not match inserted path")
	})
}
