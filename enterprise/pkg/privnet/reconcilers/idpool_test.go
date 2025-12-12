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
	"fmt"
	"log/slog"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/wal"
)

func TestIDPool(t *testing.T) {
	log := slog.Default()

	pool := NewIDPool(log, 3, 5)

	nameFn := func(id tables.NetworkID) tables.NetworkName {
		return tables.NetworkName(fmt.Sprintf("net-%d", id))
	}

	acquireAssertValue := func(expected tables.NetworkID) {
		actual, err := pool.acquire(nameFn(expected))
		require.NoError(t, err, "acquire unexpectedly failed")
		require.Equal(t, expected, actual)
	}

	acquireAssertError := func() {
		_, err := pool.acquire("error")
		require.Error(t, err, "acquire should have failed")
	}

	acquireAssertValue(3)
	acquireAssertValue(4)
	acquireAssertValue(5)
	acquireAssertValue(1)
	acquireAssertValue(2)

	// No more IDs should be available
	acquireAssertError()

	pool.release(4)
	pool.release(0) // No-op
	pool.release(2)

	acquireAssertValue(4)
	acquireAssertValue(2)

	// No more IDs should be available
	acquireAssertError()

	// Checking the boundaries
	pool = NewIDPool(log, 0, 5)
	acquireAssertValue(1)
	acquireAssertValue(2)

	pool = NewIDPool(log, 5, 5)
	acquireAssertValue(5)
	acquireAssertValue(1)

	pool = NewIDPool(log, tables.NetworkIDMax-1, tables.NetworkIDMax)
	acquireAssertValue(tables.NetworkIDMax - 1)
	acquireAssertValue(tables.NetworkIDMax)
	acquireAssertValue(1)

	// Checking re requesting the ID
	pool = NewIDPool(log, 0, 5)
	actual, err := pool.acquire("foobar")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(1), actual)

	actual, err = pool.acquire("buzz")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(2), actual)

	actual, err = pool.acquire("buzz")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(2), actual)

	actual, err = pool.acquire("foobar")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(1), actual)

	pool.release(1)
	// Acquire new id after release
	actual, err = pool.acquire("foobar")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(3), actual)
	actual, err = pool.acquire("buzz")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(2), actual)
}

func TestIDPool_restore(t *testing.T) {
	log := slog.Default()
	walFile := path.Join(t.TempDir(), PrivnetIDWALFile)
	var err error

	pool := NewIDPool(log, 0, 5)
	pool.walWriter, err = wal.NewWriter[allocationWALEntry](walFile)
	require.NoError(t, err)

	actual, err := pool.acquire("foo")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(1), actual)

	actual, err = pool.acquire("bar")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(2), actual)

	actual, err = pool.acquire("buzz")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(3), actual)

	actual, err = pool.acquire("other")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(4), actual)

	pool.release(tables.NetworkID(4))

	pool = NewIDPool(log, 3, 6)
	require.NoError(t, pool.restore(walFile))
	pool.walWriter, err = wal.NewWriter[allocationWALEntry](walFile)
	require.NoError(t, err)

	actual, err = pool.acquire("buzz")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(3), actual)

	actual, err = pool.acquire("foo")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(1), actual)

	actual, err = pool.acquire("not_other")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(4), actual)

	actual, err = pool.acquire("other")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(5), actual)

	pool.initialized()

	actual, err = pool.acquire("bar")
	require.NoError(t, err, "acquire unexpectedly failed")
	require.Equal(t, tables.NetworkID(6), actual)
}
