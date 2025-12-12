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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

func TestIDPool(t *testing.T) {
	pool := NewIDPool(3, 5)

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
	pool = NewIDPool(0, 5)
	acquireAssertValue(1)
	acquireAssertValue(2)

	pool = NewIDPool(5, 5)
	acquireAssertValue(5)
	acquireAssertValue(1)

	pool = NewIDPool(tables.NetworkIDMax-1, tables.NetworkIDMax)
	acquireAssertValue(tables.NetworkIDMax - 1)
	acquireAssertValue(tables.NetworkIDMax)
	acquireAssertValue(1)

	// Checking re requesting the ID
	pool = NewIDPool(0, 5)
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
