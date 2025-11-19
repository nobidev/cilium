//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package privnet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestWatchdog(t *testing.T) {
	assert.Equal(t, "AgentLiveness", WatchdogIndexLiveness.String())
	assert.Equal(t, "AgentLivenessTimeout", WatchdogIndexTimeout.String())
	assert.Equal(t, "Unknown", WatchdogIndex(0xbeef).String())

	assert.Equal(t, "0x0", WatchdogValue(0).String())
	assert.Equal(t, "0x1357", WatchdogValue(0x1357).String())
	assert.Equal(t, "0xbeef", WatchdogValue(0xbeef).String())
}

func TestPrivilegedWatchdog(t *testing.T) {
	testutils.PrivilegedTest(t)

	var (
		ctx = t.Context()
		log = hivetest.Logger(t)

		wd     Watchdog
		theMap *bpf.Map
		nd     = make(defines.Map)

		mtimeValue = 15*time.Minute + 23*time.Second + 754*time.Microsecond
	)

	t.Cleanup(func() {
		testutils.GoleakVerifyNone(t)

		if theMap != nil {
			require.NoError(t, theMap.Unpin())
		}
	})

	h := hive.New(
		cell.Provide(
			newWatchdog,

			func() config.Config {
				return config.Config{
					Common: config.Common{Enabled: true},
				}
			},
		),

		cell.Invoke(func(in struct {
			cell.In
			Watchdog         Watchdog
			NodeExtraDefines []defines.Map `group:"header-node-defines"`
		}) {
			wd = in.Watchdog
			theMap = in.Watchdog.(watchdog).Map

			for _, ned := range in.NodeExtraDefines {
				nd.Merge(ned)
			}
		}),
	)

	require.NoError(t, h.Start(log, ctx), "h.Start")
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()), "h.Stop")
	})

	defer func(curr func() (uint64, error)) { getMtime = curr }(getMtime)
	getMtime = func() (uint64, error) { return uint64(mtimeValue.Nanoseconds()), nil }

	getLiveness := func() time.Duration {
		val, err := theMap.Lookup(ptr.To(WatchdogIndexLiveness))
		require.NoError(t, err, "theMap.Lookup")
		return time.Duration(*(val.(*WatchdogValue)))
	}

	getTimeout := func() time.Duration {
		val, err := theMap.Lookup(ptr.To(WatchdogIndexTimeout))
		require.NoError(t, err, "theMap.Lookup")
		return time.Duration(*(val.(*WatchdogValue)))
	}

	require.Equal(t, "2", nd["PRIVNET_WATCHDOG_MAP_SIZE"])

	// Initially, the map entry should be uninitialized (i.e., 0)
	require.EqualValues(t, 0, getLiveness())
	require.EqualValues(t, 0, getTimeout())

	// Call [Watchdog.SetAlive], and assert that the entry is appropriately updated.
	require.NoError(t, wd.SetAlive(), "wd.SetAlive")
	require.Equal(t, mtimeValue, getLiveness())

	// Call [Watchdog.SetAlive] again, and assert that the entry is updated again.
	mtimeValue += 148 * time.Millisecond
	require.NoError(t, wd.SetAlive(), "wd.SetAlive")
	require.Equal(t, mtimeValue, getLiveness())

	// Errors returned by [bpf.GetMtime] should be propagated.
	var err = errors.New("failing on purpose")
	getMtime = func() (uint64, error) { return 0, err }
	require.ErrorIs(t, wd.SetAlive(), err)

	// Call [Watchdog.SetTimeout] a few times, and assert that the entry is appropriately updated.
	for _, timeout := range []time.Duration{100 * time.Millisecond, 1 * time.Second, 10 * time.Second} {
		require.NoError(t, wd.SetTimeout(timeout), "wd.SetTimeout")
		require.Equal(t, timeout, getTimeout())
	}

	path, err := theMap.Path()
	require.NoError(t, err, "theMap.Path")

	require.NoError(t, h.Stop(log, ctx), "h.Stop")
	require.FileExists(t, path, "Map pin should still exist")

	// When disabled, the map should be deleted
	h = hive.New(
		cell.Provide(
			newWatchdog,
			func() config.Config { return config.Config{} },
		),

		cell.Invoke(
			func(Watchdog) { /* make sure Watchdog gets constructed */ },
		),
	)

	require.NoError(t, h.Start(log, ctx), "h.Start")
	require.NoFileExists(t, path, "Map pin should not exist")
}
