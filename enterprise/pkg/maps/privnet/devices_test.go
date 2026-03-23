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
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestDevicesString(t *testing.T) {
	assert.Equal(t, "10", NewDeviceKey(10).String())
	assert.Equal(t, "0x42 lxc 10.0.0.1 2001::1", NewDeviceVal(0x42, DeviceValTypeLxc, netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("2001::1")).String())
}

func TestPrivilegedDevices(t *testing.T) {
	testutils.PrivilegedTest(t)

	var (
		ctx = t.Context()
		log = hivetest.Logger(t)

		theMap *bpf.Map
		nd     = make(defines.Map)
	)

	t.Cleanup(func() {
		testutils.GoleakVerifyNone(t)

		if theMap != nil {
			require.NoError(t, theMap.Unpin())
		}
	})

	h := hive.New(
		cell.Config(defaultConfig),

		cell.Provide(
			newDevices,
			Config.nodeDefs,

			func() config.Config {
				return config.Config{
					Common: config.Common{Enabled: true},
				}
			},
		),

		cell.Invoke(func(in struct {
			cell.In
			Devices          Map[*DeviceKeyVal]
			NodeExtraDefines []defines.Map `group:"header-node-defines"`
		}) {
			theMap = in.Devices.(Devices).Map

			for _, ned := range in.NodeExtraDefines {
				nd.Merge(ned)
			}
		}),
	)

	require.NoError(t, h.Start(log, ctx), "h.Start")
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()), "h.Stop")
	})

	require.Equal(t, "16384", nd["PRIVNET_DEVICES_MAP_SIZE"])

	path, err := theMap.Path()
	require.NoError(t, err, "theMap.Path")

	require.NoError(t, h.Stop(log, ctx), "h.Stop")
	require.FileExists(t, path, "Map pin should still exist")

	// When disabled, the map should be deleted
	h = hive.New(
		cell.Config(defaultConfig),

		cell.Provide(
			newDevices,
			func() config.Config { return config.Config{} },
		),

		cell.Invoke(
			func(Map[*DeviceKeyVal]) { /* make sure the map gets constructed */ },
		),
	)

	require.NoError(t, h.Start(log, ctx), "h.Start")
	require.NoFileExists(t, path, "Map pin should not exist")
}
