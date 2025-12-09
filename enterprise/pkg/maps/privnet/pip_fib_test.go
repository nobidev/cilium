// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package privnet

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/types"
)

func TestPIPFIBString(t *testing.T) {
	// PIP key
	assert.Equal(t, "10.1.0.0/16",
		NewPIPKey(
			netip.MustParsePrefix("10.1.0.0/16"),
		).String())
	assert.Equal(t, "fd00::/96",
		NewPIPKey(
			netip.MustParsePrefix("fd00::/96"),
		).String())

	// PIP value
	assert.Equal(t, "0x42 192.168.2.11 99 00:aa:bb:cc:dd:ee 0x0",
		NewPIPVal(
			0x42,
			netip.MustParseAddr("192.168.2.11"),
			types.MACAddr(mac.MustParseMAC("00:AA:BB:CC:DD:EE")),
			99,
		).String())
	assert.Equal(t, "0xff f0:d:f0:: 3 00:ee:11:22:33:44 0x0",
		NewPIPVal(
			255,
			netip.MustParseAddr("f0:0d:f0::"),
			types.MACAddr(mac.MustParseMAC("00:ee:11:22:33:44")),
			3,
		).String())

	// FIB key
	assert.Equal(t, "0x42 10.1.0.0/16",
		NewFIBKey(
			0x42,
			netip.MustParsePrefix("10.1.0.0/16"),
		).String())
	assert.Equal(t, "0x63 fc:0:80::/64",
		NewFIBKey(
			99,
			netip.MustParsePrefix("fc:00:80::/64"),
		).String())

	// FIB value
	assert.Equal(t, "192.168.3.99 0x1",
		NewFIBVal(
			netip.MustParseAddr("192.168.3.99"),
			FIBFlagL2Announce,
		).String())
	assert.Equal(t, "fa:ce::1 0x2",
		NewFIBVal(
			netip.MustParseAddr("fa:ce:0:0::1"),
			FIBFlagSubnetRoute,
		).String())
}

func TestPrivilegedPIPFIB(t *testing.T) {
	testutils.PrivilegedTest(t)

	var (
		ctx = t.Context()
		log = hivetest.Logger(t)

		pip PIP
		fib FIB
		nd  = make(defines.Map)
	)

	t.Cleanup(func() {
		testutils.GoleakVerifyNone(t)

		if pip.Map != nil {
			require.NoError(t, pip.Map.Unpin())
		}
		if fib.Map != nil {
			require.NoError(t, fib.Map.Unpin())
		}
	})

	h := hive.New(
		cell.Config(defaultConfig),

		cell.Provide(
			newPIP,
			newFIB,
			Config.nodeDefs,

			func() config.Config {
				return config.Config{
					Common: config.Common{Enabled: true},
				}
			},
		),

		cell.Invoke(func(in struct {
			cell.In
			PIP              PIP
			FIB              FIB
			NodeExtraDefines []defines.Map `group:"header-node-defines"`
		}) {
			pip = in.PIP
			fib = in.FIB

			for _, ned := range in.NodeExtraDefines {
				nd.Merge(ned)
			}
		}),
	)

	require.NoError(t, h.Start(log, ctx), "h.Start")
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()), "h.Stop")
	})

	require.Equal(t, fmt.Sprintf("%d", defaultConfig.MapSize), nd["PRIVNET_PIP_FIB_MAP_SIZE"])

	pipPath, err := pip.Map.Path()
	require.NoError(t, err, "pip.Map.Path")

	fibPath, err := fib.Map.Path()
	require.NoError(t, err, "fib.Map.Path")

	require.NoError(t, h.Stop(log, ctx), "h.Stop")
	require.FileExists(t, pipPath, "PIP map pin should still exist")
	require.FileExists(t, fibPath, "FIB map pin should still exist")

	// When disabled, the maps should be deleted
	h = hive.New(
		cell.Config(defaultConfig),

		cell.Provide(
			newPIP,
			newFIB,
			Config.nodeDefs,

			func() config.Config { return config.Config{} },
		),

		cell.Invoke(
			func(PIP, FIB) { /* make sure PIP and FIB maps get constructed */ },
		),
	)

	require.NoError(t, h.Start(log, ctx), "h.Start")
	require.NoFileExists(t, pipPath, "PIP map pin should not exist")
	require.NoFileExists(t, fibPath, "FIB map pin should not exist")

}
