// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vni

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	evpnCfg "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	privnetcfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedMapPinning(t *testing.T) {
	testutils.PrivilegedTest(t)

	var (
		ctx = t.Context()
		log = hivetest.Logger(t)

		vni VNI
		nd  = make(defines.Map)
	)

	t.Cleanup(func() {
		testutils.GoleakVerifyNone(t)
		if vni.Map != nil {
			require.NoError(t, vni.Unpin())
		}
	})

	newHive := func() *hive.Hive {
		return hive.New(
			cell.Config(defaultConfig),
			cell.Config(privnetcfg.Config{}),
			cell.Config(evpnCfg.Config{}),

			cell.Provide(
				newVNI,
				Config.nodeDefs,
			),

			cell.Invoke(func(in struct {
				cell.In
				VNI              VNI
				NodeExtraDefines []defines.Map `group:"header-node-defines"`
			}) {
				vni = in.VNI
				for _, ned := range in.NodeExtraDefines {
					nd.Merge(ned)
				}
			}),
		)
	}

	// Enabled
	h := newHive()

	hive.AddConfigOverride(h, func(cfg *privnetcfg.Config) {
		cfg.Enabled = true
	})
	hive.AddConfigOverride(h, func(cfg *evpnCfg.Config) {
		cfg.Enabled = true
	})

	require.NoError(t, h.Start(log, ctx), "h.Start")
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()), "h.Stop")
	})

	require.Equal(t, fmt.Sprintf("%d", defaultConfig.MapSize), nd["VNI_MAP_SIZE"])

	vniPath, err := vni.Path()
	require.NoError(t, err, "vni.Path")

	require.NoError(t, h.Stop(log, ctx), "h.Stop")
	require.FileExists(t, vniPath, "VNI map pin should still exist")

	// Disable Privnet
	h = newHive()

	hive.AddConfigOverride(h, func(cfg *evpnCfg.Config) {
		cfg.Enabled = true
	})

	require.NoError(t, h.Start(log, ctx), "h.Start")
	require.NoFileExists(t, vniPath, "VNI map pin should not exist")
}
