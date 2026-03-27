// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package evpn

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	evpnCfg "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/types"
)

func TestNewFIBKey(t *testing.T) {
	tests := []struct {
		name        string
		netID       uint16
		prefix      netip.Prefix
		expectedKey *FIBKey
		expectError bool
	}{
		{
			name:   "Baseline IPv4",
			netID:  42,
			prefix: netip.MustParsePrefix("10.0.0.0/24"),
			expectedKey: &FIBKey{
				PrefixLen: 24 + fibKeyStaticPrefixBits,
				Family:    unix.AF_INET,
				NetID:     42,
				Address:   types.IPv6{0xa},
			},
		},
		{
			name:   "Baseline IPv6",
			netID:  42,
			prefix: netip.MustParsePrefix("fd00::/64"),
			expectedKey: &FIBKey{
				PrefixLen: 64 + fibKeyStaticPrefixBits,
				Family:    unix.AF_INET6,
				NetID:     42,
				Address:   types.IPv6{0xfd},
			},
		},
		{
			name:        "Invalid prefix",
			netID:       42,
			prefix:      netip.Prefix{},
			expectError: true,
			expectedKey: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewFIBKey(tt.netID, tt.prefix)
			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedKey, key)
		})
	}
}

func TestFIBKeyString(t *testing.T) {
	require.Equal(t, "net_id=42 prefix=10.0.0.0/24", (&FIBKey{
		PrefixLen: 24 + fibKeyStaticPrefixBits,
		Family:    unix.AF_INET,
		NetID:     42,
		Address:   types.IPv6{0xa},
	}).String())
	require.Equal(t, "net_id=42 prefix=fd00::/64", (&FIBKey{
		PrefixLen: 64 + fibKeyStaticPrefixBits,
		Family:    unix.AF_INET6,
		NetID:     42,
		Address:   types.IPv6{0xfd},
	}).String())
}

func TestFIBKeyPrefix(t *testing.T) {
	require.Equal(t, netip.MustParsePrefix("10.0.0.0/24"), (&FIBKey{
		PrefixLen: 24 + fibKeyStaticPrefixBits,
		Family:    unix.AF_INET,
		NetID:     42,
		Address:   types.IPv6{0xa},
	}).Prefix())
	require.Equal(t, netip.MustParsePrefix("fd00::/64"), (&FIBKey{
		PrefixLen: 64 + fibKeyStaticPrefixBits,
		Family:    unix.AF_INET6,
		NetID:     42,
		Address:   types.IPv6{0xfd},
	}).Prefix())
}

func TestNewFIBVal(t *testing.T) {
	tests := []struct {
		name        string
		vni         vni.VNI
		mac         mac.MAC
		ip          netip.Addr
		expectedVal *FIBVal
		expectError bool
	}{
		{
			name: "Baseline IPv4",
			vni:  vni.MustFromUint32(100),
			mac:  mac.MustParseMAC("aa:bb:cc:dd:ee:ff"),
			ip:   netip.MustParseAddr("10.0.0.1"),
			expectedVal: &FIBVal{
				VNI:     100,
				Family:  unix.AF_INET,
				MAC:     mac.MustParseMAC("aa:bb:cc:dd:ee:ff").As6(),
				Address: types.IPv6{0xa, 0, 0, 1},
			},
		},
		{
			name: "Baseline IPv6",
			vni:  vni.MustFromUint32(100),
			mac:  mac.MustParseMAC("aa:bb:cc:dd:ee:ff"),
			ip:   netip.MustParseAddr("fd00::1"),
			expectedVal: &FIBVal{
				VNI:     100,
				Family:  unix.AF_INET6,
				MAC:     mac.MustParseMAC("aa:bb:cc:dd:ee:ff").As6(),
				Address: types.IPv6{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			},
		},
		{
			name:        "Invalid IP",
			vni:         vni.MustFromUint32(100),
			mac:         mac.MustParseMAC("aa:bb:cc:dd:ee:ff"),
			ip:          netip.Addr{},
			expectError: true,
			expectedVal: nil,
		},
		{
			name:        "Invalid MAC",
			vni:         vni.MustFromUint32(100),
			mac:         mac.MustParseMAC("00:00:00:00:00:00"),
			ip:          netip.MustParseAddr("10.0.0.1"),
			expectError: true,
			expectedVal: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := NewFIBVal(tt.vni, tt.mac, tt.ip)
			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedVal, val)
		})
	}
}

func TestFIBValString(t *testing.T) {
	require.Equal(t, "vni=100 mac=aa:bb:cc:dd:ee:ff addr=10.0.0.1", (&FIBVal{
		VNI:     100,
		Family:  unix.AF_INET,
		MAC:     mac.MustParseMAC("aa:bb:cc:dd:ee:ff").As6(),
		Address: types.IPv6{0xa, 0, 0, 1},
	}).String())
	require.Equal(t, "vni=100 mac=aa:bb:cc:dd:ee:ff addr=fd00::1", (&FIBVal{
		VNI:     100,
		Family:  unix.AF_INET6,
		MAC:     mac.MustParseMAC("aa:bb:cc:dd:ee:ff").As6(),
		Address: types.IPv6{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}).String())
}

func TestFIBValAddr(t *testing.T) {
	require.Equal(t, netip.MustParseAddr("10.0.0.1"), (&FIBVal{
		VNI:     100,
		Family:  unix.AF_INET,
		MAC:     mac.MustParseMAC("aa:bb:cc:dd:ee:ff").As6(),
		Address: types.IPv6{0xa, 0, 0, 1},
	}).Addr())
	require.Equal(t, netip.MustParseAddr("fd00::1"), (&FIBVal{
		VNI:     100,
		Family:  unix.AF_INET6,
		MAC:     mac.MustParseMAC("aa:bb:cc:dd:ee:ff").As6(),
		Address: types.IPv6{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}).Addr())
}

func TestPrivilegedMapPinning(t *testing.T) {
	testutils.PrivilegedTest(t)

	var (
		ctx = t.Context()
		log = hivetest.Logger(t)

		fib FIB
		nd  = make(defines.Map)
	)

	t.Cleanup(func() {
		if fib.Map != nil {
			// Make sure we don't have any leftover pinned maps after the test
			require.NoError(t, fib.UnpinIfExists())
		}
	})

	newHive := func() *hive.Hive {
		return hive.New(
			cell.Config(defaultConfig),
			cell.Config(evpnCfg.Config{}),

			cell.Provide(
				newFIB,
				Config.nodeDefs,
			),

			cell.Invoke(func(in struct {
				cell.In
				FIB              FIB
				NodeExtraDefines []defines.Map `group:"header-node-defines"`
			}) {
				fib = in.FIB
				for _, ned := range in.NodeExtraDefines {
					nd.Merge(ned)
				}
			}),
		)
	}

	// Disable EVPN
	t.Run("EVPN disabled, Start should succeed, no pin", func(t *testing.T) {
		h := newHive()

		hive.AddConfigOverride(h, func(cfg *evpnCfg.Config) {
			cfg.Enabled = false
		})

		require.NoError(t, h.Start(log, ctx), "h.Start")

		fibPath, err := fib.Path()
		require.NoError(t, err, "fib.Path")

		require.NoError(t, h.Stop(log, ctx), "h.Stop")

		require.NoFileExists(t, fibPath, "FIB map pin should not exist")
	})

	key := MustNewFIBKey(42, netip.MustParsePrefix("10.0.0.0/24"))
	val := MustNewFIBVal(vni.MustFromUint32(100), mac.MustParseMAC("aa:bb:cc:dd:ee:ff"), netip.MustParseAddr("10.0.0.1"))

	// Enable EVPN, should create and pin the FIB map
	t.Run("EVPN enabled, Start should succeed, pin should exist", func(t *testing.T) {
		h := newHive()

		hive.AddConfigOverride(h, func(cfg *evpnCfg.Config) {
			cfg.Enabled = true
		})

		require.NoError(t, h.Start(log, ctx), "h.Start")

		fibPath, err := fib.Path()
		require.NoError(t, err, "fib.Path")

		require.Equal(t, fmt.Sprintf("%d", defaultConfig.FIBMapSize), nd["EVPN_FIB_MAP_SIZE"], "FIB map size should be set in node defines")

		// Insert an entry to ensure the entry is preserved across restarts
		err = fib.Update(key, val)
		require.NoError(t, err, "fib.Update")

		require.NoError(t, h.Stop(log, ctx), "h.Stop")
		require.FileExists(t, fibPath, "FIB map pin should exist even after Stop")
	})

	// Restart with EVPN enabled, should reuse the pinned FIB map and preserve entries
	t.Run("EVPN enabled, restart should preserve FIB map and entries", func(t *testing.T) {
		h := newHive()
		hive.AddConfigOverride(h, func(cfg *evpnCfg.Config) {
			cfg.Enabled = true
		})
		require.NoError(t, h.Start(log, ctx), "h.Start")

		v, err := fib.Lookup(key)
		require.NoError(t, err, "fib.Lookup")
		require.Equal(t, val, v, "FIB entry should be preserved across restart")

		require.NoError(t, h.Stop(log, ctx), "h.Stop")
	})

	// Restart with FIB map resize, should create a new FIB map
	t.Run("EVPN enabled, restart with FIB map resize should create new FIB map", func(t *testing.T) {
		h := newHive()
		hive.AddConfigOverride(h, func(cfg *evpnCfg.Config) {
			cfg.Enabled = true
		})
		hive.AddConfigOverride(h, func(cfg *Config) {
			cfg.FIBMapSize = defaultConfig.FIBMapSize - 1
		})
		require.NoError(t, h.Start(log, ctx), "h.Start")

		_, err := fib.Lookup(key)
		require.ErrorIs(t, err, ebpf.ErrKeyNotExist, "The map should be recreated due to size change, so the old entry should not exist")

		require.NoError(t, h.Stop(log, ctx), "h.Stop")
	})

	// Disable EVPN, should unpin the FIB map
	t.Run("EVPN disabled, Start should unpin FIB map", func(t *testing.T) {
		h := newHive()
		hive.AddConfigOverride(h, func(cfg *evpnCfg.Config) {
			cfg.Enabled = false
		})
		require.NoError(t, h.Start(log, ctx), "h.Start")

		fibPath, err := fib.Path()
		require.NoError(t, err, "fib.Path")

		require.NoFileExists(t, fibPath, "FIB map pin should not exist")

		require.NoError(t, h.Stop(log, ctx), "h.Stop")
	})
}
