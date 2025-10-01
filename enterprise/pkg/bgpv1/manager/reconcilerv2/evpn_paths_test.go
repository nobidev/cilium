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
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/evpn"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	ciliumhive "github.com/cilium/cilium/pkg/hive"
)

func TestEVPNPathsType5(t *testing.T) {
	var (
		testEVPNDeviceName = "cilium_evpn"
		vni101             = vni.MustFromUint32(101)
		vni102             = vni.MustFromUint32(102)
	)
	tests := []struct {
		name             string
		prefix           netip.Prefix
		vrfInfo          *EvpnVRFInfo
		upsertDevice     *tables.Device
		deleteDevice     *tables.Device
		expectSignal     bool
		expectErr        error
		expectRoutersMAC string
	}{
		{
			name:         "no VRF info",
			prefix:       netip.MustParsePrefix("192.168.0.1/32"),
			vrfInfo:      nil,
			expectSignal: false,
			expectErr:    errMissingEvpnPathInfo,
		},
		{
			name:   "invalid VNI",
			prefix: netip.MustParsePrefix("192.168.0.1/32"),
			vrfInfo: &EvpnVRFInfo{
				VNI: vni.VNI{},
				RD:  DeriveEVPNRouteDistinguisher("1.2.3.4", 1),
				RTs: []string{DeriveEVPNRouteTarget(65001, vni.VNI{})},
			},
			expectSignal: false,
			expectErr:    errInvalidVNI,
		},
		{
			name:   "no RD",
			prefix: netip.MustParsePrefix("192.168.0.1/32"),
			vrfInfo: &EvpnVRFInfo{
				VNI: vni101,
				RTs: []string{DeriveEVPNRouteTarget(65001, vni101)},
			},
			expectSignal: false,
			expectErr:    errMissingRD,
		},
		{
			name:   "no RTs",
			prefix: netip.MustParsePrefix("192.168.0.1/32"),
			vrfInfo: &EvpnVRFInfo{
				VNI: vni101,
				RD:  DeriveEVPNRouteDistinguisher("1.2.3.4", 1),
			},
			expectSignal: false,
			expectErr:    errMissingRTs,
		},
		{
			name:   "no evpn device",
			prefix: netip.MustParsePrefix("192.168.0.1/32"),
			vrfInfo: &EvpnVRFInfo{
				VNI: vni101,
				RD:  DeriveEVPNRouteDistinguisher("1.2.3.4", 1),
				RTs: []string{DeriveEVPNRouteTarget(65001, vni101)},
			},
			expectSignal: false,
			expectErr:    errMissingRoutersMAC,
		},
		{
			name:   "add evpn device, IPv4 path",
			prefix: netip.MustParsePrefix("192.168.0.1/32"),
			vrfInfo: &EvpnVRFInfo{
				VNI: vni101,
				RD:  DeriveEVPNRouteDistinguisher("1.2.3.4", 1),
				RTs: []string{DeriveEVPNRouteTarget(65001, vni101)},
			},
			upsertDevice:     &tables.Device{Index: 1, Name: testEVPNDeviceName, HardwareAddr: tables.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
			expectSignal:     true,
			expectRoutersMAC: "aa:bb:cc:dd:ee:ff",
		},
		{
			name:   "no evpn device, IPv6 path",
			prefix: netip.MustParsePrefix("2001:db8::7334/128"),
			vrfInfo: &EvpnVRFInfo{
				VNI: vni102,
				RD:  DeriveEVPNRouteDistinguisher("1.2.3.4", 2),
				RTs: []string{DeriveEVPNRouteTarget(65001, vni102)},
			},
			deleteDevice: &tables.Device{Index: 1, Name: testEVPNDeviceName, HardwareAddr: tables.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
			expectSignal: true,
			expectErr:    errMissingRoutersMAC,
		},
		{
			name:   "unrelated device, IPv6 path",
			prefix: netip.MustParsePrefix("2001:db8::7334/128"),
			vrfInfo: &EvpnVRFInfo{
				VNI: vni102,
				RD:  DeriveEVPNRouteDistinguisher("1.2.3.4", 2),
				RTs: []string{DeriveEVPNRouteTarget(65001, vni102)},
			},
			upsertDevice: &tables.Device{Index: 2, Name: "unrelated", HardwareAddr: tables.HardwareAddr{0x00, 0xbb, 0xcc, 0xdd, 0xee, 0x11}},
			expectSignal: false,
			expectErr:    errMissingRoutersMAC,
		},
		{
			name:   "add evpn device, IPv6 path",
			prefix: netip.MustParsePrefix("2001:db8::7334/128"),
			vrfInfo: &EvpnVRFInfo{
				VNI: vni102,
				RD:  DeriveEVPNRouteDistinguisher("1.2.3.4", 2),
				RTs: []string{DeriveEVPNRouteTarget(65001, vni102)},
			},
			upsertDevice:     &tables.Device{Index: 1, Name: testEVPNDeviceName, HardwareAddr: tables.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
			expectSignal:     true,
			expectRoutersMAC: "aa:bb:cc:dd:ee:ff",
		},
		{
			name:   "multiple RTs, mac address change, IPv6 path",
			prefix: netip.MustParsePrefix("2001:db8::7334/128"),
			vrfInfo: &EvpnVRFInfo{
				VNI: vni102,
				RD:  DeriveEVPNRouteDistinguisher("1.2.3.4", 2),
				RTs: []string{DeriveEVPNRouteTarget(65001, vni102), DeriveEVPNRouteTarget(65001, vni102)},
			},
			upsertDevice:     &tables.Device{Index: 1, Name: testEVPNDeviceName, HardwareAddr: tables.HardwareAddr{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa}},
			expectSignal:     true,
			expectRoutersMAC: "ff:ee:dd:cc:bb:aa",
		},
	}

	var (
		db          *statedb.DB
		deviceTable statedb.RWTable[*tables.Device]
		paths       *evpnPaths
		bgpSignaler *signaler.BGPCPSignaler
	)

	// start test hive
	hive := ciliumhive.New(
		cell.Module("evpn-paths-test", "EVPN paths test",
			cell.Provide(
				signaler.NewBGPCPSignaler,

				tables.NewDeviceTable,
				statedb.RWTable[*tables.Device].ToTable,

				func() evpn.Config {
					return evpn.Config{
						CommonConfig: evpn.CommonConfig{
							Enabled: true,
						},
						VxlanDevice: testEVPNDeviceName,
					}
				},
				func() config.Config {
					return config.Config{
						Enabled: true,
					}
				},
			),
			cell.Invoke(func(database *statedb.DB, table statedb.RWTable[*tables.Device]) {
				db = database
				deviceTable = table
			}),
			cell.Invoke(func(in evpnPathsIn) {
				paths = newEVPNPaths(in)
			}),
			cell.Invoke(func(sig *signaler.BGPCPSignaler) {
				bgpSignaler = sig
			}),
		),
	)
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	err := hive.Start(log, context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		hive.Stop(log, context.Background())
	})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.upsertDevice != nil || test.deleteDevice != nil {
				// update statedb table
				tx := db.WriteTxn(deviceTable)
				if test.upsertDevice != nil {
					_, _, err = deviceTable.Insert(tx, test.upsertDevice)
				} else if test.deleteDevice != nil {
					_, _, err = deviceTable.Delete(tx, test.deleteDevice)
				}
				require.NoError(t, err)
				tx.Commit()
			}
			if test.expectSignal {
				// wait for BGP signal
				select {
				case <-bgpSignaler.Sig:
				case <-t.Context().Done():
					t.Fatalf("missed expected BGP reconciliation signal")
				}
			}

			if test.vrfInfo != nil {
				test.vrfInfo.RoutersMAC = paths.GetEvpnRoutersMAC()
			}
			path, key, err := paths.GetEvpnRT5Path(test.prefix, test.vrfInfo)
			if test.expectErr != nil {
				require.Equal(t, test.expectErr, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, path)
			require.NotNil(t, key)

			require.Equal(t, types.Family{Afi: types.AfiL2VPN, Safi: types.SafiEvpn}, path.Family)

			require.IsType(t, &bgp.EVPNNLRI{}, path.NLRI)
			nlri := path.NLRI.(*bgp.EVPNNLRI)
			require.EqualValues(t, bgp.EVPN_IP_PREFIX, nlri.RouteType)
			require.IsType(t, &bgp.EVPNIPPrefixRoute{}, nlri.RouteTypeData)

			type5 := nlri.RouteTypeData.(*bgp.EVPNIPPrefixRoute)
			require.Equal(t, test.vrfInfo.RD, type5.RD.String())
			require.Equal(t, test.vrfInfo.VNI.AsUint32(), type5.Label)

			var (
				gotEncap   bool
				rts        []string
				routersMac string
			)
			for _, pa := range path.PathAttributes {
				if pa.GetType() == bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES {
					for _, extComm := range pa.(*bgp.PathAttributeExtendedCommunities).Value {
						_, subType := extComm.GetTypes()
						if subType == bgp.EC_SUBTYPE_ENCAPSULATION {
							encap := extComm.(*bgp.EncapExtended)
							require.Equal(t, bgp.TUNNEL_TYPE_VXLAN, encap.TunnelType)
							gotEncap = true
						}
						if subType == bgp.EC_SUBTYPE_ROUTE_TARGET {
							rt := extComm.(*bgp.TwoOctetAsSpecificExtended)
							rts = append(rts, fmt.Sprintf("%d:%d", rt.AS, rt.LocalAdmin))
						}
						if subType == bgp.EC_SUBTYPE_ROUTER_MAC {
							rm := extComm.(*bgp.RouterMacExtended)
							routersMac = rm.Mac.String()
						}
					}
				}
			}
			require.True(t, gotEncap)
			require.Equal(t, test.vrfInfo.RTs, rts)
			require.Equal(t, test.expectRoutersMAC, routersMac)
		})
	}
}
