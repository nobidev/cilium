//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package datapath

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	evpnCfg "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	evpnMaps "github.com/cilium/cilium/enterprise/pkg/maps/evpn"
	"github.com/cilium/cilium/enterprise/pkg/rib"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedRIBDataPlane(t *testing.T) {
	testutils.PrivilegedTest(t)

	var (
		RIB *rib.RIB
		FIB evpnMaps.FIB
	)

	Hive := hive.New(
		evpnCfg.Cell,
		rib.Cell,
		evpnMaps.Cell,
		cell.Provide(
			func() tunnel.EncapProtocol {
				return tunnel.VXLAN
			},
			tunnel.NewTestConfig,
			newRIBDataPlane,
		),
		cell.Invoke(func(_RIB *rib.RIB, _FIB evpnMaps.FIB) {
			RIB = _RIB
			FIB = _FIB
		}),
	)

	hive.AddConfigOverride(Hive, func(cfg *evpnCfg.Config) {
		cfg.Enabled = true
	})

	logger := hivetest.Logger(t)

	err := Hive.Start(logger, t.Context())
	require.NoError(t, err, "hive.Start")

	t.Cleanup(func() {
		FIB.UnpinIfExists()
		Hive.Stop(logger, t.Context())
	})

	steps := []struct {
		name                string
		ribOp               func()
		expectedMapElements []evpnMaps.FIBKeyVal
	}{
		{
			name: "IPv4: Create route, should be added to FIB map",
			ribOp: func() {
				RIB.UpsertRoute(1, rib.Route{
					Prefix:   netip.MustParsePrefix("10.0.0.0/24"),
					Owner:    "test-owner0",
					Protocol: rib.ProtocolIBGP,
					NextHop: &rib.VXLANEncap{
						VNI:         vni.MustFromUint32(100),
						VTEPIP:      netip.MustParseAddr("192.168.0.1"),
						InnerDstMAC: net.HardwareAddr(mac.MustParseMAC("aa:bb:cc:dd:ee:ff")),
					},
				})
			},
			expectedMapElements: []evpnMaps.FIBKeyVal{
				{
					Key: evpnMaps.MustNewFIBKey(1, netip.MustParsePrefix("10.0.0.0/24")),
					Val: evpnMaps.MustNewFIBVal(
						vni.MustFromUint32(100),
						mac.MustParseMAC("aa:bb:cc:dd:ee:ff"),
						netip.MustParseAddr("192.168.0.1"),
					),
				},
			},
		},
		{
			name: "IPv4: Create non-VXLAN route, should not be added to FIB map",
			ribOp: func() {
				RIB.UpsertRoute(2, rib.Route{
					Prefix:   netip.MustParsePrefix("10.0.0.0/24"),
					Owner:    "test-owner0",
					Protocol: rib.ProtocolIBGP,
					NextHop: &rib.EndDT4{
						VRFID: 1,
					},
				})
			},
			// Exactly the same as before
			expectedMapElements: []evpnMaps.FIBKeyVal{
				{
					Key: evpnMaps.MustNewFIBKey(1, netip.MustParsePrefix("10.0.0.0/24")),
					Val: evpnMaps.MustNewFIBVal(
						vni.MustFromUint32(100),
						mac.MustParseMAC("aa:bb:cc:dd:ee:ff"),
						netip.MustParseAddr("192.168.0.1"),
					),
				},
			},
		},
		{
			name: "IPv4: Update route, should update FIB map",
			ribOp: func() {
				RIB.UpsertRoute(1, rib.Route{
					Prefix:   netip.MustParsePrefix("10.0.0.0/24"),
					Owner:    "test-owner1",
					Protocol: rib.ProtocolEBGP,
					NextHop: &rib.VXLANEncap{
						VNI:         vni.MustFromUint32(200),
						VTEPIP:      netip.MustParseAddr("fd00::1"),
						InnerDstMAC: net.HardwareAddr(mac.MustParseMAC("ff:ee:dd:cc:bb:aa")),
					},
				})
			},
			expectedMapElements: []evpnMaps.FIBKeyVal{
				{
					Key: evpnMaps.MustNewFIBKey(1, netip.MustParsePrefix("10.0.0.0/24")),
					Val: evpnMaps.MustNewFIBVal(
						vni.MustFromUint32(200),
						mac.MustParseMAC("ff:ee:dd:cc:bb:aa"),
						netip.MustParseAddr("fd00::1"),
					),
				},
			},
		},
		{
			name: "IPv4: Delete the current best route, should replace the FIB map element",
			ribOp: func() {
				RIB.DeleteRoute(1, rib.Route{
					Prefix: netip.MustParsePrefix("10.0.0.0/24"),
					Owner:  "test-owner1",
				})
			},
			expectedMapElements: []evpnMaps.FIBKeyVal{
				{
					Key: evpnMaps.MustNewFIBKey(1, netip.MustParsePrefix("10.0.0.0/24")),
					Val: evpnMaps.MustNewFIBVal(
						vni.MustFromUint32(100),
						mac.MustParseMAC("aa:bb:cc:dd:ee:ff"),
						netip.MustParseAddr("192.168.0.1"),
					),
				},
			},
		},
		{
			name: "IPv4: Delete the current best route again, should remove the FIB map element",
			ribOp: func() {
				RIB.DeleteRoute(1, rib.Route{
					Prefix: netip.MustParsePrefix("10.0.0.0/24"),
					Owner:  "test-owner0",
				})
			},
			expectedMapElements: []evpnMaps.FIBKeyVal{},
		},

		// Same scenario with IPv6
		{
			name: "IPv6: Create route, should be added to FIB map",
			ribOp: func() {
				RIB.UpsertRoute(1, rib.Route{
					Prefix:   netip.MustParsePrefix("fd00::/64"),
					Owner:    "test-owner0",
					Protocol: rib.ProtocolIBGP,
					NextHop: &rib.VXLANEncap{
						VNI:         vni.MustFromUint32(100),
						VTEPIP:      netip.MustParseAddr("2001:db8::1"),
						InnerDstMAC: net.HardwareAddr(mac.MustParseMAC("aa:bb:cc:dd:ee:ff")),
					},
				})
			},
			expectedMapElements: []evpnMaps.FIBKeyVal{
				{
					Key: evpnMaps.MustNewFIBKey(1, netip.MustParsePrefix("fd00::/64")),
					Val: evpnMaps.MustNewFIBVal(
						vni.MustFromUint32(100),
						mac.MustParseMAC("aa:bb:cc:dd:ee:ff"),
						netip.MustParseAddr("2001:db8::1"),
					),
				},
			},
		},
		{
			name: "IPv6: Create non-VXLAN route, should not be added to FIB map",
			ribOp: func() {
				RIB.UpsertRoute(2, rib.Route{
					Prefix:   netip.MustParsePrefix("fd00::/64"),
					Owner:    "test-owner0",
					Protocol: rib.ProtocolIBGP,
					NextHop: &rib.EndDT4{
						VRFID: 1,
					},
				})
			},
			// Exactly the same as before
			expectedMapElements: []evpnMaps.FIBKeyVal{
				{
					Key: evpnMaps.MustNewFIBKey(1, netip.MustParsePrefix("fd00::/64")),
					Val: evpnMaps.MustNewFIBVal(
						vni.MustFromUint32(100),
						mac.MustParseMAC("aa:bb:cc:dd:ee:ff"),
						netip.MustParseAddr("2001:db8::1"),
					),
				},
			},
		},
		{
			name: "IPv6: Update route, should update FIB map",
			ribOp: func() {
				RIB.UpsertRoute(1, rib.Route{
					Prefix:   netip.MustParsePrefix("fd00::/64"),
					Owner:    "test-owner1",
					Protocol: rib.ProtocolEBGP,
					NextHop: &rib.VXLANEncap{
						VNI:         vni.MustFromUint32(200),
						VTEPIP:      netip.MustParseAddr("10.0.0.1"),
						InnerDstMAC: net.HardwareAddr(mac.MustParseMAC("ff:ee:dd:cc:bb:aa")),
					},
				})
			},
			expectedMapElements: []evpnMaps.FIBKeyVal{
				{
					Key: evpnMaps.MustNewFIBKey(1, netip.MustParsePrefix("fd00::/64")),
					Val: evpnMaps.MustNewFIBVal(
						vni.MustFromUint32(200),
						mac.MustParseMAC("ff:ee:dd:cc:bb:aa"),
						netip.MustParseAddr("10.0.0.1"),
					),
				},
			},
		},
		{
			name: "IPv6: Delete the current best route, should replace the FIB map element",
			ribOp: func() {
				RIB.DeleteRoute(1, rib.Route{
					Prefix: netip.MustParsePrefix("fd00::/64"),
					Owner:  "test-owner1",
				})
			},
			expectedMapElements: []evpnMaps.FIBKeyVal{
				{
					Key: evpnMaps.MustNewFIBKey(1, netip.MustParsePrefix("fd00::/64")),
					Val: evpnMaps.MustNewFIBVal(
						vni.MustFromUint32(100),
						mac.MustParseMAC("aa:bb:cc:dd:ee:ff"),
						netip.MustParseAddr("2001:db8::1"),
					),
				},
			},
		},
		{
			name: "IPv6: Delete the current best route again, should remove the FIB map element",
			ribOp: func() {
				RIB.DeleteRoute(1, rib.Route{
					Prefix: netip.MustParsePrefix("fd00::/64"),
					Owner:  "test-owner0",
				})
			},
			expectedMapElements: []evpnMaps.FIBKeyVal{},
		},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			step.ribOp()
			elems, err := FIB.List()
			require.NoError(t, err, "FIB.List")
			require.ElementsMatch(t, step.expectedMapElements, elems, "FIB map elements mismatch")
		})
	}
}
