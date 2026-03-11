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
	"log/slog"
	"net"

	evpnCfg "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	evpnMap "github.com/cilium/cilium/enterprise/pkg/maps/evpn"
	"github.com/cilium/cilium/enterprise/pkg/rib"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
)

// dataPlane implements the rib.DataPlane interface
type dataPlane struct {
	logger *slog.Logger
	fibMap evpnMap.FIB
}

var _ rib.DataPlane = (*dataPlane)(nil)

func newRIBDataPlane(
	logger *slog.Logger,
	config evpnCfg.Config,
	fibMap evpnMap.FIB,
) rib.DataPlaneOut {
	if !config.Enabled {
		return rib.DataPlaneOut{}
	}
	return rib.DataPlaneOut{
		DataPlane: &dataPlane{
			logger: logger,
			fibMap: fibMap,
		},
	}
}

func (dp *dataPlane) ProcessUpdate(u *rib.RIBUpdate) {
	if dp.isUpsert(u) {
		if err := dp.upsertRoute(u); err != nil {
			dp.logger.Warn("Failed to upsert route in EVPN FIB map", logfields.Error, err)
		}
	} else {
		if err := dp.deleteRoute(u); err != nil {
			dp.logger.Warn("Failed to delete route from EVPN FIB map", logfields.Error, err)
		}
	}
}

func (dp *dataPlane) ForEach(cb func(uint32, *rib.Route)) {
	dp.fibMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		fibKey := k.(*evpnMap.FIBKey)
		fibVal := v.(*evpnMap.FIBVal)

		// We cannot restore owners and protocols from the FIB map, so
		// we set them to unknown. The route with unknown owner will be
		// GC'ed eventually if it is not re-added with the correct
		// owner.
		route := &rib.Route{
			Prefix:   fibKey.Prefix(),
			Owner:    rib.OwnerUnknown,
			Protocol: rib.ProtocolUnknown,
		}

		vni, err := vni.FromUint32(fibVal.VNI)
		if err != nil {
			dp.logger.Warn("Failed to parse VNI from FIB map", logfields.Error, err)
			return
		}

		addr := fibVal.Addr()
		if !addr.IsValid() {
			dp.logger.Warn("Failed to parse nexthop address from FIB map", logfields.Family, fibVal.Family)
			return
		}

		route.NextHop = &rib.VXLANEncap{
			VNI:         vni,
			VTEPIP:      addr,
			InnerDstMAC: net.HardwareAddr(fibVal.MAC[:6]),
		}

		cb(uint32(fibKey.NetID), route)
	})
}

func (dp *dataPlane) isUpsert(u *rib.RIBUpdate) bool {
	return (u.OldBest == nil && u.NewBest != nil) || (u.OldBest != nil && u.NewBest != nil)
}

func (dp *dataPlane) upsertRoute(u *rib.RIBUpdate) error {
	nh, ok := u.NewBest.NextHop.(*rib.VXLANEncap)
	if !ok {
		// Skip non-VXLAN routes. We cannot handle it in this dataplane.
		return nil
	}

	k, err := evpnMap.NewFIBKey(uint16(u.VRFID), u.NewBest.Prefix)
	if err != nil {
		return err
	}

	v, err := evpnMap.NewFIBVal(nh.VNI, mac.MAC(nh.InnerDstMAC), nh.VTEPIP)
	if err != nil {
		return err
	}

	if err := dp.fibMap.Update(k, v); err != nil {
		return err
	}

	return nil
}

func (dp *dataPlane) deleteRoute(u *rib.RIBUpdate) error {
	k, err := evpnMap.NewFIBKey(uint16(u.VRFID), u.OldBest.Prefix)
	if err != nil {
		return err
	}
	return dp.fibMap.Delete(k)
}
