//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dataplane

import (
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/rib"
	srv6Types "github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/maps/srv6map"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

type DataPlane struct {
	policyMap4 policyMap
	sidMap     sidMap
}

// Ensure DataPlane implements rib.DataPlane interface
var _ rib.DataPlane = &DataPlane{}

type in struct {
	cell.In

	DaemonConfig *option.DaemonConfig
	PolicyMap4   *srv6map.PolicyMap4
	SIDMap       *srv6map.SIDMap
}

// TODO: Make srv6map package mockable
type policyMap interface {
	Update(k *srv6map.PolicyKey, v types.IPv6) error
	Delete(k *srv6map.PolicyKey) error
	IterateWithCallback(cb srv6map.SRv6PolicyIterateCallback) error
}

// TODO: Make srv6map package mockable
type sidMap interface {
	Update(k *srv6map.SIDKey, vrfID uint32) error
	Delete(k *srv6map.SIDKey) error
	IterateWithCallback(cb srv6map.SRv6SIDIterateCallback) error
}

func New(in in) rib.DataPlaneOut {
	if !in.DaemonConfig.EnableSRv6 {
		return rib.DataPlaneOut{
			DataPlane: nil,
		}
	}
	return rib.DataPlaneOut{
		DataPlane: &DataPlane{
			policyMap4: in.PolicyMap4,
			sidMap:     in.SIDMap,
		},
	}
}

func (dp *DataPlane) ProcessUpdate(u *rib.RIBUpdate) {
	// Currently, we can only handle IPv4 prefix written to the specific
	// VRF with H.Encaps nexthop and IPv6 prefix written to the default VRF
	// with EndDT4 nexthop. These combinations are what we can guarantee to
	// be valid with our current dataplane implementation. Note that we
	// don't support IPv6 prefix written to the written to the specific VRF
	// with H.Encaps nexthop because we only have partial implementation.
	if u.VRFID == 0 {
		if dp.isUpsert(u) {
			if !u.NewBest.Prefix.Addr().Is6() {
				return
			}
			if _, ok := u.NewBest.NextHop.(*rib.EndDT4); !ok {
				return
			}
			dp.upsertEndDT4(u)
		} else {
			if !u.OldBest.Prefix.Addr().Is6() {
				return
			}
			if _, ok := u.OldBest.NextHop.(*rib.EndDT4); !ok {
				return
			}
			dp.deleteEndDT4(u)
		}
	} else {
		if dp.isUpsert(u) {
			if _, ok := u.NewBest.NextHop.(*rib.HEncaps); !ok {
				return
			}
			if !u.NewBest.Prefix.Addr().Is4() {
				return
			}
			dp.upsertHEncaps(dp.policyMap4, u)
		} else {
			if _, ok := u.OldBest.NextHop.(*rib.HEncaps); !ok {
				return
			}
			if !u.OldBest.Prefix.Addr().Is4() {
				return
			}
			dp.deleteHEncaps(dp.policyMap4, u)
		}
	}
}

func (dp *DataPlane) upsertHEncaps(m policyMap, u *rib.RIBUpdate) {
	hEncaps := u.NewBest.NextHop.(*rib.HEncaps)
	if len(hEncaps.Segments) != 1 {
		// We don't support empty or multiple segments in HEncaps now
		return
	}
	if err := m.Update(
		dp.parseHEncapsRoute(u.VRFID, u.NewBest),
		hEncaps.Segments[0].As16(),
	); err != nil {
		return
	}
}

func (dp *DataPlane) deleteHEncaps(m policyMap, u *rib.RIBUpdate) {
	if err := m.Delete(
		dp.parseHEncapsRoute(u.VRFID, u.OldBest),
	); err != nil {
		return
	}
}

func (dp *DataPlane) parseHEncapsRoute(vrfID uint32, rt *rib.Route) *srv6map.PolicyKey {
	return &srv6map.PolicyKey{
		VRFID:    vrfID,
		DestCIDR: rt.Prefix,
	}
}

func (dp *DataPlane) upsertEndDT4(u *rib.RIBUpdate) {
	k, v := dp.parseEndDT4Route(u.NewBest)
	if v == 0 {
		// We don't support End.DT4 for default VRF now
		return
	}
	if err := dp.sidMap.Update(k, v); err != nil {
		return
	}
}

func (dp *DataPlane) deleteEndDT4(u *rib.RIBUpdate) {
	k, _ := dp.parseEndDT4Route(u.OldBest)
	if err := dp.sidMap.Delete(k); err != nil {
		return
	}
}

func (dp *DataPlane) parseEndDT4Route(rt *rib.Route) (*srv6map.SIDKey, uint32) {
	endDT4 := rt.NextHop.(*rib.EndDT4)
	return &srv6map.SIDKey{
		SID: rt.Prefix.Addr().As16(),
	}, endDT4.VRFID
}

func (dp *DataPlane) isUpsert(u *rib.RIBUpdate) bool {
	return (u.OldBest == nil && u.NewBest != nil) || (u.OldBest != nil && u.NewBest != nil)
}

func (dp *DataPlane) ForEach(cb func(uint32, *rib.Route)) {
	dp.policyMap4.IterateWithCallback(func(k *srv6map.PolicyKey, v *srv6map.PolicyValue) {
		cb(
			k.VRFID,
			&rib.Route{
				Prefix:   k.DestCIDR,
				Owner:    rib.OwnerUnknown,
				Protocol: rib.ProtocolUnknown,
				NextHop: &rib.HEncaps{
					Segments: []srv6Types.SID{
						{Addr: v.SID.Addr()},
					},
				},
			},
		)
	})
	dp.sidMap.IterateWithCallback(func(k *srv6map.SIDKey, v *srv6map.SIDValue) {
		cb(
			0,
			&rib.Route{
				Prefix:   netip.PrefixFrom(k.SID.Addr(), 128),
				Owner:    rib.OwnerUnknown,
				Protocol: rib.ProtocolUnknown,
				NextHop: &rib.EndDT4{
					VRFID: v.VRFID,
				},
			},
		)
	})
}
