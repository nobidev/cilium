// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package commands

import (
	"fmt"
	"strings"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
)

// FormatPathAttributes should be used for formatting BGP Path Attributes in CEE commands
// as it decodes some implementation-specific path attributes into a format that is more
// human-friendly than the upstream GoBGP String() methods.
func FormatPathAttributes(pattrs []bgp.PathAttributeInterface) string {
	formatted := make([]string, 0, len(pattrs))
	for _, pa := range pattrs {
		if extComms, ok := pa.(*bgp.PathAttributeExtendedCommunities); ok {
			formatted = append(formatted, formatExtendedCommunities(extComms))
		} else {
			formatted = append(formatted, pa.String())
		}

	}
	return "[" + strings.Join(formatted, " ") + "]"
}

func formatExtendedCommunities(extComms *bgp.PathAttributeExtendedCommunities) string {
	formatted := make([]string, 0, len(extComms.Value))
	for _, extComm := range extComms.Value {
		switch ec := extComm.(type) {
		case *bgp.EncapExtended:
			formatted = append(formatted, formatEncapExtendedCommunity(ec))
		case *bgp.OpaqueExtended:
			formatted = append(formatted, formatOpaqueExtendedCommunity(ec))
		case *bgp.RouterMacExtended:
			formatted = append(formatted, formatRouterMacExtendedCommunity(ec))
		default:
			_, subType := extComm.GetTypes()
			if subType == bgp.EC_SUBTYPE_ROUTE_TARGET {
				formatted = append(formatted, formatRouteTargetExtendedCommunity(extComm))
			} else {
				formatted = append(formatted, extComm.String())
			}
		}
	}
	return "{Extcomms: [" + strings.Join(formatted, "], [") + "]}"
}

func formatEncapExtendedCommunity(e *bgp.EncapExtended) string {
	return fmt.Sprintf("Encap:%s", e.TunnelType.String())
}

func formatRouterMacExtendedCommunity(r *bgp.RouterMacExtended) string {
	return fmt.Sprintf("RouterMAC:%s", r.Mac)
}

func formatOpaqueExtendedCommunity(o *bgp.OpaqueExtended) string {
	if len(o.Value) == 0 {
		return o.String()
	}
	if types.IsGroupPolicyIDExtendedCommunity(o) {
		return formatGroupPolicyIDExtendedCommunity(o)
	}
	trans := "Transitive"
	if !o.IsTransitive {
		trans = "NonTransitive"
	}
	return fmt.Sprintf("Opaque%s:[subtype:%d][value:0x%x]", trans, o.Value[0], o.Value[1:])
}

func formatGroupPolicyIDExtendedCommunity(sgt *bgp.OpaqueExtended) string {
	return fmt.Sprintf("GroupPolicyID:%d", types.GetGroupPolicyIDFromExtendedCommunity(sgt))
}

func formatRouteTargetExtendedCommunity(rt bgp.ExtendedCommunityInterface) string {
	return fmt.Sprintf("RouteTarget:%s", rt.String())
}
