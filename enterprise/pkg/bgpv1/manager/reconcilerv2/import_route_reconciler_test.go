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
	"net"
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgp/types"
)

func TestRouteImportReconcilerParseV4Path(t *testing.T) {
	nlri := bgp.NewIPAddrPrefix(24, "10.0.0.0")

	tests := []struct {
		name        string
		inputPath   *types.Path
		outputPath  *path
		expectedErr error
	}{
		{
			name: "Valid IPv4 NEXT_HOP",
			inputPath: &types.Path{
				NLRI: nlri,
				PathAttributes: []bgp.PathAttributeInterface{
					bgp.NewPathAttributeNextHop("192.168.0.1"),
				},
				Family: types.Family{
					Afi:  types.AfiIPv4,
					Safi: types.SafiUnicast,
				},
				SourceASN: 65000,
			},
			outputPath: &path{
				prefix:  netip.MustParsePrefix("10.0.0.0/24"),
				nexthop: netip.MustParseAddr("192.168.0.1"),
				isIBGP:  true,
			},
		},
		{
			name: "Valid IPv4 MP_REACH_NLRI",
			inputPath: &types.Path{
				NLRI: nlri,
				PathAttributes: []bgp.PathAttributeInterface{
					bgp.NewPathAttributeMpReachNLRI(
						"192.168.0.1",
						[]bgp.AddrPrefixInterface{
							nlri,
						},
					),
				},
				Family: types.Family{
					Afi:  types.AfiIPv4,
					Safi: types.SafiUnicast,
				},
				SourceASN: 65000,
			},
			outputPath: &path{
				prefix:  netip.MustParsePrefix("10.0.0.0/24"),
				nexthop: netip.MustParseAddr("192.168.0.1"),
				isIBGP:  true,
			},
		},
		{
			name: "Invalid missing required attributes",
			inputPath: &types.Path{
				NLRI:           nlri,
				PathAttributes: []bgp.PathAttributeInterface{},
				Family: types.Family{
					Afi:  types.AfiIPv4,
					Safi: types.SafiUnicast,
				},
				SourceASN: 65000,
			},
			expectedErr: errMalformedPath,
		},
		{
			name: "Unsupported v6 nexthop NEXT_HOP",
			inputPath: &types.Path{
				NLRI: nlri,
				PathAttributes: []bgp.PathAttributeInterface{
					bgp.NewPathAttributeNextHop("fd00::1"),
				},
				Family: types.Family{
					Afi:  types.AfiIPv4,
					Safi: types.SafiUnicast,
				},
				SourceASN: 65000,
			},
			expectedErr: errUnsupportedNexthop,
		},
		{
			name: "Unsupported v6 nexthop MP_REACH_NLRI (RFC8960)",
			inputPath: &types.Path{
				NLRI: nlri,
				PathAttributes: []bgp.PathAttributeInterface{
					bgp.NewPathAttributeMpReachNLRI(
						"fd00::1",
						[]bgp.AddrPrefixInterface{
							nlri,
						},
					),
				},
				Family: types.Family{
					Afi:  types.AfiIPv4,
					Safi: types.SafiUnicast,
				},
				SourceASN: 65000,
			},
			expectedErr: errUnsupportedNexthop,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler := &importRouteReconciler{}
			parsedPath, err := reconciler.parseV4Path(tt.inputPath, 65000)
			if tt.expectedErr != nil {
				require.ErrorIs(t, tt.expectedErr, err)
			} else {
				require.Equal(t, tt.outputPath, parsedPath, "Unexpected result (error=%s)", err)
			}
		})
	}
}

func TestRouteImportReconcilerParseV6Path(t *testing.T) {
	nlri := bgp.NewIPv6AddrPrefix(64, "fd00::")
	mpReachNLRIGlobalOnly := bgp.NewPathAttributeMpReachNLRI(
		"2001:db8::1",
		[]bgp.AddrPrefixInterface{
			nlri,
		},
	)

	mpReachNLRIGlobalAndLinkLocal := bgp.NewPathAttributeMpReachNLRI(
		"2001:db8::1",
		[]bgp.AddrPrefixInterface{
			nlri,
		},
	)
	mpReachNLRIGlobalAndLinkLocal.LinkLocalNexthop = net.ParseIP("fe80::1")

	tests := []struct {
		name        string
		inputPath   *types.Path
		outputPath  *path
		expectedErr error
	}{
		{
			name: "Valid IPv6 MP_REACH_NLRI global only",
			inputPath: &types.Path{
				NLRI: nlri,
				PathAttributes: []bgp.PathAttributeInterface{
					mpReachNLRIGlobalOnly,
				},
				Family: types.Family{
					Afi:  types.AfiIPv6,
					Safi: types.SafiUnicast,
				},
				SourceASN: 65000,
			},
			outputPath: &path{
				prefix:  netip.MustParsePrefix("fd00::/64"),
				nexthop: netip.MustParseAddr("2001:db8::1"),
				isIBGP:  true,
			},
		},
		{
			name: "Valid IPv6 MP_REACH_NLRI global and link-local",
			inputPath: &types.Path{
				NLRI: nlri,
				PathAttributes: []bgp.PathAttributeInterface{
					mpReachNLRIGlobalAndLinkLocal,
				},
				Family: types.Family{
					Afi:  types.AfiIPv6,
					Safi: types.SafiUnicast,
				},
				SourceASN: 65000,
			},
			outputPath: &path{
				prefix:  netip.MustParsePrefix("fd00::/64"),
				nexthop: netip.MustParseAddr("fe80::1"),
				isIBGP:  true,
			},
		},
		{
			name: "Invalid missing required attributes",
			inputPath: &types.Path{
				NLRI:           nlri,
				PathAttributes: []bgp.PathAttributeInterface{},
				Family: types.Family{
					Afi:  types.AfiIPv6,
					Safi: types.SafiUnicast,
				},
				SourceASN: 65000,
			},
			expectedErr: errMalformedPath,
		},
		{
			name: "Unsupported v4 nexthop MP_REACH_NLRI (non-standard)",
			inputPath: &types.Path{
				NLRI: nlri,
				PathAttributes: []bgp.PathAttributeInterface{
					bgp.NewPathAttributeMpReachNLRI(
						"10.0.0.1",
						[]bgp.AddrPrefixInterface{
							nlri,
						},
					),
				},
				Family: types.Family{
					Afi:  types.AfiIPv6,
					Safi: types.SafiUnicast,
				},
				SourceASN: 65000,
			},
			expectedErr: errUnsupportedNexthop,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler := &importRouteReconciler{}
			parsedPath, err := reconciler.parseV6Path(tt.inputPath, 65000)
			if tt.expectedErr != nil {
				require.ErrorIs(t, tt.expectedErr, err)
			} else {
				require.Equal(t, tt.outputPath, parsedPath, "Unexpected result (error=%s)", err)
			}
		})
	}
}
