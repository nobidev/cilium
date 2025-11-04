// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

func TestToRoutePolicy(t *testing.T) {
	policy := &v1.BGPImportPolicy{
		Statements: []v1.BGPPolicyStatement{
			{
				Conditions: v1.BGPPolicyConditions{},
				Actions:    v1.BGPPolicyActions{},
			},
		},
	}
	rp := ToRoutePolicy(
		policy,
		"test",
		netip.MustParseAddr("10.0.0.1"),
		types.Family{Afi: types.AfiIPv4, Safi: types.SafiUnicast},
	)
	require.NotNil(t, rp)
	require.Equal(t, "test", rp.Name)
	require.Equal(t, types.RoutePolicyTypeImport, rp.Type)
	require.Len(t, rp.Statements, 1)
}

func TestToRoutePolicyStatement(t *testing.T) {
	statement := v1.BGPPolicyStatement{
		Conditions: v1.BGPPolicyConditions{},
		Actions:    v1.BGPPolicyActions{},
	}
	rps := ToRoutePolicyStatement(
		&statement,
		netip.MustParseAddr("10.0.0.1"),
		types.Family{Afi: types.AfiIPv4, Safi: types.SafiUnicast},
	)
	require.NotNil(t, rps)
}

func TestToRoutePolicyConditions(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		conditions := v1.BGPPolicyConditions{}
		rpc := ToRoutePolicyConditions(
			&conditions,
			netip.MustParseAddr("10.0.0.1"),
			types.Family{Afi: types.AfiIPv4, Safi: types.SafiUnicast},
		)
		require.NotNil(t, rpc)

		// Ensure the neighbors and families are copied without modification
		require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, rpc.MatchNeighbors)
		require.Equal(t, []types.Family{{Afi: types.AfiIPv4, Safi: types.SafiUnicast}}, rpc.MatchFamilies)
	})

	t.Run("PrefixesV4", func(t *testing.T) {
		conditions := v1.BGPPolicyConditions{
			PrefixesV4: &v1.PrefixesV4Condition{
				MatchType: v1.BGPPolicyMatchTypeOr,
				Matches: []v1.PrefixV4Match{
					{
						Prefix: "10.0.0.0/24",
						MaxLen: ptr.To(uint8(32)),
						MinLen: ptr.To(uint8(24)),
					},
				},
			},
		}
		rpc := ToRoutePolicyConditions(
			&conditions,
			netip.MustParseAddr("10.0.0.1"),
			types.Family{Afi: types.AfiIPv4, Safi: types.SafiUnicast},
		)
		require.NotNil(t, rpc)
		require.Len(t, rpc.MatchPrefixes, 1)
		require.Equal(t, netip.MustParsePrefix("10.0.0.0/24"), rpc.MatchPrefixes[0].CIDR)
		require.Equal(t, 32, rpc.MatchPrefixes[0].PrefixLenMax)
		require.Equal(t, 24, rpc.MatchPrefixes[0].PrefixLenMin)
	})

	t.Run("PrefixesV6", func(t *testing.T) {
		conditions := v1.BGPPolicyConditions{
			PrefixesV6: &v1.PrefixesV6Condition{
				MatchType: v1.BGPPolicyMatchTypeOr,
				Matches: []v1.PrefixV6Match{
					{
						Prefix: "fd00::/64",
						MaxLen: ptr.To(uint8(128)),
						MinLen: ptr.To(uint8(64)),
					},
				},
			},
		}
		rpc := ToRoutePolicyConditions(
			&conditions,
			netip.MustParseAddr("2001:db8::1"),
			types.Family{Afi: types.AfiIPv6, Safi: types.SafiUnicast},
		)
		require.NotNil(t, rpc)
		require.Len(t, rpc.MatchPrefixes, 1)
		require.Equal(t, netip.MustParsePrefix("fd00::/64"), rpc.MatchPrefixes[0].CIDR)
		require.Equal(t, 128, rpc.MatchPrefixes[0].PrefixLenMax)
		require.Equal(t, 64, rpc.MatchPrefixes[0].PrefixLenMin)
	})

	t.Run("DualStackPolicy", func(t *testing.T) {
		conditions := v1.BGPPolicyConditions{
			PrefixesV4: &v1.PrefixesV4Condition{
				MatchType: v1.BGPPolicyMatchTypeOr,
				Matches: []v1.PrefixV4Match{
					{
						Prefix: "10.0.0.0/24",
						MaxLen: ptr.To(uint8(32)),
						MinLen: ptr.To(uint8(24)),
					},
				},
			},
			PrefixesV6: &v1.PrefixesV6Condition{
				MatchType: v1.BGPPolicyMatchTypeOr,
				Matches: []v1.PrefixV6Match{
					{
						Prefix: "fd00::/64",
						MaxLen: ptr.To(uint8(128)),
						MinLen: ptr.To(uint8(64)),
					},
				},
			},
		}

		// Test for IPv4 family
		rpc := ToRoutePolicyConditions(
			&conditions,
			netip.MustParseAddr("10.0.0.1"),
			types.Family{Afi: types.AfiIPv4, Safi: types.SafiUnicast},
		)
		require.NotNil(t, rpc)
		require.Len(t, rpc.MatchPrefixes, 1)
		require.Equal(t, netip.MustParsePrefix("10.0.0.0/24"), rpc.MatchPrefixes[0].CIDR)
		require.Equal(t, 32, rpc.MatchPrefixes[0].PrefixLenMax)
		require.Equal(t, 24, rpc.MatchPrefixes[0].PrefixLenMin)

		// Test for IPv6 family
		rpc = ToRoutePolicyConditions(
			&conditions,
			netip.MustParseAddr("fd00::1"),
			types.Family{Afi: types.AfiIPv6, Safi: types.SafiUnicast},
		)
		require.NotNil(t, rpc)
		require.Len(t, rpc.MatchPrefixes, 1)
		require.Equal(t, netip.MustParsePrefix("fd00::/64"), rpc.MatchPrefixes[0].CIDR)
		require.Equal(t, 128, rpc.MatchPrefixes[0].PrefixLenMax)
		require.Equal(t, 64, rpc.MatchPrefixes[0].PrefixLenMin)
	})
}

func TestToRoutePolicyActions(t *testing.T) {
	cases := []struct {
		name           string
		action         v1.BGPRouteAction
		expectedAction types.RoutePolicyAction
	}{
		{
			name:           "Empty => None",
			action:         "",
			expectedAction: types.RoutePolicyActionNone,
		},
		{
			name:           "Unexpected => None",
			action:         "foo",
			expectedAction: types.RoutePolicyActionNone,
		},
		{
			name:           "Accept",
			action:         v1.BGPRouteActionAccept,
			expectedAction: types.RoutePolicyActionAccept,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			actions := v1.BGPPolicyActions{
				RouteAction: tt.action,
			}
			rpa := ToRoutePolicyActions(&actions)
			require.NotNil(t, rpa)
			require.Equal(t, tt.expectedAction, rpa.RouteAction)
		})
	}
}

func TestBGPConditionsValidateAndDefault(t *testing.T) {
	tests := []struct {
		name       string
		conditions v1.BGPPolicyConditions
		family     v2.CiliumBGPFamily
		isInvalid  bool
	}{
		{
			name: "Valid IPv4",
			conditions: v1.BGPPolicyConditions{
				PrefixesV4: &v1.PrefixesV4Condition{
					MatchType: v1.BGPPolicyMatchTypeOr,
					Matches: []v1.PrefixV4Match{
						{
							Prefix: "10.0.0.0/24",
						},
					},
				},
			},
			family:    v2.CiliumBGPFamily{Afi: "ipv4", Safi: "unicast"},
			isInvalid: false,
		},
		{
			name: "Valid IPv6",
			conditions: v1.BGPPolicyConditions{
				PrefixesV6: &v1.PrefixesV6Condition{
					MatchType: v1.BGPPolicyMatchTypeOr,
					Matches: []v1.PrefixV6Match{
						{
							Prefix: "fd00::/64",
						},
					},
				},
			},
			family:    v2.CiliumBGPFamily{Afi: "ipv6", Safi: "unicast"},
			isInvalid: false,
		},
		{
			name:       "Invalid no match",
			conditions: v1.BGPPolicyConditions{},
			family:     v2.CiliumBGPFamily{Afi: "ipv4", Safi: "unicast"},
			isInvalid:  true,
		},
		{
			name: "Invalid IPv4 prefix in IPv6 family, no matching criteria",
			conditions: v1.BGPPolicyConditions{
				PrefixesV4: &v1.PrefixesV4Condition{
					MatchType: v1.BGPPolicyMatchTypeOr,
					Matches: []v1.PrefixV4Match{
						{
							Prefix: "10.0.0.0/24",
						},
					},
				},
			},
			family:    v2.CiliumBGPFamily{Afi: "ipv6", Safi: "unicast"},
			isInvalid: true,
		},
		{
			name: "Invalid IPv6 prefix in IPv4 family, no matching criteria",
			conditions: v1.BGPPolicyConditions{
				PrefixesV6: &v1.PrefixesV6Condition{
					MatchType: v1.BGPPolicyMatchTypeOr,
					Matches: []v1.PrefixV6Match{
						{
							Prefix: "fd00::/64",
						},
					},
				},
			},
			family:    v2.CiliumBGPFamily{Afi: "ipv4", Safi: "unicast"},
			isInvalid: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAndDefaultPolicyConditions(&tt.conditions, tt.family)
			if tt.isInvalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPrefixV4MatchValidateAndDefault(t *testing.T) {
	tests := []struct {
		name       string
		conditions v1.PrefixV4Match
		expected   v1.PrefixV4Match
		isInvalid  bool
	}{
		{
			name: "Valid prefix no min/max",
			conditions: v1.PrefixV4Match{
				Prefix: "10.0.0.0/24",
			},
			expected: v1.PrefixV4Match{
				Prefix: "10.0.0.0/24",
				MaxLen: ptr.To(uint8(24)),
				MinLen: ptr.To(uint8(24)),
			},
			isInvalid: false,
		},
		{
			name: "Valid prefix no min",
			conditions: v1.PrefixV4Match{
				Prefix: "10.0.0.0/24",
				MaxLen: ptr.To(uint8(32)),
			},
			expected: v1.PrefixV4Match{
				Prefix: "10.0.0.0/24",
				MinLen: ptr.To(uint8(32)),
				MaxLen: ptr.To(uint8(32)),
			},
			isInvalid: false,
		},
		{
			name:       "Invalid no prefixes",
			conditions: v1.PrefixV4Match{},
			isInvalid:  true,
		},
		{
			name: "Invalid min greater than max",
			conditions: v1.PrefixV4Match{
				Prefix: "10.0.0.0/24",
				MaxLen: ptr.To(uint8(26)),
				MinLen: ptr.To(uint8(28)),
			},
			isInvalid: true,
		},
		{
			name: "Invalid min greater than max by defaulting",
			conditions: v1.PrefixV4Match{
				Prefix: "10.0.0.0/24",
				// This will become larger than the maxLen
				// which defaults to the prefix length.
				MinLen: ptr.To(uint8(26)),
			},
			isInvalid: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAndDefaultPrefixV4Match(&tt.conditions)
			if tt.isInvalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, tt.conditions)
			}
		})
	}
}

func TestPrefixV6MatchValidateAndDefault(t *testing.T) {
	tests := []struct {
		name       string
		conditions v1.PrefixV6Match
		expected   v1.PrefixV6Match
		isInvalid  bool
	}{
		{
			name: "Valid prefix no min/max",
			conditions: v1.PrefixV6Match{
				Prefix: "fd00::/64",
			},
			expected: v1.PrefixV6Match{
				Prefix: "fd00::/64",
				MaxLen: ptr.To(uint8(64)),
				MinLen: ptr.To(uint8(64)),
			},
			isInvalid: false,
		},
		{
			name: "Valid prefix no min",
			conditions: v1.PrefixV6Match{
				Prefix: "fd00::/64",
				MaxLen: ptr.To(uint8(96)),
			},
			expected: v1.PrefixV6Match{
				Prefix: "fd00::/64",
				MinLen: ptr.To(uint8(96)),
				MaxLen: ptr.To(uint8(96)),
			},
			isInvalid: false,
		},
		{
			name:       "Invalid no prefixes",
			conditions: v1.PrefixV6Match{},
			isInvalid:  true,
		},
		{
			name: "Invalid min greater than max",
			conditions: v1.PrefixV6Match{
				Prefix: "fd00::/64",
				MaxLen: ptr.To(uint8(96)),
				MinLen: ptr.To(uint8(128)),
			},
			isInvalid: true,
		},
		{
			name: "Invalid min greater than max by defaulting",
			conditions: v1.PrefixV6Match{
				Prefix: "fd00::/64",
				// This will become larger than the maxLen
				// which defaults to the prefix length.
				MinLen: ptr.To(uint8(96)),
			},
			isInvalid: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAndDefaultPrefixV6Match(&tt.conditions)
			if tt.isInvalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, tt.conditions)
			}
		})
	}
}
