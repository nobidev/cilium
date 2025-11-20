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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgp/types"
)

func Test_MergePolicies(t *testing.T) {
	neighbor1 := []netip.Addr{netip.MustParseAddr("192.168.1.1")}

	v4PrefixAExact1 := types.RoutePolicyPrefix{
		CIDR:         netip.MustParsePrefix("10.100.1.1/32"),
		PrefixLenMin: 32,
		PrefixLenMax: 32,
	}

	v4PrefixALen24 := types.RoutePolicyPrefix{
		CIDR:         netip.MustParsePrefix("10.100.1.0/24"),
		PrefixLenMin: 24,
		PrefixLenMax: 24,
	}

	ipv4UnicastFamily := types.Family{
		Afi:  types.AfiIPv4,
		Safi: types.SafiUnicast,
	}

	condition1 := types.RoutePolicyConditions{
		MatchNeighbors: &types.RoutePolicyNeighborMatch{
			Type:      types.RoutePolicyMatchAny,
			Neighbors: neighbor1,
		},
		MatchPrefixes: &types.RoutePolicyPrefixMatch{
			Type:     types.RoutePolicyMatchAny,
			Prefixes: []types.RoutePolicyPrefix{v4PrefixAExact1},
		},
		MatchFamilies: []types.Family{ipv4UnicastFamily},
	}

	condition2 := types.RoutePolicyConditions{
		MatchNeighbors: &types.RoutePolicyNeighborMatch{
			Type:      types.RoutePolicyMatchAny,
			Neighbors: neighbor1,
		},
		MatchPrefixes: &types.RoutePolicyPrefixMatch{
			Type:     types.RoutePolicyMatchAny,
			Prefixes: []types.RoutePolicyPrefix{v4PrefixALen24},
		},
		MatchFamilies: []types.Family{ipv4UnicastFamily},
	}

	action1 := types.RoutePolicyActions{
		RouteAction:    types.RoutePolicyActionAccept,
		AddCommunities: []string{"65000:1"},
	}

	action2 := types.RoutePolicyActions{
		RouteAction:    types.RoutePolicyActionAccept,
		AddCommunities: []string{"65000:2"},
	}

	action3 := types.RoutePolicyActions{
		RouteAction:    types.RoutePolicyActionAccept,
		AddCommunities: []string{"65000:3"},
	}

	mergedAction12 := types.RoutePolicyActions{
		RouteAction:    types.RoutePolicyActionAccept,
		AddCommunities: []string{"65000:1", "65000:2"},
	}

	// statement1 and statement2 have same matching condition but different actions
	// This is the scenario when 2 advertisements match same service but have different
	// community values.
	statement1 := &types.RoutePolicyStatement{
		Conditions: condition1,
		Actions:    action1,
	}

	statement2 := &types.RoutePolicyStatement{
		Conditions: condition1,
		Actions:    action2,
	}

	// statement3 has different matching condition ( prefix length 24)
	statement3 := &types.RoutePolicyStatement{
		Conditions: condition2,
		Actions:    action3,
	}

	mergedStatement12 := &types.RoutePolicyStatement{
		Conditions: condition1,
		Actions:    mergedAction12,
	}

	policy1 := &types.RoutePolicy{
		Name: "policy-A",
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			statement1,
		},
	}

	policy2 := &types.RoutePolicy{
		Name: "policy-A",
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			statement2,
		},
	}

	policy3 := &types.RoutePolicy{
		Name: "policy-A",
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			statement3,
		},
	}

	mergedPolicy12 := &types.RoutePolicy{
		Name: "policy-A",
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			mergedStatement12,
		},
	}

	mergedPolicy123 := &types.RoutePolicy{
		Name: "policy-A",
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			// order of the statements is important, statement3 should come after mergedStatement12
			// since statement3 has a prefix length of 24 compared to 32 in mergedStatement12
			mergedStatement12,
			statement3,
		},
	}

	tests := []struct {
		name           string
		policyA        *types.RoutePolicy
		policyB        *types.RoutePolicy
		expectedError  bool
		expectedPolicy *types.RoutePolicy
	}{
		{
			name:           "nil policies",
			policyA:        nil,
			policyB:        nil,
			expectedError:  true,
			expectedPolicy: nil,
		},
		{
			name:           "merge policies with same prefix",
			policyA:        policy1,
			policyB:        policy2,
			expectedPolicy: mergedPolicy12,
		},
		{
			name:           "merge policies with different prefix lengths",
			policyA:        mergedPolicy12,
			policyB:        policy3,
			expectedPolicy: mergedPolicy123,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			mergedPolicy, err := MergePolicies(tt.policyA, tt.policyB)
			if tt.expectedError {
				req.Error(err)
			} else {
				req.NoError(err)
			}

			req.Equal(tt.expectedPolicy, mergedPolicy)
		})
	}
}
