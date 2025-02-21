//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllocateEgressIPsForGroup(t *testing.T) {
	testCases := []struct {
		name              string
		cidrs             []netip.Prefix
		gatewaysByAZ      map[string][]netip.Addr
		prevAllocs        map[netip.Addr]netip.Addr
		healthyGatewayIPs []netip.Addr
		expected          map[netip.Addr]netip.Addr
		expectedError     bool
	}{
		{
			name: "no previous allocations",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/29"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				affinityZoneNoZone: {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
			},
			prevAllocs: nil,
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
			},
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.10"),
			},
		},
		{
			name: "with previous allocations",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/29"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				affinityZoneNoZone: {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
			},
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
			},
		},
		{
			name: "with in-active gateways, 10.0.0.2 and 10.0.0.3 are in-active but healthy",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/29"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				affinityZoneNoZone: {
					netip.MustParseAddr("10.0.0.1"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
			},
			// should not release the egress IPs of 10.0.0.2 and 10.0.0.3
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
			},
		},
		{
			name: "no enough address with in-active gateways",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/30"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				affinityZoneNoZone: {
					netip.MustParseAddr("10.0.0.1"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.11"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
			},
			// It should release the egress IPs 10.0.0.5: 192.168.0.11 and allocate it to an active gateway 10.0.0.1
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.11"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.10"),
			},
			expectedError: true,
		},
		{
			name: "with affinity zones",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/29"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.3"),
					netip.MustParseAddr("10.0.0.4"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.12"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.13"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
				netip.MustParseAddr("10.0.0.6"),
			},
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.12"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.13"),
				netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
			},
		},
		{
			name: "in-active gateways with affinity zones, 10.0.0.4, 10.0.0.5 and 10.0.0.6 are in-active but healthy",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/29"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.3"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.12"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.13"),
				netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
				netip.MustParseAddr("10.0.0.6"),
			},
			// should not release the egress IPs of 10.0.0.4, 10.0.0.5 and 10.0.0.6
			// The allocation priority is in the order of zone2(the number of alloc is 0),
			// then zone1(the number of alloc is 1(10.0.0.2: 192.168.0.12 from provAllocs)).
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.12"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.13"),
				netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
			},
		},
		{
			name: "not enough addresses",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/30"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.3"),
					netip.MustParseAddr("10.0.0.4"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
				netip.MustParseAddr("10.0.0.6"),
			},
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.11"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
			},
			expectedError: true,
		},
		{
			name: "rebalanced allocations",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/30"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.3"),
					netip.MustParseAddr("10.0.0.4"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.11"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
				netip.MustParseAddr("10.0.0.6"),
			},
			// zone-1 should give up an address in favor of zone-3
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.11"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.9"),
			},
			expectedError: true,
		},
		{
			name: "rebalanced allocations using egress IPs of inactive gateways",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/30"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.3"),
					netip.MustParseAddr("10.0.0.4"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.7"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.8"): netip.MustParseAddr("192.168.0.11"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
				netip.MustParseAddr("10.0.0.6"),
				netip.MustParseAddr("10.0.0.7"),
				netip.MustParseAddr("10.0.0.8"),
			},
			// It should release egress IPs for inactive gateways(10.0.0.7: 192.168.0.10, 10.0.0.8: 192.168.0.11)
			// and allocates them to zone-2 and zone-3
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.11"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
			},
			expectedError: true,
		},
		{
			name: "allocations not rebalanced",
			cidrs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.8/31"),
			},
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.3"),
					netip.MustParseAddr("10.0.0.4"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
				},
			},
			prevAllocs: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
			},
			healthyGatewayIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
				netip.MustParseAddr("10.0.0.6"),
			},
			// not enough addresses to cover all zones, thus no rebalance
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := newPool(tc.cidrs...)
			require.NoErrorf(t, err, "unexpected error while creating pool for CIDRs %v", tc.cidrs)

			allocs, err := allocateEgressIPsForGroup(pool, tc.gatewaysByAZ, tc.prevAllocs, tc.healthyGatewayIPs)
			if !tc.expectedError {
				require.NoErrorf(t, err, "unexpected error while allocating egress IPs")
			} else {
				require.Errorf(t, err, "expected error while allocating egress IPs, got nil")
			}

			require.Equal(t, tc.expected, allocs)
		})
	}
}

type expectedValues struct {
	allocsByAZ                  map[string]map[netip.Addr]netip.Addr
	egressIPsOfInactiveGateways map[netip.Addr]netip.Addr
}

func TestEnsureZonesCoverage(t *testing.T) {
	testCases := []struct {
		name                        string
		gatewaysByAZ                map[string][]netip.Addr
		egressIPsByAZ               map[string]map[netip.Addr]netip.Addr
		egressIPsOfInactiveGateways map[netip.Addr]netip.Addr
		expected                    expectedValues
	}{
		{
			name: "one zone to cover",
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"),
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
					netip.MustParseAddr("10.0.0.7"),
					netip.MustParseAddr("10.0.0.8"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.9"),
					netip.MustParseAddr("10.0.0.10"),
				},
			},
			egressIPsByAZ: map[string]map[netip.Addr]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
					netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
					netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
					netip.MustParseAddr("10.0.0.7"): netip.MustParseAddr("192.168.0.12"),
				},
				"zone-3": {},
			},
			egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{},
			expected: expectedValues{
				allocsByAZ: map[string]map[netip.Addr]netip.Addr{
					"zone-1": {
						netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
					},
					"zone-2": {
						netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
						netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
						netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
					},
					"zone-3": {
						netip.MustParseAddr("10.0.0.9"): netip.MustParseAddr("192.168.0.12"),
					},
				},
				egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{},
			},
		},
		{
			name: "one zone to cover using an egressIP of inactive gateway",
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"),
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
					netip.MustParseAddr("10.0.0.7"),
					netip.MustParseAddr("10.0.0.8"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.9"),
					netip.MustParseAddr("10.0.0.10"),
				},
			},
			egressIPsByAZ: map[string]map[netip.Addr]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
					netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
					netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
					netip.MustParseAddr("10.0.0.7"): netip.MustParseAddr("192.168.0.12"),
				},
				"zone-3": {},
			},
			egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.11"): netip.MustParseAddr("192.168.0.13"),
				netip.MustParseAddr("10.0.0.12"): netip.MustParseAddr("192.168.0.14"),
			},
			expected: expectedValues{
				allocsByAZ: map[string]map[netip.Addr]netip.Addr{
					"zone-1": {
						netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
					},
					"zone-2": {
						netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
						netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
						netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
						netip.MustParseAddr("10.0.0.7"): netip.MustParseAddr("192.168.0.12"),
					},
					"zone-3": {
						netip.MustParseAddr("10.0.0.9"): netip.MustParseAddr("192.168.0.14"),
					},
				},
				egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{
					netip.MustParseAddr("10.0.0.11"): netip.MustParseAddr("192.168.0.13"),
				},
			},
		},
		{
			name: "multiple zones to cover",
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"),
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
					netip.MustParseAddr("10.0.0.7"),
					netip.MustParseAddr("10.0.0.8"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.9"),
					netip.MustParseAddr("10.0.0.10"),
				},
				"zone-4": {
					netip.MustParseAddr("10.0.0.11"),
					netip.MustParseAddr("10.0.0.12"),
				},
				"zone-5": {
					netip.MustParseAddr("10.0.0.13"),
					netip.MustParseAddr("10.0.0.14"),
				},
				"zone-6": {
					netip.MustParseAddr("10.0.0.15"),
					netip.MustParseAddr("10.0.0.16"),
					netip.MustParseAddr("10.0.0.17"),
					netip.MustParseAddr("10.0.0.18"),
				},
			},
			egressIPsByAZ: map[string]map[netip.Addr]netip.Addr{
				"zone-1": {},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
					netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
					netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
					netip.MustParseAddr("10.0.0.7"): netip.MustParseAddr("192.168.0.12"),
					netip.MustParseAddr("10.0.0.8"): netip.MustParseAddr("192.168.0.13"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.9"): netip.MustParseAddr("192.168.0.14"),
				},
				"zone-4": {},
				"zone-5": {
					netip.MustParseAddr("10.0.0.13"): netip.MustParseAddr("192.168.0.15"),
				},
				"zone-6": {},
			},
			egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{},
			expected: expectedValues{
				allocsByAZ: map[string]map[netip.Addr]netip.Addr{
					"zone-1": {
						netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.13"),
					},
					"zone-2": {
						netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
						netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
					},
					"zone-3": {
						netip.MustParseAddr("10.0.0.9"): netip.MustParseAddr("192.168.0.14"),
					},
					"zone-4": {
						netip.MustParseAddr("10.0.0.11"): netip.MustParseAddr("192.168.0.12"),
					},
					"zone-5": {
						netip.MustParseAddr("10.0.0.13"): netip.MustParseAddr("192.168.0.15"),
					},
					"zone-6": {
						netip.MustParseAddr("10.0.0.15"): netip.MustParseAddr("192.168.0.11"),
					},
				},
				egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{},
			},
		},
		{
			name: "multiple zones to cover using egressIPs of inactive gateway",
			gatewaysByAZ: map[string][]netip.Addr{
				"zone-1": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"),
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("10.0.0.6"),
					netip.MustParseAddr("10.0.0.7"),
					netip.MustParseAddr("10.0.0.8"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.9"),
					netip.MustParseAddr("10.0.0.10"),
				},
				"zone-4": {
					netip.MustParseAddr("10.0.0.11"),
					netip.MustParseAddr("10.0.0.12"),
				},
				"zone-5": {
					netip.MustParseAddr("10.0.0.13"),
					netip.MustParseAddr("10.0.0.14"),
				},
				"zone-6": {
					netip.MustParseAddr("10.0.0.15"),
					netip.MustParseAddr("10.0.0.16"),
					netip.MustParseAddr("10.0.0.17"),
					netip.MustParseAddr("10.0.0.18"),
				},
			},
			egressIPsByAZ: map[string]map[netip.Addr]netip.Addr{
				"zone-1": {},
				"zone-2": {
					netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
					netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
					netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
					netip.MustParseAddr("10.0.0.7"): netip.MustParseAddr("192.168.0.12"),
					netip.MustParseAddr("10.0.0.8"): netip.MustParseAddr("192.168.0.13"),
				},
				"zone-3": {
					netip.MustParseAddr("10.0.0.9"): netip.MustParseAddr("192.168.0.14"),
				},
				"zone-4": {},
				"zone-5": {
					netip.MustParseAddr("10.0.0.13"): netip.MustParseAddr("192.168.0.15"),
				},
				"zone-6": {},
			},
			egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.19"): netip.MustParseAddr("192.168.0.16"),
			},
			expected: expectedValues{
				allocsByAZ: map[string]map[netip.Addr]netip.Addr{
					"zone-1": {
						netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.16"),
					},
					"zone-2": {
						netip.MustParseAddr("10.0.0.4"): netip.MustParseAddr("192.168.0.9"),
						netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
						netip.MustParseAddr("10.0.0.6"): netip.MustParseAddr("192.168.0.11"),
					},
					"zone-3": {
						netip.MustParseAddr("10.0.0.9"): netip.MustParseAddr("192.168.0.14"),
					},
					"zone-4": {
						netip.MustParseAddr("10.0.0.11"): netip.MustParseAddr("192.168.0.13"),
					},
					"zone-5": {
						netip.MustParseAddr("10.0.0.13"): netip.MustParseAddr("192.168.0.15"),
					},
					"zone-6": {
						netip.MustParseAddr("10.0.0.15"): netip.MustParseAddr("192.168.0.12"),
					},
				},
				egressIPsOfInactiveGateways: map[netip.Addr]netip.Addr{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			allocsByAZ, egressIPsOfInactiveGateways := ensureZonesCoverage(tc.gatewaysByAZ, tc.egressIPsByAZ, tc.egressIPsOfInactiveGateways)
			require.Equal(t, tc.expected.allocsByAZ, allocsByAZ)
			require.Equal(t, tc.expected.egressIPsOfInactiveGateways, egressIPsOfInactiveGateways)
		})
	}
}
