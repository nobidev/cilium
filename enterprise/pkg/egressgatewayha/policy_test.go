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
		name          string
		cidrs         []netip.Prefix
		gatewaysByAZ  map[string][]netip.Addr
		prevAllocs    map[netip.Addr]netip.Addr
		expected      map[netip.Addr]netip.Addr
		expectedError bool
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
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.10"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
			},
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
			expected: map[netip.Addr]netip.Addr{
				netip.MustParseAddr("10.0.0.1"): netip.MustParseAddr("192.168.0.8"),
				netip.MustParseAddr("10.0.0.2"): netip.MustParseAddr("192.168.0.11"),
				netip.MustParseAddr("10.0.0.3"): netip.MustParseAddr("192.168.0.9"),
				netip.MustParseAddr("10.0.0.5"): netip.MustParseAddr("192.168.0.10"),
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := newPool(tc.cidrs...)
			require.NoErrorf(t, err, "unexpected error while creating pool for CIDRs %v", tc.cidrs)

			allocs, err := allocateEgressIPsForGroup(pool, tc.gatewaysByAZ, tc.prevAllocs)
			if !tc.expectedError {
				require.NoErrorf(t, err, "unexpected error while allocating egress IPs")
			} else {
				require.Errorf(t, err, "expected error while allocating egress IPs, got nil")
			}

			require.Equal(t, tc.expected, allocs)
		})
	}
}
