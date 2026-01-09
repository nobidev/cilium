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

	"github.com/stretchr/testify/assert"
)

func parseNetIPs(t *testing.T, ss ...string) []netip.Addr {
	out := []netip.Addr{}
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func Test_computeHealthyGateways(t *testing.T) {
	policyHealthyGatewayIPs := []gatewayNodeIP{
		{
			ip:                    netip.MustParseAddr("10.0.0.1"),
			selectingGroupIndices: []int{0},
			zone:                  true,
			available:             true,
		},
		{
			ip:                    netip.MustParseAddr("10.0.0.2"),
			selectingGroupIndices: []int{3, 2, 1},
			zone:                  true,
			available:             true,
		},
		{
			ip:                    netip.MustParseAddr("10.0.0.3"),
			selectingGroupIndices: []int{},
			zone:                  true,
			available:             false,
		},
		{
			ip:                    netip.MustParseAddr("10.0.0.4"),
			selectingGroupIndices: []int{3, 2, 0},
			zone:                  false,
			available:             true,
		},
	}
	assert.Equal(t, parseNetIPs(t,
		"10.0.0.1", "10.0.0.4"), computeHealthyGateways(policyHealthyGatewayIPs, 0))

}

func Test_computeAvailableHealthyGatewaysByAZ(t *testing.T) {
	policyHealthyGatewayIPs := map[string][]gatewayNodeIP{
		"az-0": {
			{
				ip:                    netip.MustParseAddr("10.0.0.1"),
				selectingGroupIndices: []int{0},
				zone:                  true,
				available:             true,
			},
			{
				ip:                    netip.MustParseAddr("10.0.0.2"),
				selectingGroupIndices: []int{3, 2, 1},
				zone:                  true,
				available:             true,
			},
			{
				ip:                    netip.MustParseAddr("10.0.0.3"),
				selectingGroupIndices: []int{},
				zone:                  true,
				available:             true,
			},
			{
				ip:                    netip.MustParseAddr("10.0.0.4"),
				selectingGroupIndices: []int{3, 2, 0},
				zone:                  false,
				available:             true,
			},
		},
		"az-1": {
			{
				ip:                    netip.MustParseAddr("10.0.0.5"),
				selectingGroupIndices: []int{0, 2, 3},
				zone:                  false,
				available:             true,
			},
		},
	}
	out := computeAvailableHealthyGatewaysByAZ(policyHealthyGatewayIPs, false, 0)
	assert.Equal(t, map[string][]netip.Addr{
		"az-0": parseNetIPs(t, "10.0.0.1", "10.0.0.4"),
		"az-1": parseNetIPs(t, "10.0.0.5"),
	}, out)
	out = computeAvailableHealthyGatewaysByAZ(policyHealthyGatewayIPs, true, 0)
	assert.Equal(t, map[string][]netip.Addr{
		"az-0": parseNetIPs(t, "10.0.0.1"),
		"az-1": {},
	}, out)
}
