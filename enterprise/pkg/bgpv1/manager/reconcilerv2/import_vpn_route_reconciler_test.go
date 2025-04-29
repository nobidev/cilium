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

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/stretchr/testify/require"
)

// This test covers the most complicated MPReachNLRI parsing logic.
// Rest of the path attribute parsing doesn't have much logic and
// about extracting the values from the path attribute.
func TestParseMPReachNLRI(t *testing.T) {
	tests := []struct {
		name           string
		attr           *bgp.PathAttributeMpReachNLRI
		expectedPrefix netip.Prefix
		expectedLabel  uint32
		expectedError  error
	}{
		{
			name: "VPNv4 NLRI",
			attr: bgp.NewPathAttributeMpReachNLRI(
				"fd00::1",
				[]bgp.AddrPrefixInterface{
					bgp.NewLabeledVPNIPAddrPrefix(
						24, "10.0.0.0",
						bgp.MPLSLabelStack{Labels: []uint32{0x12345}},
						bgp.NewRouteDistinguisherTwoOctetAS(65000, 1),
					),
				},
			),
			expectedPrefix: netip.MustParsePrefix("10.0.0.0/24"),
			expectedLabel:  0x12345,
			expectedError:  nil,
		},
		{
			name: "More than one NLRI",
			attr: bgp.NewPathAttributeMpReachNLRI(
				"fd00::1",
				[]bgp.AddrPrefixInterface{
					bgp.NewLabeledVPNIPAddrPrefix(
						24, "10.0.0.0",
						bgp.MPLSLabelStack{Labels: []uint32{0x12345}},
						bgp.NewRouteDistinguisherTwoOctetAS(65000, 1),
					),
					bgp.NewLabeledVPNIPAddrPrefix(
						24, "20.0.0.0",
						bgp.MPLSLabelStack{Labels: []uint32{0x12345}},
						bgp.NewRouteDistinguisherTwoOctetAS(65000, 1),
					),
				},
			),
			expectedPrefix: netip.Prefix{},
			expectedLabel:  0,
			expectedError:  errUnexpectedNLRI,
		},
		{
			name: "Non-IPv4 AFI",
			attr: bgp.NewPathAttributeMpReachNLRI(
				"fd00::1",
				[]bgp.AddrPrefixInterface{
					bgp.NewIPv6AddrPrefix(64, "fd00::"),
				},
			),
			expectedPrefix: netip.Prefix{},
			expectedLabel:  0,
			expectedError:  errUnexpectedAFI,
		},
		{
			name: "Non-Labeled-VPN SAFI",
			attr: bgp.NewPathAttributeMpReachNLRI(
				"fd00::1",
				[]bgp.AddrPrefixInterface{
					bgp.NewIPAddrPrefix(24, "10.0.0.0"),
				},
			),
			expectedPrefix: netip.Prefix{},
			expectedLabel:  0,
			expectedError:  errUnexpectedSAFI,
		},
		{
			name: "Self-originated route v4",
			attr: bgp.NewPathAttributeMpReachNLRI(
				"0.0.0.0",
				[]bgp.AddrPrefixInterface{
					bgp.NewLabeledVPNIPAddrPrefix(
						24, "10.0.0.0",
						bgp.MPLSLabelStack{Labels: []uint32{0x12345}},
						bgp.NewRouteDistinguisherTwoOctetAS(65000, 1),
					),
				},
			),
			expectedPrefix: netip.Prefix{},
			expectedLabel:  0,
			expectedError:  errSelfOriginatedVPNRoute,
		},
		{
			name: "Self-originated route v6",
			attr: bgp.NewPathAttributeMpReachNLRI(
				"::",
				[]bgp.AddrPrefixInterface{
					bgp.NewLabeledVPNIPAddrPrefix(
						24, "10.0.0.0",
						bgp.MPLSLabelStack{Labels: []uint32{0x12345}},
						bgp.NewRouteDistinguisherTwoOctetAS(65000, 1),
					),
				},
			),
			expectedPrefix: netip.Prefix{},
			expectedLabel:  0,
			expectedError:  errSelfOriginatedVPNRoute,
		},
		{
			name: "More than one label",
			attr: bgp.NewPathAttributeMpReachNLRI(
				"fd00::1",
				[]bgp.AddrPrefixInterface{
					bgp.NewLabeledVPNIPAddrPrefix(
						24, "10.0.0.0",
						bgp.MPLSLabelStack{Labels: []uint32{0x12345, 0x56789}},
						bgp.NewRouteDistinguisherTwoOctetAS(65000, 1),
					),
				},
			),
			expectedPrefix: netip.Prefix{},
			expectedLabel:  0,
			expectedError:  errMoreThanOneLabel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, label, err := parseMPReachNLRI(tt.attr)
			require.Equal(t, tt.expectedPrefix, prefix)
			require.Equal(t, tt.expectedLabel, label)
			require.ErrorIs(t, tt.expectedError, err)
		})
	}
}
