// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package gobgp

import (
	"net/netip"
	"testing"
	"time"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
)

func TestToAgentPathsExtended(t *testing.T) {
	validPath, err := apiutil.NewPath(
		bgp.NewIPAddrPrefix(24, "10.0.0.0"),
		false,
		[]bgp.PathAttributeInterface{
			bgp.NewPathAttributeNextHop("192.168.0.1"),
		},
		time.Time{},
	)
	require.NoError(t, err)

	invalidPath, err := apiutil.NewPath(
		bgp.NewIPAddrPrefix(24, "10.0.0.0"),
		false,
		[]bgp.PathAttributeInterface{},
		time.Time{},
	)
	require.NoError(t, err)
	invalidPath.Nlri = nil // Force an invalid NLRI

	p, err := ToAgentPath(validPath)
	require.NoError(t, err)

	expectedPath := &types.ExtendedPath{
		Path: *p,
	}

	tests := []struct {
		name    string
		paths   []*gobgp.Path
		want    []*types.ExtendedPath
		wantErr bool
	}{
		{
			name: "Complete Result",
			paths: []*gobgp.Path{
				validPath,
			},
			want: []*types.ExtendedPath{
				expectedPath,
			},
			wantErr: false,
		},
		{
			name: "Partial Result with Error",
			paths: []*gobgp.Path{
				invalidPath,
				validPath,
			},
			want: []*types.ExtendedPath{
				expectedPath,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToAgentPathsExtended(tt.paths)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToAgentPathsExtended() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Equal(t, tt.want, got)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestToAgentPathExtended(t *testing.T) {
	tests := []struct {
		name           string
		extendInput    func(*gobgp.Path)
		extendExpected func(*types.ExtendedPath)
	}{
		{
			name:           "No extension",
			extendInput:    func(p *gobgp.Path) {},
			extendExpected: func(p *types.ExtendedPath) {},
		},
		{
			name: "NeighborIp extension",
			extendInput: func(p *gobgp.Path) {
				p.NeighborIp = "fe80::1%eth0"
			},
			extendExpected: func(p *types.ExtendedPath) {
				p.NeighborAddr = netip.MustParseAddr("fe80::1%eth0")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validPath, err := apiutil.NewPath(
				bgp.NewIPAddrPrefix(24, "10.0.0.0"),
				false,
				[]bgp.PathAttributeInterface{
					bgp.NewPathAttributeNextHop("192.168.0.1"),
				},
				time.Time{},
			)
			require.NoError(t, err)

			p, err := ToAgentPath(validPath)
			require.NoError(t, err)

			expectedPath := &types.ExtendedPath{
				Path: *p,
			}

			tt.extendInput(validPath)
			tt.extendExpected(expectedPath)

			got, err := ToAgentPathExtended(validPath)
			require.NoError(t, err)
			require.Equal(t, expectedPath, got)
		})
	}
}
