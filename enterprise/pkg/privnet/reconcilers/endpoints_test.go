// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/kvstore"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

func TestEndpointHasUsableIP(t *testing.T) {
	tests := []struct {
		name     string
		endpoint tables.Endpoint
		want     bool
	}{
		{
			name: "valid-ipv4",
			endpoint: tables.Endpoint{Endpoint: &kvstore.Endpoint{
				Network: kvstore.Network{
					IP: netip.MustParseAddr("192.168.100.10"),
				},
			}},
			want: true,
		},
		{
			name: "valid-ipv6",
			endpoint: tables.Endpoint{Endpoint: &kvstore.Endpoint{
				Network: kvstore.Network{
					IP: netip.MustParseAddr("fd10::10"),
				},
			}},
			want: true,
		},
		{
			name: "unspecified-network-ipv4",
			endpoint: tables.Endpoint{Endpoint: &kvstore.Endpoint{
				Network: kvstore.Network{
					IP: netip.MustParseAddr("0.0.0.0"),
				},
			}},
			want: false,
		},
		{
			name: "invalid-network-ip",
			endpoint: tables.Endpoint{Endpoint: &kvstore.Endpoint{
				Network: kvstore.Network{},
			}},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.endpoint.HasUsableIP())
		})
	}
}

func TestClusterMeshEndpointWithUnusableIPIsIgnored(t *testing.T) {
	db := statedb.New()
	endpoints, err := tables.NewEndpointsTable(db)
	require.NoError(t, err)
	subnets, err := tables.NewSubnetTable(db)
	require.NoError(t, err)

	r := &Endpoints{
		db:      db,
		tbl:     endpoints,
		subnets: subnets,
	}

	existing := &kvstore.Endpoint{
		Name: "pod-1",
		IP:   netip.MustParseAddr("10.0.0.10"),
		Network: kvstore.Network{
			Name: "blue-network",
			IP:   netip.MustParseAddr("192.168.100.10"),
		},
		Source: kvstore.Source{
			Cluster:   "remote",
			Namespace: "default",
			Name:      "slice-1",
		},
	}

	wtx := db.WriteTxn(endpoints)
	_, _, err = endpoints.Insert(wtx, tables.Endpoint{Endpoint: existing})
	require.NoError(t, err)
	r.upsertClusterMeshEndpoint(wtx, &kvstore.Endpoint{
		Name: "pod-1",
		IP:   netip.MustParseAddr("10.0.0.10"),
		Network: kvstore.Network{
			Name: "blue-network",
			IP:   netip.MustParseAddr("0.0.0.0"),
		},
		Source: kvstore.Source{
			Cluster:   "remote",
			Namespace: "default",
			Name:      "slice-1",
		},
	})
	wtx.Commit()

	require.Empty(t, statedb.Collect(endpoints.All(db.ReadTxn())))
}
