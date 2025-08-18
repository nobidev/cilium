//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package kvstore_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/kvstore"
	"github.com/cilium/cilium/pkg/mac"
)

func TestEndpointMarshalUnmarshal(t *testing.T) {
	m, err := mac.ParseMAC("00:11:22:33:44:55")
	require.NoError(t, err, "mac.ParseMAC")

	ep := kvstore.Endpoint{
		ActivatedAt: time.Now().UTC(),
		IP:          netip.MustParseAddr("1.2.3.4"),
		Name:        "name",
		Network: kvstore.Network{
			Name: "blue",
			IP:   netip.MustParseAddr("5.6.7.8"),
			MAC:  m,
		},
		Source: kvstore.Source{Cluster: "foo", Namespace: "bar", Name: "baz"},
	}

	tests := []struct {
		name     string
		endpoint kvstore.Endpoint
		key      string
		cname    string
		errstr   string
	}{
		{
			name:     "valid endpoint (with activatedAt)",
			endpoint: ep,
			key:      "blue/1.2.3.4",
			cname:    "foo",
		},
		{
			name: "valid endpoint (without activatedAt)",
			endpoint: func() kvstore.Endpoint {
				cpy := ep
				cpy.ActivatedAt = time.Time{}
				return cpy
			}(),
			key:   "blue/1.2.3.4",
			cname: "foo",
		},
		{
			name:     "mismatching cluster name",
			endpoint: ep,
			key:      "blue/1.2.3.4",
			cname:    "other",
			errstr:   "unexpected cluster name: got \"foo\", expected \"other\"",
		},
		{
			name:     "mismatching key",
			endpoint: ep,
			key:      "green/1.2.3.4",
			cname:    "other",
			errstr:   "endpoint does not match provided key: got \"green/1.2.3.4\", expected \"blue/1.2.3.4\"",
		},
		{
			name: "missing IP address",
			endpoint: func() kvstore.Endpoint {
				cpy := ep
				cpy.IP = netip.Addr{}
				return cpy
			}(),
			key:    "blue/1.2.3.4",
			cname:  "foo",
			errstr: "Key: 'Endpoint.IP' Error:Field validation for 'IP' failed on the 'required' tag",
		},
		{
			name: "invalid endpoint name",
			endpoint: func() kvstore.Endpoint {
				cpy := ep
				cpy.Name = ".^."
				return cpy
			}(),
			key:    "blue/1.2.3.4",
			cname:  "foo",
			errstr: "Key: 'Endpoint.Name' Error:Field validation for 'Name' failed on the 'dns1123-subdomain' tag",
		},
		{
			name: "missing and invalid network information",
			endpoint: func() kvstore.Endpoint {
				cpy := ep
				cpy.Network.Name = "-_-"
				cpy.Network.IP = netip.Addr{}
				cpy.Network.MAC = mac.MAC{}
				return cpy
			}(),
			key:    "blue/1.2.3.4",
			cname:  "foo",
			errstr: "Key: 'Endpoint.Network.Name' Error:Field validation for 'Name' failed on the 'dns1123-subdomain' tag\nKey: 'Endpoint.Network.IP' Error:Field validation for 'IP' failed on the 'required' tag\nKey: 'Endpoint.Network.MAC' Error:Field validation for 'MAC' failed on the 'len' tag",
		},
		{
			name: "missing source information",
			endpoint: func() kvstore.Endpoint {
				cpy := ep
				cpy.Source = kvstore.Source{}
				return cpy
			}(),
			key:    "blue/1.2.3.4",
			cname:  "foo",
			errstr: "Key: 'Endpoint.Source' Error:Field validation for 'Source' failed on the 'required' tag",
		},
		{
			name: "invalid source information",
			endpoint: func() kvstore.Endpoint {
				cpy := ep
				cpy.Source = kvstore.Source{
					Cluster:   "in/valid",
					Namespace: "not-|valid",
					Name:      "wrong--",
				}
				return cpy
			}(),
			key:    "blue/1.2.3.4",
			cname:  "foo",
			errstr: "Key: 'Endpoint.Source.Cluster' Error:Field validation for 'Cluster' failed on the 'cluster-name' tag\nKey: 'Endpoint.Source.Namespace' Error:Field validation for 'Namespace' failed on the 'dns1123-label' tag\nKey: 'Endpoint.Source.Name' Error:Field validation for 'Name' failed on the 'dns1123-subdomain' tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.endpoint.Marshal()
			require.NoError(t, err, "endpoint.Marshal")

			got := kvstore.EndpointKeyCreator(kvstore.EndpointClusterNameValidator(tt.cname))()
			err = got.Unmarshal(tt.key, data)
			if tt.errstr != "" {
				require.EqualError(t, err, tt.errstr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.endpoint, got.(*kvstore.ValidatingEndpoint).Endpoint)
		})
	}
}
