// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslice

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
)

// normalizeExpectedProtoRoundTrip normalizes fields that are expected to default
// to nil after a protobuf encoding/decoding for equality checks in tests
func normalizeExpectedClusterEndpointSlice(eps *ClusterEndpointSlice) {
	if len(eps.Labels) == 0 {
		eps.Labels = nil
	}
	if len(eps.Annotations) == 0 {
		eps.Annotations = nil
	}
}

func TestClusterEndpointSlice(t *testing.T) {
	eps := NewClusterEndpointSlice("foo", "bar")
	eps.Cluster = "default"
	eps.AddressType = slim_discovery_v1.AddressTypeIPv4

	require.Equal(t, "foo", eps.Name)
	require.Equal(t, "bar", eps.Namespace)

	require.Equal(t, "default/bar/foo", eps.String())

	b, err := eps.Marshal()
	require.NoError(t, err)

	unmarshal := ClusterEndpointSlice{}
	err = unmarshal.Unmarshal("", b)
	require.NoError(t, err)
	normalizeExpectedClusterEndpointSlice(&eps)
	require.Equal(t, eps, unmarshal)

	require.Equal(t, "default/bar/foo", eps.GetKeyName())
}

func TestClusterEndpointSliceValidate(t *testing.T) {
	tests := []struct {
		name   string
		eps    ClusterEndpointSlice
		assert assert.ErrorAssertionFunc
	}{
		{
			name:   "empty",
			eps:    ClusterEndpointSlice{},
			assert: assert.Error,
		},
		{
			name: "minimum information",
			eps: ClusterEndpointSlice{ClusterEndpointSliceEmbed: ClusterEndpointSliceEmbed{
				Cluster:     "foo",
				Namespace:   "bar",
				Name:        "qux",
				AddressType: slim_discovery_v1.AddressTypeIPv4,
			}},
			assert: assert.NoError,
		},
		{
			name: "valid",
			eps: ClusterEndpointSlice{ClusterEndpointSliceEmbed: ClusterEndpointSliceEmbed{
				Cluster:     "foo",
				Namespace:   "bar",
				Name:        "qux",
				ClusterID:   99,
				AddressType: slim_discovery_v1.AddressTypeIPv4,
				Endpoints: []slim_discovery_v1.Endpoint{{
					Addresses: []string{"10.1.2.3"},
				}},
			}},
			assert: assert.NoError,
		},
		{
			name: "invalid cluster ID",
			eps: ClusterEndpointSlice{ClusterEndpointSliceEmbed: ClusterEndpointSliceEmbed{
				Cluster: "foo", Namespace: "bar", Name: "qux", ClusterID: 260, AddressType: slim_discovery_v1.AddressTypeIPv4,
			}},
			assert: assert.Error,
		},
		{
			name: "invalid IPv4 endpoint address",
			eps: ClusterEndpointSlice{ClusterEndpointSliceEmbed: ClusterEndpointSliceEmbed{
				Cluster: "foo", Namespace: "bar", Name: "qux",
				AddressType: slim_discovery_v1.AddressTypeIPv4,
				Endpoints: []slim_discovery_v1.Endpoint{{
					Addresses: []string{"invalid"},
				}},
			}},
			assert: assert.Error,
		},
		{
			name: "invalid IPv6 endpoint address",
			eps: ClusterEndpointSlice{ClusterEndpointSliceEmbed: ClusterEndpointSliceEmbed{
				Cluster: "foo", Namespace: "bar", Name: "qux",
				AddressType: slim_discovery_v1.AddressTypeIPv6,
				Endpoints: []slim_discovery_v1.Endpoint{{
					Addresses: []string{"10.1.2.3"},
				}},
			}},
			assert: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assert(t, tt.eps.validate())
		})
	}
}

func TestValidatingClusterEndpointSlice(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		eps       ClusterEndpointSlice
		validator clusterEndpointSliceValidator
		errstr    string
	}{
		{
			name: "valid cluster name",
			eps: ClusterEndpointSlice{ClusterEndpointSliceEmbed: ClusterEndpointSliceEmbed{
				Cluster: "foo", Namespace: "bar", Name: "qux", AddressType: slim_discovery_v1.AddressTypeIPv4,
			}},
			validator: ClusterNameValidator("foo"),
		},
		{
			name: "invalid cluster name",
			eps: ClusterEndpointSlice{ClusterEndpointSliceEmbed: ClusterEndpointSliceEmbed{
				Cluster: "foo", Namespace: "bar", Name: "qux", AddressType: slim_discovery_v1.AddressTypeIPv4,
			}},
			validator: ClusterNameValidator("fred"),
			errstr:    "unexpected cluster name: got foo, expected fred",
		},
		{
			name: "valid namespaced name",
			key:  "bar/qux",
			eps: ClusterEndpointSlice{ClusterEndpointSliceEmbed: ClusterEndpointSliceEmbed{
				Cluster: "foo", Namespace: "bar", Name: "qux", AddressType: slim_discovery_v1.AddressTypeIPv4,
			}},
			validator: NamespacedNameValidator(),
		},
		{
			name: "invalid namespaced name",
			key:  "fred/qux",
			eps: ClusterEndpointSlice{ClusterEndpointSliceEmbed: ClusterEndpointSliceEmbed{
				Cluster: "foo", Namespace: "bar", Name: "qux", AddressType: slim_discovery_v1.AddressTypeIPv4,
			}},
			validator: NamespacedNameValidator(),
			errstr:    "namespaced name does not match key: got bar/qux, expected fred/qux",
		},
		{
			name: "valid cluster ID",
			eps: ClusterEndpointSlice{ClusterEndpointSliceEmbed: ClusterEndpointSliceEmbed{
				Cluster: "foo", Namespace: "bar", Name: "qux", ClusterID: 10, AddressType: slim_discovery_v1.AddressTypeIPv4,
			}},
			validator: ClusterIDValidator(ptr.To[uint32](10)),
		},
		{
			name: "invalid cluster ID",
			eps: ClusterEndpointSlice{ClusterEndpointSliceEmbed: ClusterEndpointSliceEmbed{
				Cluster: "foo", Namespace: "bar", Name: "qux", ClusterID: 10, AddressType: slim_discovery_v1.AddressTypeIPv4,
			}},
			validator: ClusterIDValidator(ptr.To[uint32](15)),
			errstr:    "unexpected cluster ID: got 10, expected 15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.eps.Marshal()
			require.NoError(t, err)

			got := KeyCreator(tt.validator)()
			err = got.Unmarshal(tt.key, data)
			if tt.errstr != "" {
				require.EqualError(t, err, tt.errstr)
				return
			}

			require.NoError(t, err)
			gotEPS := got.(*ValidatingClusterEndpointSlice).ClusterEndpointSlice
			normalizeExpectedClusterEndpointSlice(&tt.eps)
			require.Equal(t, tt.eps, gotEPS)
		})
	}
}
