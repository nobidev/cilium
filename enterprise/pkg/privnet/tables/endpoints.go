// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tables

import (
	"iter"
	"log/slog"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/privnet/kvstore"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/slices"
	"github.com/cilium/cilium/pkg/time"
)

// Source identifies the resource propagating the endpoint information.
type Source = kvstore.Source

// Endpoint represents a single private network endpoint, for either IPv4 or IPv6.
type Endpoint struct {
	*kvstore.Endpoint
}

// Equal returns whether two Endpoint objects are identical.
func (ep Endpoint) Equal(other Endpoint) bool {
	return ep.Endpoint.Equal(other.Endpoint)
}

// Key returns the key uniquely identifying this endpoint in the endpoints table.
func (ep Endpoint) Key() EndpointKey {
	return newEndpointKey(ep.Source, NetworkName(ep.Name), ep.IP)
}

// MapEntryType returns the MapEntry type of this endpoint.
func (ep Endpoint) MapEntryType() MapEntryType {
	if ep.Flags.External {
		return MapEntryTypeExternalEndpoint
	}
	return MapEntryTypeEndpoint
}

// ToMapEntry returns the MapEntry object created from the Endpoint and
// PrivateNetwork information.
func (ep Endpoint) ToMapEntry(privnet SlimPrivateNetwork, bridgeMode bool) *MapEntry {
	// gneigh status is only relevant on the INB where it will be set as done by the gneigh
	// reconciler.
	gneighStatus := reconciler.StatusDone()
	if bridgeMode {
		gneighStatus = reconciler.StatusPending()
	}

	return &MapEntry{
		Type: ep.MapEntryType(),

		Target: MapEntryTarget{
			NetworkName: privnet.Name,
			NetworkID:   privnet.ID,
			CIDR:        netip.PrefixFrom(ep.Network.IP, ep.Network.IP.BitLen()),
			MAC:         ep.Network.MAC,
		},

		Routing: MapEntryRouting{
			NextHop:       ep.IP,
			EgressIfIndex: privnet.EgressIfIndex,
			Cluster:       ClusterName(ep.Source.Cluster),
		},

		Status:       reconciler.StatusPending(),
		GneighStatus: gneighStatus,
	}
}

// ToMapEntryKey returns the key uniquely identifying the corresponding entry in
// the map entries table.
func (ep Endpoint) ToMapEntryKey() MapEntryKey {
	return newMapEntryKey(NetworkName(ep.Network.Name), ep.MapEntryType(),
		netip.PrefixFrom(ep.Network.IP, ep.Network.IP.BitLen()))
}

var _ statedb.TableWritable = Endpoint{}

func (ep Endpoint) TableHeader() []string {
	return []string{
		"Source", "Name",
		"Network", "NetworkIP", "NetworkMAC",
		"PodIP", "ActivatedAt",
	}
}

func (ep Endpoint) TableRow() []string {
	activatedAt := "<inactive>"
	if !ep.ActivatedAt.IsZero() {
		activatedAt = ep.ActivatedAt.UTC().Format(time.RFC3339)
	}

	return []string{
		ep.Source.String(),
		ep.Name,
		ep.Network.Name,
		ep.Network.IP.String(),
		ep.Network.MAC.String(),
		ep.IP.String(),
		activatedAt,
	}
}

// EndpointsFromEndpointSliceEntry returns an iterator of Endpoint objects generated from the specific EndpointSlice.
func EndpointsFromEndpointSlice(logger *slog.Logger, clusterName ClusterName, slice *iso_v1alpha1.PrivateNetworkEndpointSlice) iter.Seq[Endpoint] {
	return slices.MapIter(
		kvstore.EndpointsFromEndpointSlice(logger, string(clusterName), slice),
		func(in *kvstore.Endpoint) Endpoint { return Endpoint{Endpoint: in} },
	)
}

const (
	// indexDelimiter is the delimiter used to concatenate strings for composite indexes.
	indexDelimiter = "|"
)

// EndpointKey is <cluster>/<namespace>/<name>|<network>|<network-ip>.
type EndpointKey string

func (key EndpointKey) Key() index.Key {
	return index.String(string(key))
}

func newEndpointKeyFromCluster(cluster string) EndpointKey {
	return EndpointKey(cluster + indexDelimiter)
}

func newEndpointKeyFromSource(source Source) EndpointKey {
	return newEndpointKeyFromCluster(source.Cluster) + EndpointKey(source.Namespace+indexDelimiter+source.Name+indexDelimiter)
}

func newEndpointKey(source Source, network NetworkName, networkIP netip.Addr) EndpointKey {
	return newEndpointKeyFromSource(source) + EndpointKey(string(network)+indexDelimiter+networkIP.String())
}

// endpointNetIPKey is <network>|<network-ip>.
type endpointNetIPKey string

func (key endpointNetIPKey) Key() index.Key {
	return index.String(string(key))
}

func newEndpointNetIPKeyFromNetwork(network NetworkName) endpointNetIPKey {
	return endpointNetIPKey(string(network) + indexDelimiter)
}

func newEndpointNetIPKey(network NetworkName, networkIP netip.Addr) endpointNetIPKey {
	return newEndpointNetIPKeyFromNetwork(network) + endpointNetIPKey(networkIP.String())
}

var (
	endpointsPrimaryIndex = statedb.Index[Endpoint, EndpointKey]{
		Name: "primary",
		FromObject: func(obj Endpoint) index.KeySet {
			return index.NewKeySet(obj.Key().Key())
		},
		FromKey:    EndpointKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}

	endpointsPIPIndex = statedb.Index[Endpoint, netip.Addr]{
		Name: "pod-ip",
		FromObject: func(obj Endpoint) index.KeySet {
			return index.NewKeySet(index.NetIPAddr(obj.IP))
		},
		FromKey:    index.NetIPAddr,
		FromString: index.NetIPAddrString,
		Unique:     false,
	}

	endpointsNetIPIndex = statedb.Index[Endpoint, endpointNetIPKey]{
		Name: "network-ip",
		FromObject: func(obj Endpoint) index.KeySet {
			return index.NewKeySet(newEndpointNetIPKey(
				NetworkName(obj.Network.Name), obj.Network.IP).Key())
		},
		FromKey:    endpointNetIPKey.Key,
		FromString: index.FromString,
		Unique:     false,
	}

	// EndpointsByPIP queries the endpoints table by Pod IP.
	EndpointsByPIP = endpointsPIPIndex.Query
)

// EndpointsByCluster queries the endpoints table by source cluster name.
func EndpointsByCluster(cluster ClusterName) statedb.Query[Endpoint] {
	return endpointsPrimaryIndex.Query(newEndpointKeyFromCluster(string(cluster)))
}

// EndpointsBySource queries the endpoints table by source.
func EndpointsBySource(source Source) statedb.Query[Endpoint] {
	return endpointsPrimaryIndex.Query(newEndpointKeyFromSource(source))
}

// EndpointsByNetwork queries the endpoints table by network name.
func EndpointsByNetwork(network NetworkName) statedb.Query[Endpoint] {
	return endpointsNetIPIndex.Query(newEndpointNetIPKeyFromNetwork(network))
}

// EndpointsByNetworkIP queries the endpoints table by network name and IP.
func EndpointsByNetworkIP(network NetworkName, networkIP netip.Addr) statedb.Query[Endpoint] {
	return endpointsNetIPIndex.Query(newEndpointNetIPKey(network, networkIP))
}

func NewEndpointsTable(db *statedb.DB) (statedb.RWTable[Endpoint], error) {
	return statedb.NewTable(
		db,
		"privnet-endpoints",
		endpointsPrimaryIndex,
		endpointsPIPIndex,
		endpointsNetIPIndex,
	)
}
