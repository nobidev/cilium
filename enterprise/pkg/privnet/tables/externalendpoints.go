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
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

type ExternalEndpoint struct {
	// NamespacedName identifies the namespace and name of the PrivateNetworkExternalEndpoint
	k8sTypes.NamespacedName

	// UID of the PrivateNetworkExternalEndpoint
	UID k8sTypes.UID

	// ResourceVersion is the K8s resource version of the last observed PrivateNetworkExternalEndpoint
	ResourceVersion string

	// Network of the PrivateNetworkExternalEndpoint.
	Network NetworkName

	// K8sLabels is the set of (unsanitized) labels with the PrivateNetworkExternalEndpoint
	// The map is shared across revisions of the same ExternalEndpoint, do not modify!
	K8sLabels map[string]string

	// K8sNamespaceLabels is the set of (unsanitized)  namespaces labels by the PrivateNetworkExternalEndpoint
	// The map is shared between all ExternalEndpoint of the same namespace, do not modify!
	K8sNamespaceLabels map[string]string

	// IPv4 address of the PrivateNetworkExternalEndpoint.
	IPv4 netip.Addr

	// IPv6 address of the PrivateNetworkExternalEndpoint.
	IPv6 netip.Addr

	// MAC address of the PrivateNetworkExternalEndpoint.
	MAC mac.MAC

	// ActivatedAt is the time at which this endpoint became active. Zero for inactive endpoints.
	ActivatedAt time.Time

	// EndpointStatus contains the state of local endpoint creation reconciler
	EndpointStatus reconciler.Status

	// K8sStatus contains the state of the K8s status writer
	K8sStatus reconciler.Status
}

var _ statedb.TableWritable = &ExternalEndpoint{}

func (e *ExternalEndpoint) TableHeader() []string {
	return []string{"Name", "Network", "NetworkIPv4", "NetworkIPv6", "MAC", "ActivatedAt", "EndpointsStatus", "K8sStatus"}
}

func (e *ExternalEndpoint) TableRow() []string {
	ipv4 := "N/A"
	if e.IPv4.IsValid() {
		ipv4 = e.IPv4.String()
	}
	ipv6 := "N/A"
	if e.IPv6.IsValid() {
		ipv6 = e.IPv6.String()
	}

	return []string{
		e.NamespacedName.String(),
		string(e.Network),
		ipv4,
		ipv6,
		e.MAC.String(),
		formatActivatedAt(e.ActivatedAt),
		e.EndpointStatus.String(),
		e.K8sStatus.String(),
	}
}

var (
	externalEndpointIndex = statedb.Index[*ExternalEndpoint, k8sTypes.NamespacedName]{
		Name: "namespaced-name",
		FromObject: func(obj *ExternalEndpoint) index.KeySet {
			return index.NewKeySet(index.String(obj.NamespacedName.String()))
		},
		FromKey: func(key k8sTypes.NamespacedName) index.Key {
			return index.String(key.String())
		},
		FromString: index.FromString,
		Unique:     true,
	}
)

// ExternalEndpointByNamespacedName queries the private network external endpoint by its namespace and name
func ExternalEndpointByNamespacedName(namespace, name string) statedb.Query[*ExternalEndpoint] {
	return externalEndpointIndex.Query(k8sTypes.NamespacedName{
		Name:      name,
		Namespace: namespace,
	})
}

// ExternalEndpointsByNamespace queries the private network external endpoint by its namespace
func ExternalEndpointsByNamespace(namespace string) statedb.Query[*ExternalEndpoint] {
	return externalEndpointIndex.Query(k8sTypes.NamespacedName{
		Namespace: namespace,
	})
}

func NewExternalEndpointsTable(db *statedb.DB) (statedb.RWTable[*ExternalEndpoint], error) {
	return statedb.NewTable(
		db,
		"privnet-external-endpoints",
		externalEndpointIndex,
	)
}
