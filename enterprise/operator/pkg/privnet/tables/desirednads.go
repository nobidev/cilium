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
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

// DesiredNetworkAttachmentDefinition represents a desired Multus
// NetworkAttachmentDefinition to be reconciled into Kubernetes.
type DesiredNetworkAttachmentDefinition struct {
	// NamespacedName identifies the namespace and name of the NAD.
	NamespacedName

	// Network is the network name associated with the given NAD.
	Network tables.NetworkName

	// Subnet is the subnet name associated with the given NAD.
	Subnet tables.SubnetName

	// Status is the status of the reconciliation of this NAD into Kubernetes.
	Status reconciler.Status
}

func (nad DesiredNetworkAttachmentDefinition) Clone() DesiredNetworkAttachmentDefinition { return nad }
func (nad DesiredNetworkAttachmentDefinition) GetStatus() reconciler.Status              { return nad.Status }
func (nad DesiredNetworkAttachmentDefinition) SetStatus(status reconciler.Status) DesiredNetworkAttachmentDefinition {
	nad.Status = status
	return nad
}

var _ statedb.TableWritable = DesiredNetworkAttachmentDefinition{}

func (nad DesiredNetworkAttachmentDefinition) TableHeader() []string {
	return []string{"Namespace", "Name", "Network", "Subnet", "Status"}
}

func (nad DesiredNetworkAttachmentDefinition) TableRow() []string {
	return []string{
		nad.Namespace,
		nad.Name,
		string(nad.Network),
		string(nad.Subnet),
		nad.Status.String(),
	}
}

var (
	desiredNADsNamespacedNameIndex = statedb.Index[DesiredNetworkAttachmentDefinition, NamespacedName]{
		Name: "namespaced-name",
		FromObject: func(obj DesiredNetworkAttachmentDefinition) index.KeySet {
			return index.NewKeySet(obj.NamespacedName.Key())
		},
		FromKey:    NamespacedName.Key,
		FromString: index.FromString,
		Unique:     true,
	}

	desiredNADsNetworkSubnetNamespaceIndex = statedb.Index[DesiredNetworkAttachmentDefinition, nadKey]{
		Name: "network-subnet-namespace",
		FromObject: func(obj DesiredNetworkAttachmentDefinition) index.KeySet {
			return index.NewKeySet(newNADKey(obj.Network, obj.Subnet, obj.Namespace).Key())
		},
		FromKey:    nadKey.Key,
		FromString: index.FromString,
		// Differently from the NADs table, here we are guaranteed that there's only a single
		// desired NAD for a given network and subnet in a specific namespace.
		Unique: true,
	}

	// DesiredNADByNamespacedName queries the DesiredNetworkAttachmentDefinitions table by namespaced name.
	DesiredNADByNamespacedName = desiredNADsNamespacedNameIndex.Query
)

// DesiredNADsByNamespace queries the DesiredNetworkAttachmentDefinitions table by namespace.
func DesiredNADsByNamespace(namespace string) statedb.Query[DesiredNetworkAttachmentDefinition] {
	return desiredNADsNamespacedNameIndex.Query(NamespacedName{Namespace: namespace})
}

// DesiredNADsByNetwork queries the DesiredNetworkAttachmentDefinitions table by network name.
func DesiredNADsByNetwork(network tables.NetworkName) statedb.Query[DesiredNetworkAttachmentDefinition] {
	return desiredNADsNetworkSubnetNamespaceIndex.Query(newNADKeyFromNetwork(network))
}

// DesiredNADByNetworkSubnetAndNamespace queries the DesiredNetworkAttachmentDefinitions table by
// network, subnet and namespace name.
func DesiredNADByNetworkSubnetAndNamespace(network tables.NetworkName, subnet tables.SubnetName, namespace string,
) statedb.Query[DesiredNetworkAttachmentDefinition] {
	return desiredNADsNetworkSubnetNamespaceIndex.Query(newNADKey(network, subnet, namespace))
}

func NewDesiredNetworkAttachmentDefinitionsTable(db *statedb.DB) (statedb.RWTable[DesiredNetworkAttachmentDefinition], error) {
	return statedb.NewTable(
		db,
		"privnet-desired-nads",
		desiredNADsNamespacedNameIndex,
		desiredNADsNetworkSubnetNamespaceIndex,
	)
}
