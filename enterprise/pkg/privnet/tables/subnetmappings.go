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
)

// SubnetMapping maps a private network and CIDR to the identifier of the
// corresponding subnet.
type SubnetMapping struct {
	// NetworkName is the name of the target private network.
	NetworkName NetworkName

	// NetworkID is the identifier of the target private network.
	NetworkID NetworkID

	// SubnetName is the name of the target subnet.
	SubnetName SubnetName

	// SubnetID is the identifier of the target subnet.
	SubnetID SubnetID

	// CIDR is the CIDR associated with the target subnet.
	CIDR netip.Prefix

	// Status is the status of the reconciliation of this entry into the BPF map.
	Status reconciler.Status
}

func (sm *SubnetMapping) Equal(other *SubnetMapping) bool {
	if sm == nil || other == nil {
		return sm == other
	}

	return sm.NetworkName == other.NetworkName &&
		sm.NetworkID == other.NetworkID &&
		sm.SubnetName == other.SubnetName &&
		sm.SubnetID == other.SubnetID &&
		sm.CIDR == other.CIDR
}

func (sm SubnetMapping) Clone() SubnetMapping         { return sm }
func (sm SubnetMapping) GetStatus() reconciler.Status { return sm.Status }
func (sm SubnetMapping) SetStatus(status reconciler.Status) SubnetMapping {
	sm.Status = status
	return sm
}

var _ statedb.TableWritable = SubnetMapping{}

func (sm SubnetMapping) TableHeader() []string {
	return []string{"Network", "NetworkID", "Subnet", "SubnetID", "CIDR", "Status"}
}

func (sm SubnetMapping) TableRow() []string {
	return []string{
		string(sm.NetworkName),
		sm.NetworkID.String(),
		string(sm.SubnetName),
		sm.SubnetID.String(),
		sm.CIDR.String(),
		sm.Status.String(),
	}
}

// subnetMappingKey is <network>|<cidr>
type subnetMappingKey string

func (key subnetMappingKey) Key() index.Key {
	return index.String(string(key))
}

func newSubnetMappingKey(network NetworkName, cidr netip.Prefix) subnetMappingKey {
	return subnetMappingKey(string(network) + indexDelimiter + cidr.String())
}

var (
	subnetMappingsNetCIDRIndex = statedb.Index[SubnetMapping, subnetMappingKey]{
		Name: "network-cidr",
		FromObject: func(obj SubnetMapping) index.KeySet {
			return index.NewKeySet(newSubnetMappingKey(obj.NetworkName, obj.CIDR).Key())
		},
		FromKey:    subnetMappingKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}

	subnetMappingsNetSubIndex = statedb.Index[SubnetMapping, SubnetKey]{
		Name: "network-subnet",
		FromObject: func(obj SubnetMapping) index.KeySet {
			return index.NewKeySet(newSubnetKey(obj.NetworkName, obj.SubnetName).Key())
		},
		FromKey:    SubnetKey.Key,
		FromString: index.FromString,
	}
)

// SubnetMappingsBySubnetKey queries the subnet mappings table by subnet key.
func SubnetMappingsBySubnetKey(key SubnetKey) statedb.Query[SubnetMapping] {
	return subnetMappingsNetSubIndex.Query(key)
}

func NewSubnetMappingsTable(db *statedb.DB) (statedb.RWTable[SubnetMapping], error) {
	return statedb.NewTable(
		db,
		"privnet-subnet-mappings",
		subnetMappingsNetCIDRIndex,
		subnetMappingsNetSubIndex,
	)
}
