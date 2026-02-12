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
	"cmp"
	"fmt"
	"net/netip"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
)

type (
	// DeviceMappingOwner identifies the owner of the [DeviceMapping] entry.
	DeviceMappingOwner string
)

// NewDeviceMappingOwner generates a new [DeviceMappingOwner] given thw
// provided identifying tokens.
func NewDeviceMappingOwner(tokens ...string) DeviceMappingOwner {
	return DeviceMappingOwner(strings.Join(tokens, "-"))
}

// DeviceMapping maps a network interface to the identifier of the associated
// private network. Eventually, all entries are propagated to the corresponding
// BPF map, allowing to determine, for each packet, the corresponding NetworkID.
type DeviceMapping struct {
	// Owner identifies the owner of this entry. Multiple entries can be
	// associated with the same owner.
	Owner DeviceMappingOwner

	// DeviceIndex is the index of the target network interface.
	DeviceIndex int

	// DeviceName is the name of the target network interface. It is provided
	// for convenience only (e.g., in the table output), and shall not be
	// depended on during reconciliation.
	DeviceName string

	// NetworkName is the name of the target private network.
	NetworkName NetworkName

	// NetworkID is the identifier of the target private network.
	NetworkID NetworkID

	// NetworkIPv4 is the IPv4 address of the endpoint.
	NetworkIPv4 netip.Addr

	// NetworkIPv6 is the IPv6 address of the endpoint.
	NetworkIPv6 netip.Addr

	// Status is the status of the reconciliation of this entry into the BPF map.
	Status reconciler.Status
}

func (dm *DeviceMapping) Equal(other *DeviceMapping) bool {
	if dm == nil || other == nil {
		return dm == other
	}

	return dm.Owner == other.Owner &&
		dm.DeviceIndex == other.DeviceIndex &&
		dm.DeviceName == other.DeviceName &&
		dm.NetworkName == other.NetworkName &&
		dm.NetworkID == other.NetworkID &&
		dm.NetworkIPv4 == other.NetworkIPv4 &&
		dm.NetworkIPv6 == other.NetworkIPv6
}

var _ statedb.TableWritable = DeviceMapping{}

func (dm DeviceMapping) TableHeader() []string {
	return []string{"Interface", "Network", "NetworkID", "NetworkIPv4", "NetworkIPv6", "Owner", "Status"}
}

func (dm DeviceMapping) TableRow() []string {
	return []string{
		fmt.Sprintf("%s (%d)", cmp.Or(dm.DeviceName, "?"), dm.DeviceIndex),
		string(dm.NetworkName),
		dm.NetworkID.String(),
		dm.NetworkIPv4.String(),
		dm.NetworkIPv6.String(),
		string(dm.Owner),
		dm.Status.String(),
	}
}

var (
	deviceMappingsInterfaceIndex = statedb.Index[DeviceMapping, int]{
		Name: "ifindex",
		FromObject: func(obj DeviceMapping) index.KeySet {
			return index.NewKeySet(index.Int(obj.DeviceIndex))
		},
		FromKey:    index.Int,
		FromString: index.IntString,
		Unique:     true,
	}

	deviceMappingsNetworkIndex = statedb.Index[DeviceMapping, string]{
		Name: "network",
		FromObject: func(obj DeviceMapping) index.KeySet {
			return index.NewKeySet(index.String(string(obj.NetworkName)))
		},
		FromKey:    index.String,
		FromString: index.FromString,
	}

	deviceMappingsOwnerIndex = statedb.Index[DeviceMapping, string]{
		Name: "owner",
		FromObject: func(obj DeviceMapping) index.KeySet {
			return index.NewKeySet(index.String(string(obj.Owner)))
		},
		FromKey:    index.String,
		FromString: index.FromString,
	}
)

// DeviceMappingsByNetwork queries the device mappings table by network.
func DeviceMappingsByNetwork(network NetworkName) statedb.Query[DeviceMapping] {
	return deviceMappingsNetworkIndex.Query(string(network))
}

// DeviceMappingsByOwner queries the device mappings table by owner.
func DeviceMappingsByOwner(owner DeviceMappingOwner) statedb.Query[DeviceMapping] {
	return deviceMappingsOwnerIndex.Query(string(owner))
}

func NewDeviceMappingsTable(db *statedb.DB) (statedb.RWTable[DeviceMapping], error) {
	return statedb.NewTable(
		db,
		"privnet-device-mappings",
		deviceMappingsInterfaceIndex,
		deviceMappingsNetworkIndex,
		deviceMappingsOwnerIndex,
	)
}
