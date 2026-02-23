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
	"fmt"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

// DHCPLease represents a DHCP lease for a private network endpoint.
type DHCPLease struct {
	// Network is the private network name.
	Network NetworkName

	// EndpointID is the Cilium's numeric identifier of the endpoint.
	EndpointID uint16

	// MAC is the endpoint interface MAC address.
	MAC mac.MAC

	// IPv4 is the leased IPv4 address.
	IPv4 netip.Addr

	// ServerID is the DHCP server IPv4 address, if provided.
	ServerID netip.Addr

	// ObtainedAt is the time the lease was acquired.
	ObtainedAt time.Time

	// RenewAt is the time the lease should be renewed.
	RenewAt time.Time

	// ExpireAt is the lease expiration time.
	ExpireAt time.Time
}

var _ statedb.TableWritable = DHCPLease{}

func (l DHCPLease) TableHeader() []string {
	return []string{"Network", "EndpointID", "MAC", "IPv4", "ServerID", "ObtainedAt", "RenewAt", "ExpireAt"}
}

func (l DHCPLease) TableRow() []string {
	showTime := func(t time.Time) string {
		if t.IsZero() {
			return "<unknown>"
		}
		return t.UTC().Format(time.RFC3339)
	}
	return []string{
		string(l.Network),
		fmt.Sprintf("%d", l.EndpointID),
		l.MAC.String(),
		l.IPv4.String(),
		l.ServerID.String(),
		showTime(l.ObtainedAt),
		showTime(l.RenewAt),
		showTime(l.ExpireAt),
	}
}

// DHCPLeaseKey is <network>|<mac>.
type DHCPLeaseKey string

func (key DHCPLeaseKey) Key() index.Key {
	return index.String(string(key))
}

func newDHCPLeaseKey(network NetworkName, macAddr mac.MAC) DHCPLeaseKey {
	return DHCPLeaseKey(string(network) + indexDelimiter + macAddr.String())
}

// DHCPLeaseByNetworkMAC queries leases by network and MAC.
func DHCPLeaseByNetworkMAC(network NetworkName, macAddr mac.MAC) statedb.Query[DHCPLease] {
	return leasePrimaryIndex.Query(newDHCPLeaseKey(network, macAddr))
}

var (
	leasePrimaryIndex = statedb.Index[DHCPLease, DHCPLeaseKey]{
		Name: "network-mac",
		FromObject: func(obj DHCPLease) index.KeySet {
			return index.NewKeySet(newDHCPLeaseKey(obj.Network, obj.MAC).Key())
		},
		FromKey:    DHCPLeaseKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}
)

// NewDHCPLeasesTable returns a StateDB table for DHCP leases.
func NewDHCPLeasesTable(db *statedb.DB) (statedb.RWTable[DHCPLease], error) {
	return statedb.NewTable(
		db,
		"privnet-dhcp-leases",
		leasePrimaryIndex,
	)
}
