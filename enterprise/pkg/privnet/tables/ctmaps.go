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
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
)

type ConnTrackMap struct {
	// Network is the name of the private network owning this conntrack map
	Network NetworkName
	// Network ID is used as the key to find the conntrack map
	NetworkID NetworkID
	// Status contains the reconciler status of the map of maps entry
	Status reconciler.Status
}

var _ statedb.TableWritable = ConnTrackMap{}

func (c ConnTrackMap) TableHeader() []string {
	return []string{"Network", "NetworkID", "Status"}
}

func (c ConnTrackMap) TableRow() []string {
	return []string{
		string(c.Network),
		"0x" + strconv.FormatUint(uint64(c.NetworkID), 16),
		c.Status.String(),
	}
}

var (
	connTrackMapIndex = statedb.Index[ConnTrackMap, uint16]{
		Name: "id",
		FromObject: func(obj ConnTrackMap) index.KeySet {
			return index.NewKeySet(index.Uint16(uint16(obj.NetworkID)))
		},
		FromKey:    index.Uint16,
		FromString: index.Uint16String,
		Unique:     true,
	}
)

// ConnTrackMapByID queries the private network conntrack map table by network ID
func ConnTrackMapByID(networkId NetworkID) statedb.Query[ConnTrackMap] {
	return connTrackMapIndex.Query(uint16(networkId))
}

func NewConnTrackMapTable(db *statedb.DB) (statedb.RWTable[ConnTrackMap], error) {
	return statedb.NewTable(
		db,
		"privnet-ctmaps",
		connTrackMapIndex,
	)
}
