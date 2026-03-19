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
)

// EndpointSecurityGroup holds endpoint ID to fabric security group ID mapping.
// The table only contains endpoints relevant for the EVPN feature - for now those are
// only endpoints which have private network properties.
type EndpointSecurityGroup struct {
	EndpointID      uint16
	SecurityGroupID uint16
}

func (e EndpointSecurityGroup) TableHeader() []string {
	return []string{"EndpointID", "SecurityGroupID"}
}

func (e EndpointSecurityGroup) TableRow() []string {
	return []string{
		strconv.FormatUint(uint64(e.EndpointID), 10),
		strconv.FormatUint(uint64(e.SecurityGroupID), 10),
	}
}

var endpointIDIndex = statedb.Index[EndpointSecurityGroup, uint16]{
	Name: "endpoint-id",
	FromObject: func(obj EndpointSecurityGroup) index.KeySet {
		if obj.EndpointID == 0 {
			return index.NewKeySet()
		}
		return index.NewKeySet(index.Uint16(obj.EndpointID))
	},
	FromKey:    index.Uint16,
	FromString: index.FromString,
	Unique:     true,
}

func EndpointSecurityGroupByEndpointID(endpointID uint16) statedb.Query[EndpointSecurityGroup] {
	return endpointIDIndex.Query(endpointID)
}

func NewEndpointSecurityGroupTable(db *statedb.DB) (statedb.RWTable[EndpointSecurityGroup], error) {
	return statedb.NewTable(
		db,
		"evpn-endpoint-security-groups",
		endpointIDIndex,
	)
}
