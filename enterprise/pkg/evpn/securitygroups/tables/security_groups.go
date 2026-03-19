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

	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

// SecurityGroup reflects a FabricSecurityGroup CRD object.
// As CRD object's name reflects into GroupID, CRD objects with invalid name
// (non-numeric or out-of range) are not reflected.
type SecurityGroup struct {
	GroupID          uint16
	EndpointSelector *policyTypes.LabelSelector
}

func (f SecurityGroup) TableHeader() []string {
	return []string{"GroupID", "EndpointSelector"}
}

func (f SecurityGroup) TableRow() []string {
	selector := "<nil>"
	if f.EndpointSelector != nil {
		selector = f.EndpointSelector.String()
	}
	return []string{strconv.FormatUint(uint64(f.GroupID), 10), selector}
}

func (f SecurityGroup) Equal(other SecurityGroup) bool {
	if f.GroupID != other.GroupID {
		return false
	}
	if f.EndpointSelector == nil || other.EndpointSelector == nil {
		return f.EndpointSelector == other.EndpointSelector
	}
	return f.EndpointSelector.DeepEqual(other.EndpointSelector)
}

var securityGroupIDIndex = statedb.Index[SecurityGroup, uint16]{
	Name: "group-id",
	FromObject: func(obj SecurityGroup) index.KeySet {
		return index.NewKeySet(index.Uint16(obj.GroupID))
	},
	FromKey:    index.Uint16,
	FromString: index.Uint16String,
	Unique:     true,
}

func SecurityGroupByID(endpointID uint16) statedb.Query[SecurityGroup] {
	return securityGroupIDIndex.Query(endpointID)
}

func NewSecurityGroupsTable(db *statedb.DB) (statedb.RWTable[SecurityGroup], error) {
	return statedb.NewTable(
		db,
		"evpn-security-groups",
		securityGroupIDIndex,
	)
}
