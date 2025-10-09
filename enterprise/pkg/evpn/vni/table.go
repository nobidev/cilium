// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vni

import (
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	privnetTables "github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/vni"
)

type VNIMapping struct {
	VNI       vni.VNI
	NetworkID privnetTables.NetworkID
	reconciler.Status
}

func (m VNIMapping) TableHeader() []string {
	return []string{"VNI", "NetworkID"}
}

func (m VNIMapping) TableRow() []string {
	return []string{
		m.VNI.String(),
		strconv.FormatUint(uint64(m.NetworkID), 10),
	}
}

func (m0 VNIMapping) Equal(m1 VNIMapping) bool {
	return m0.VNI == m1.VNI &&
		m0.NetworkID == m1.NetworkID
}

var (
	vniIndex = statedb.Index[VNIMapping, vni.VNI]{
		Name: "vni",
		FromObject: func(obj VNIMapping) index.KeySet {
			if !obj.VNI.IsValid() {
				return index.NewKeySet()
			}
			return index.NewKeySet(
				vni.StateDBKey(obj.VNI),
			)
		},
		FromKey:    vni.StateDBKey,
		FromString: index.FromString,
		Unique:     true,
	}

	vniNetIDIndex = statedb.Index[VNIMapping, privnetTables.NetworkID]{
		Name: "network-id",
		FromObject: func(obj VNIMapping) index.KeySet {
			return index.NewKeySet(
				obj.NetworkID.Key(),
			)
		},
		FromKey:    privnetTables.NetworkID.Key,
		FromString: index.FromString,
	}
)

func VNIMappingByVNI(vni vni.VNI) statedb.Query[VNIMapping] {
	return vniIndex.Query(vni)
}

func VNIMappingByNetID(nid privnetTables.NetworkID) statedb.Query[VNIMapping] {
	return vniNetIDIndex.Query(nid)
}

func newVNIMappingTable(db *statedb.DB) (statedb.RWTable[VNIMapping], error) {
	return statedb.NewTable[VNIMapping](
		db,
		"vni-mappings",
		vniIndex,
		vniNetIDIndex,
	)
}
