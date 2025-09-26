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

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type PrivateNetworkStatus struct {
	// The Name of the private network.
	Name NetworkName

	// The status of the private network VNI allocation.
	VNI PrivateNetworkVNIStatus

	// The original resource propagated from the upstream table.
	OrigResource *v1alpha1.ClusterwidePrivateNetwork

	// The reconciler status for statedb => k8s reconciliation
	reconciler.Status
}

type PrivateNetworkVNIStatus struct {
	// The requested VNI
	RequestedVNI vni.VNI

	// The allocated VNI
	AllocatedVNI vni.VNI

	// The VNI request is conflicting with another private network
	HasVNIConflict bool
}

var _ statedb.TableWritable = &PrivateNetworkStatus{}

func (pn PrivateNetworkStatus) TableHeader() []string {
	return []string{
		"Name",
		"RequestedVNI",
		"AllocatedVNI",
		"HasVNIConflict",
	}
}

func (pn PrivateNetworkStatus) TableRow() []string {
	return []string{
		string(pn.Name),
		pn.VNI.RequestedVNI.String(),
		pn.VNI.AllocatedVNI.String(),
		strconv.FormatBool(pn.VNI.HasVNIConflict),
	}
}

func (pn0 PrivateNetworkStatus) Equal(pn1 PrivateNetworkStatus) bool {
	return pn0.Name == pn1.Name &&
		pn0.VNI.RequestedVNI == pn1.VNI.RequestedVNI &&
		pn0.VNI.AllocatedVNI == pn1.VNI.AllocatedVNI &&
		pn0.VNI.HasVNIConflict == pn1.VNI.HasVNIConflict
}

var (
	privateNetworksStatusNameIndex = statedb.Index[PrivateNetworkStatus, string]{
		Name: "name",
		FromObject: func(obj PrivateNetworkStatus) index.KeySet {
			return index.NewKeySet(index.String(string(obj.Name)))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
)

// PrivateNetworkStatusByName queries the private networks status table by name.
func PrivateNetworkStatusByName(name tables.NetworkName) statedb.Query[PrivateNetworkStatus] {
	return privateNetworksStatusNameIndex.Query(string(name))
}

func NewPrivateNetworksStatusTable(config config.Config, db *statedb.DB) (statedb.RWTable[PrivateNetworkStatus], error) {
	return statedb.NewTable(
		db,
		"private-networks-status",
		privateNetworksStatusNameIndex,
	)
}
