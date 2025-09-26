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

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type (
	// NetworkName is the name of a private network.
	NetworkName = tables.NetworkName
)

// PrivateNetwork represents a private network instance.
type PrivateNetwork struct {
	// Name is the name of the private network.
	Name NetworkName

	// VNI requested by this private network.
	RequestedVNI vni.VNI

	// Keeping the copy of the original resource for async UpdateStatus call.
	OrigResource *v1alpha1.ClusterwidePrivateNetwork
}

var _ statedb.TableWritable = &PrivateNetwork{}

func (pn PrivateNetwork) TableHeader() []string {
	return []string{"Name", "RequestedVNI"}
}

func (pn PrivateNetwork) TableRow() []string {
	return []string{
		string(pn.Name),
		pn.RequestedVNI.String(),
	}
}

var (
	privateNetworksNameIndex = statedb.Index[PrivateNetwork, string]{
		Name: "name",
		FromObject: func(obj PrivateNetwork) index.KeySet {
			return index.NewKeySet(index.String(string(obj.Name)))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}

	// An index to keep track of the private networks that requesting
	// specific VNI. Used for the VNI conflict detection.
	privateNetworksRequestedVNIIndex = statedb.Index[PrivateNetwork, vni.VNI]{
		Name: "requested-vni",
		FromObject: func(obj PrivateNetwork) index.KeySet {
			if obj.RequestedVNI.IsValid() {
				return index.NewKeySet(vni.StateDBKey(obj.RequestedVNI))
			}
			return index.NewKeySet()
		},
		FromKey: vni.StateDBKey,
		FromString: func(key string) (index.Key, error) {
			got, err := vni.Parse(key)
			return vni.StateDBKey(got), err
		},
	}
)

// PrivateNetworkByName queries the private networks table by name.
func PrivateNetworkByName(name tables.NetworkName) statedb.Query[PrivateNetwork] {
	return privateNetworksNameIndex.Query(string(name))
}

// PrivateNetworksByRequestedVNI queries the private networks table by requested VNI.
func PrivateNetworksByRequestedVNI(vni vni.VNI) statedb.Query[PrivateNetwork] {
	return privateNetworksRequestedVNIIndex.Query(vni)
}

func NewPrivateNetworksTable(config config.Config, db *statedb.DB) (statedb.RWTable[PrivateNetwork], error) {
	return statedb.NewTable(
		db,
		"private-networks",
		privateNetworksNameIndex,
		privateNetworksRequestedVNIIndex,
	)
}
