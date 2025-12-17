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

	"github.com/cilium/cilium/pkg/identity"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
)

// CIDRMetadata maps a prefix to a list of owners, which each have associated
// metadata with this CIDR
type CIDRMetadata struct {
	Prefix netip.Prefix
	Owners map[ipcacheTypes.ResourceID]CIDRMetadataInfo
}

// CIDRMetadataInfo contains the metadata a certain owner has associated with a given CIDR.
type CIDRMetadataInfo struct {
	// CIDRLabel is true if this CIDR should have `cidr` labels
	CIDRLabel bool
	// CIDRGroupLabels contains the `cidrgroup` labels that are added to this CIDR by the owner
	CIDRGroupLabels labels.Labels
	// RestoredIdentity contains the numeric identity which was restored from a prior BPF map
	RestoredIdentity identity.NumericIdentity
}

// IsEmpty returns true if no metadata is set
func (c *CIDRMetadataInfo) IsEmpty() bool {
	return !c.CIDRLabel &&
		len(c.CIDRGroupLabels) == 0 &&
		c.RestoredIdentity == identity.IdentityUnknown
}

var _ statedb.TableWritable = &CIDRMetadata{}

func (c CIDRMetadata) TableHeader() []string {
	return []string{"CIDR", "Owners"}
}

func (c CIDRMetadata) TableRow() []string {
	return []string{
		c.Prefix.String(),
		fmt.Sprintf("%d", len(c.Owners)),
	}
}

var (
	cidrMetadataPrefixIndex = statedb.Index[CIDRMetadata, netip.Prefix]{
		Name: "cidr",
		FromObject: func(obj CIDRMetadata) index.KeySet {
			return index.NewKeySet(index.NetIPPrefix(obj.Prefix))
		},
		FromKey:    index.NetIPPrefix,
		FromString: index.NetIPPrefixString,
		Unique:     true,
	}
)

func CIDRMetadataByPrefix(cidr netip.Prefix) statedb.Query[CIDRMetadata] {
	return cidrMetadataPrefixIndex.Query(cidr)
}

func NewCIDRMetadataTable(db *statedb.DB) (statedb.RWTable[CIDRMetadata], error) {
	return statedb.NewTable(
		db,
		"privnet-cidr-metadata",
		cidrMetadataPrefixIndex,
	)
}
