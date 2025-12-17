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

	"github.com/cilium/cilium/pkg/identity"
)

// CIDRIdentity maps a prefix to an identity
type CIDRIdentity struct {
	Prefix   netip.Prefix
	Identity identity.NumericIdentity
	Status   reconciler.Status
}

var _ statedb.TableWritable = CIDRIdentity{}

func (c CIDRIdentity) TableHeader() []string {
	return []string{"CIDR", "Identity", "Status"}
}

func (c CIDRIdentity) TableRow() []string {
	return []string{
		c.Prefix.String(),
		c.Identity.String(),
		c.Status.String(),
	}
}

var (
	cidrIdentityPrefixIndex = statedb.Index[CIDRIdentity, netip.Prefix]{
		Name: "cidr",
		FromObject: func(obj CIDRIdentity) index.KeySet {
			return index.NewKeySet(index.NetIPPrefix(obj.Prefix))
		},
		FromKey:    index.NetIPPrefix,
		FromString: index.NetIPPrefixString,
		Unique:     true,
	}
)

// CIDRIdentityByPrefix queries the private network CIDR identities table by exact prefix match
func CIDRIdentityByPrefix(cidr netip.Prefix) statedb.Query[CIDRIdentity] {
	return cidrIdentityPrefixIndex.Query(cidr)
}

func NewCIDRIdentitiesTable(db *statedb.DB) (statedb.RWTable[CIDRIdentity], error) {
	return statedb.NewTable(
		db,
		"privnet-cidr-identities",
		cidrIdentityPrefixIndex,
	)
}
