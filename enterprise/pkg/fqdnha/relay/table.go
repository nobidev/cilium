// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package relay

import (
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/policy/api"
)

type FQDNSelectorKey = string
type FQDNSelector api.FQDNSelector

var FQDNSelectorIndex = statedb.Index[FQDNSelector, FQDNSelectorKey]{
	Name: "id",
	FromObject: func(obj FQDNSelector) index.KeySet {
		return index.NewKeySet(index.String(obj.String()))
	},
	FromKey: index.String,
	Unique:  true,
}

func NewFQDNSelectorTable(db *statedb.DB) (statedb.RWTable[FQDNSelector], error) {
	return statedb.NewTable("fqdn-selectors", FQDNSelectorIndex)
}

func (s *FQDNSelector) String() string {
	return (*api.FQDNSelector)(s).String()
}

func (s FQDNSelector) TableHeader() []string {
	return []string{"MatchName", "MatchPattern"}
}

func (s FQDNSelector) TableRow() []string {
	return []string{s.MatchName, s.MatchPattern}
}
