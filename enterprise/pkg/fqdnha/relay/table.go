//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

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
