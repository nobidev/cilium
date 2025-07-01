//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package diagnostics

import (
	"errors"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
)

// Registry of diagnostics conditions.
type Registry struct {
	params registryParams
}

type registryParams struct {
	cell.In

	DB         *statedb.DB
	Conditions statedb.RWTable[ConditionStatus]
}

func NewRegistry(p registryParams) *Registry {
	return &Registry{p}
}

// Register a condition. This can be called at any time, e.g. before Hive starts,
// or after start.
//
// Returns an error if any of the given conditions has no associated metadata.
// On errors none of the conditions will be registered.
func (reg *Registry) Register(conditions ...Condition) error {
	txn := reg.params.DB.WriteTxn(reg.params.Conditions)
	var errs error
	for _, cond := range conditions {
		if err := cond.validate(); err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		reg.params.Conditions.Insert(txn, ConditionStatus{Condition: cond})
	}
	if errs != nil {
		txn.Abort()
	} else {
		txn.Commit()
	}
	return errs
}

func (reg *Registry) Unregister(conditions ...Condition) {
	txn := reg.params.DB.WriteTxn(reg.params.Conditions)
	for _, cond := range conditions {
		reg.params.Conditions.Delete(txn, ConditionStatus{Condition: cond})
	}
	txn.Commit()
}
