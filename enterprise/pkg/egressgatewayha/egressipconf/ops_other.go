//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build !linux

package egressipconf

import (
	"context"
	"iter"
	"log/slog"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/datapath/tables"
)

func (o *ops) Update(ctx context.Context, txn statedb.ReadTxn, obj *tables.EgressIPEntry) error {
	return ErrNotImplemented
}

func (o *ops) Delete(context.Context, statedb.ReadTxn, *tables.EgressIPEntry) error {
	return ErrNotImplemented
}

func (o *ops) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*tables.EgressIPEntry, statedb.Revision]) error {
	return ErrNotImplemented
}

func newOps(logger *slog.Logger) *ops {
	return &ops{logger}
}

type ops struct {
	logger *slog.Logger
}

var _ reconciler.Operations[*tables.EgressIPEntry] = &ops{}
