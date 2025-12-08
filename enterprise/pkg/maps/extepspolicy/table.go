//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package extepspolicy

import (
	"encoding"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/bpf"
)

var _ statedb.TableWritable = &entry{}

type entry struct {
	ip netip.Addr

	policyMapName string
	policyMapFD   uint32

	status reconciler.Status
}

func (e *entry) TableHeader() []string {
	return []string{"Address", "Policy Map Name", "Status"}
}

func (e *entry) TableRow() []string {
	return []string{e.ip.String(), e.policyMapName, e.status.String()}
}

func (e *entry) BinaryKey() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &Key{bpf.NewEndpointKey(e.ip, 0)}}
}

func (e *entry) BinaryValue() encoding.BinaryMarshaler {
	return bpf.StructBinaryMarshaler{Target: &Value{e.policyMapFD}}
}

func (e *entry) clone() *entry {
	cpy := *e
	return &cpy
}

func (e *entry) getStatus() reconciler.Status {
	return e.status
}

func (e *entry) setStatus(status reconciler.Status) *entry {
	e.status = status
	return e
}

var (
	primaryIndex = statedb.Index[*entry, netip.Addr]{
		Name: "address",
		FromObject: func(obj *entry) index.KeySet {
			return index.NewKeySet(index.NetIPAddr(obj.ip))
		},
		FromKey:    index.NetIPAddr,
		FromString: index.NetIPAddrString,
		Unique:     true,
	}
)

func newTable(db *statedb.DB) (statedb.RWTable[*entry], error) {
	return statedb.NewTable(
		db,
		"ext-eps-policy-map",
		primaryIndex,
	)
}

func registerReconciler(en enabled, tbl statedb.RWTable[*entry], m *extEpsPolMap, params reconciler.Params) (reconciler.Reconciler[entry], error) {
	if !en {
		return nil, nil
	}

	return reconciler.Register(
		params,
		tbl,
		(*entry).clone,
		(*entry).setStatus,
		(*entry).getStatus,
		bpf.NewMapOps[*entry](m.m),
		nil,
	)
}
