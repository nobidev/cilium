//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lbflowlogs

import (
	"github.com/cilium/cilium/pkg/bpf"

	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"lbflowlog-map",
	"per-node eBPF map which is populated with per-packet flow logs",

	cell.Provide(newFlowLogsMap, datapathNodeHeaderConfigProvider),
	cell.Config(defaultConfig),
)

type lbFlowLogMapParams struct {
	cell.In

	Config    Config
	Lifecycle cell.Lifecycle
}

func newFlowLogsMap(p lbFlowLogMapParams) (out struct {
	cell.Out

	bpf.MapOut[LBFlowLogMap]
}) {
	if !p.Config.LoadbalancerFlowLogsEnabled {
		return
	}

	senderLoadRegistry()

	lbFlowLogRB := newLbFlowLogMap(p.Config, v4MapName)

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error { return lbFlowLogRB.openOrCreate(&p.Config) },
		OnStop:  func(context cell.HookContext) error { return lbFlowLogRB.close() },
	})

	out.MapOut = bpf.NewMapOut(LBFlowLogMap(lbFlowLogRB))
	return
}

type LBFlowLogMap interface {
	Read() ([]byte, error)
}
