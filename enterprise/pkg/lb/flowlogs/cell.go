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
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/bpf"
)

var Cell = cell.Module(
	"loadbalancer-flowlog",
	"Per-packet loadbalancer flow logs",

	cell.Invoke(Config.validate),
	cell.Invoke(initializeFlowLogProcessor),
	cell.ProvidePrivate(newFlowLogIPFixSender),
	cell.ProvidePrivate(newFlowLogStdoutSender),
	cell.Provide(newFlowLogMap),
	cell.Provide(datapathConfigProvider),
	cell.Config(defaultConfig),
)

type lbFlowLogProcessorParams struct {
	cell.In

	Config   Config
	Logger   *slog.Logger
	Map      LBFlowLogMap
	Senders  []FlowLogSender `group:"flowlog-senders"`
	JobGroup job.Group
}

type lbFlowLogSenderOut struct {
	cell.Out

	Sender FlowLogSender `group:"flowlog-senders"`
}

func initializeFlowLogProcessor(p lbFlowLogProcessorParams) error {
	if !p.Config.LoadbalancerFlowLogsEnabled {
		return nil
	}

	var sender FlowLogSender = nil
	for _, rs := range p.Senders {
		if rs != nil && p.Config.LoadbalancerFlowLogsSender == rs.Name() {
			sender = rs
		}
	}

	if sender == nil {
		return fmt.Errorf("failed to find flow log sender %q", p.Config.LoadbalancerFlowLogsSender)
	}

	processor := &flowLogProcessor{
		logger:          p.Logger,
		reportFrequency: p.Config.ReportFrequencyDuration(),
		gcFrequency:     p.Config.GarbageCollectorFrequencyDuration(),
		sender:          sender,
		lbmap:           p.Map,
	}

	p.JobGroup.Add(job.OneShot("flowlog-processor", processor.startProcessing))

	return nil
}

type lbFlowLogIPFixSenderParams struct {
	cell.In

	Config Config
	Logger *slog.Logger
}

func newFlowLogIPFixSender(p lbFlowLogIPFixSenderParams) (lbFlowLogSenderOut, error) {
	if !p.Config.LoadbalancerFlowLogsEnabled || p.Config.LoadbalancerFlowLogsSender != "ipfix" {
		return lbFlowLogSenderOut{}, nil
	}

	collectors, err := parseCollectorAddresses(p.Config.LoadbalancerFlowLogsSenderIpfixCollectorAddress)
	if err != nil {
		return lbFlowLogSenderOut{}, err
	}
	if len(collectors) == 0 {
		return lbFlowLogSenderOut{}, fmt.Errorf("IPFix collector address list is empty")
	}

	sender := &flowLogIPFixSender{
		logger:             p.Logger,
		collectorAddresses: collectors,
		collectorProtocol:  p.Config.LoadbalancerFlowLogsSenderProtocol,
	}

	sender.loadRegistry()

	return lbFlowLogSenderOut{Sender: sender}, nil
}

type lbFlowLogMapParams struct {
	cell.In

	Config    Config
	Lifecycle cell.Lifecycle
	Logger    *slog.Logger
}

func newFlowLogMap(p lbFlowLogMapParams) (bpf.MapOut[LBFlowLogMap], error) {
	if !p.Config.LoadbalancerFlowLogsEnabled {
		return bpf.NewMapOut(LBFlowLogMap(nil)), nil
	}

	lbFlowLogMap, err := newLbFlowLogMap(p.Config, p.Logger)
	if err != nil {
		return bpf.NewMapOut(LBFlowLogMap(nil)), err
	}

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return lbFlowLogMap.openOrCreate()
		},
		OnStop: func(context cell.HookContext) error {
			return lbFlowLogMap.close()
		},
	})

	return bpf.NewMapOut(LBFlowLogMap(lbFlowLogMap)), nil
}
