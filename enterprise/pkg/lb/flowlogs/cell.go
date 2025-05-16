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

	cell.Invoke(initializeFlowLogProcessor),
	cell.ProvidePrivate(newFlowLogReader),
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
	Reader   *flowLogReader
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
		if p.Config.LoadbalancerFlowLogsSender == rs.Name() {
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
		reader:          p.Reader,
	}

	p.JobGroup.Add(job.OneShot("flowlog-processor", processor.startProcessing))

	return nil
}

type lbFlowLogReaderParams struct {
	cell.In

	Config   Config
	Logger   *slog.Logger
	Map      LBFlowLogMap
	JobGroup job.Group
}

func newFlowLogReader(p lbFlowLogReaderParams) *flowLogReader {
	if !p.Config.LoadbalancerFlowLogsEnabled {
		return nil
	}

	reader := &flowLogReader{
		logger:      p.Logger,
		flowLogMap:  p.Map,
		entriesChan: make(chan *FlowLogEntry, p.Config.LoadbalancerFlowLogsReaderQueueSize),
	}

	p.JobGroup.Add(job.OneShot("flowlog-reader", reader.startReading))

	return reader
}

type lbFlowLogIPFixSenderParams struct {
	cell.In

	Config Config
	Logger *slog.Logger
}

func newFlowLogIPFixSender(p lbFlowLogIPFixSenderParams) lbFlowLogSenderOut {
	if !p.Config.LoadbalancerFlowLogsEnabled {
		return lbFlowLogSenderOut{}
	}

	sender := &flowLogIPFixSender{
		logger:            p.Logger,
		collectorAddress:  p.Config.LoadbalancerFlowLogsSenderIpfixCollectorAddress,
		collectorProtocol: p.Config.LoadbalancerFlowLogsSenderProtocol,
	}

	sender.loadRegistry()

	return lbFlowLogSenderOut{Sender: sender}
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

	lbFlowLogMap := newLbFlowLogMap(p.Logger, p.Config, v4MapName)

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
