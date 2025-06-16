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
	"context"
	"fmt"
	"net"

	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type flowLogProcessor struct {
	logger *slog.Logger

	gcFrequency     time.Duration
	reportFrequency time.Duration
	lastReport      time.Time

	lbmap  LBFlowLogMap
	sender FlowLogSender
}

type FlowLogSender interface {
	Name() string
	SendFlowLogs(flowLogsV4 FlowLogTableV4, flowLogsV6 FlowLogTableV6, flowLogsL2 FlowLogTableL2) error
}

func (r *flowLogProcessor) startProcessing(ctx context.Context, health cell.Health) error {
	r.logger.Info("Starting flow log processing")

	reportTicker := time.NewTicker(r.reportFrequency)

	allFlowLogsV4 := make(FlowLogTableV4)
	allFlowLogsV6 := make(FlowLogTableV6)
	allFlowLogsL2 := make(FlowLogTableL2)

	consequentErrors := 0

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Stopping flow log processing", logfields.Error, ctx.Err())
			return ctx.Err()
		case <-reportTicker.C:
			newFlowLogsV4, newFlowLogsV6, newFlowLogsL2, err := r.lbmap.ReadFlowLogs()
			if err != nil {
				r.logger.Error("Failed to read flow logs", logfields.Error, err)
				health.Degraded("Failed to read flow logs", err)
				continue
			}
			r.logger.Debug("Read flow logs: v4, v6, l2",
				logfields.Size, len(newFlowLogsV4),
				logfields.Size, len(newFlowLogsV6),
				logfields.Size, len(newFlowLogsL2))

			now := time.Now()
			r.mergeFlowLogsV4(newFlowLogsV4, allFlowLogsV4, now)
			r.mergeFlowLogsV6(newFlowLogsV6, allFlowLogsV6, now)
			r.mergeFlowLogsL2(newFlowLogsL2, allFlowLogsL2, now)
			r.lastReport = now

			err = r.sender.SendFlowLogs(allFlowLogsV4, allFlowLogsV6, allFlowLogsL2)
			if err != nil {
				r.logger.Error("Failed to send flow logs", logfields.Error, err)
				health.Degraded("Failed to send flow logs", err)
				consequentErrors += 1
			}

			// In case there is no error, or this was impossible to
			// send out data for ten times in a raw, cleanup the
			// table, such that it's size will not grow forever.
			if consequentErrors%10 == 0 {
				t := time.Now().Add(-r.gcFrequency)
				r.cleanupFlowLogsV4(allFlowLogsV4, t)
				r.cleanupFlowLogsV6(allFlowLogsV6, t)
				r.cleanupFlowLogsL2(allFlowLogsL2, t)
				consequentErrors = 0
			}
		}
	}
}

func bandwidth2Str(bytes uint64, duration time.Duration) string {
	kbs := float64(bytes) * float64(time.Second) / float64(duration) / 1024
	if kbs >= 1024 {
		return fmt.Sprintf("%.2f Mb/s", kbs/1024)
	} else {
		return fmt.Sprintf("%.2f Kb/s", kbs)
	}
}

func (r *flowLogProcessor) mergeFlowLogsV4(newFlowLogs, allFlowLogs FlowLogTableV4, now time.Time) {
	packetsTotal := uint64(0)
	bytesTotal := uint64(0)

	for k, v := range newFlowLogs {
		packetsTotal += v.Packets
		bytesTotal += v.Bytes

		firstTs := allFlowLogs[k].firstTs
		if firstTs.IsZero() {
			firstTs = v.firstTs
		}

		e := FlowLogEntry{
			Packets: allFlowLogs[k].Packets + v.Packets,
			Bytes:   allFlowLogs[k].Bytes + v.Bytes,
			ts:      v.ts,
			firstTs: firstTs,
		}
		allFlowLogs[k] = e
	}

	timeSinceLastCalculation := r.reportFrequency
	if !r.lastReport.IsZero() {
		timeSinceLastCalculation = now.Sub(r.lastReport)
	}

	r.logger.Info("Successfully merged new IPv4 flow logs",
		logfields.PacketsTotal,
		packetsTotal,
		logfields.BytesTotal,
		bytesTotal,
		logfields.Bandwidth,
		bandwidth2Str(bytesTotal, timeSinceLastCalculation))
}

func (r *flowLogProcessor) mergeFlowLogsV6(newFlowLogs, allFlowLogs FlowLogTableV6, now time.Time) {
	packetsTotal := uint64(0)
	bytesTotal := uint64(0)

	for k, v := range newFlowLogs {
		packetsTotal += v.Packets
		bytesTotal += v.Bytes

		firstTs := allFlowLogs[k].firstTs
		if firstTs.IsZero() {
			firstTs = v.firstTs
		}

		e := FlowLogEntry{
			Packets: allFlowLogs[k].Packets + v.Packets,
			Bytes:   allFlowLogs[k].Bytes + v.Bytes,
			ts:      v.ts,
			firstTs: firstTs,
		}
		allFlowLogs[k] = e
	}

	timeSinceLastCalculation := r.reportFrequency
	if !r.lastReport.IsZero() {
		timeSinceLastCalculation = now.Sub(r.lastReport)
	}

	r.logger.Info("Successfully merged new IPv6 flow logs",
		logfields.PacketsTotal,
		packetsTotal,
		logfields.BytesTotal,
		bytesTotal,
		logfields.Bandwidth,
		bandwidth2Str(bytesTotal, timeSinceLastCalculation))
}

func (r *flowLogProcessor) mergeFlowLogsL2(newFlowLogs, allFlowLogs FlowLogTableL2, now time.Time) {
	packetsTotal := uint64(0)
	bytesTotal := uint64(0)

	for k, v := range newFlowLogs {
		packetsTotal += v.Packets
		bytesTotal += v.Bytes

		firstTs := allFlowLogs[k].firstTs
		if firstTs.IsZero() {
			firstTs = v.firstTs
		}

		e := FlowLogEntry{
			Packets: allFlowLogs[k].Packets + v.Packets,
			Bytes:   allFlowLogs[k].Bytes + v.Bytes,
			ts:      v.ts,
			firstTs: firstTs,
		}
		allFlowLogs[k] = e
	}

	timeSinceLastCalculation := r.reportFrequency
	if !r.lastReport.IsZero() {
		timeSinceLastCalculation = now.Sub(r.lastReport)
	}

	r.logger.Info("Successfully merged new L2 flow logs",
		logfields.PacketsTotal,
		packetsTotal,
		logfields.BytesTotal,
		bytesTotal,
		logfields.Bandwidth,
		bandwidth2Str(bytesTotal, timeSinceLastCalculation))
}

func (r *flowLogProcessor) cleanupFlowLogsV4(bigTable FlowLogTableV4, cleanupTime time.Time) {
	r.logger.Debug("Cleaning up flow logs", logfields.CleanupTime, cleanupTime)
	for k, v := range bigTable {
		if v.ts.Before(cleanupTime) {
			r.logger.Debug("Deleting flow logs", logfields.Key, r.flowLogRecordKeyToStringV4(k))
			delete(bigTable, k)
		}
	}
}

func (r *flowLogProcessor) cleanupFlowLogsV6(bigTable FlowLogTableV6, cleanupTime time.Time) {
	r.logger.Debug("Cleaning up flow logs", logfields.CleanupTime, cleanupTime)
	for k, v := range bigTable {
		if v.ts.Before(cleanupTime) {
			r.logger.Debug("Deleting flow logs", logfields.Key, r.flowLogRecordKeyToStringV6(k))
			delete(bigTable, k)
		}
	}
}

func (r *flowLogProcessor) cleanupFlowLogsL2(bigTable FlowLogTableL2, cleanupTime time.Time) {
	r.logger.Debug("Cleaning up flow logs", logfields.CleanupTime, cleanupTime)
	for k, v := range bigTable {
		if v.ts.Before(cleanupTime) {
			r.logger.Debug("Deleting flow logs", logfields.Key, r.flowLogRecordKeyToStringL2(k))
			delete(bigTable, k)
		}
	}
}

func (r *flowLogProcessor) flowLogRecordKeyToStringV4(key FlowLogKeyV4) string {
	ifName, err := InterfaceByIndex(int(key.Ifindex))
	if err != nil {
		r.logger.Error("InterfaceByIndex",
			logfields.Error, err,
			logfields.LinkIndex, key.Ifindex)
		ifName = "<unknown>"
	}

	protocol := ""
	switch key.Nexthdr {
	case 6:
		protocol = "tcp"
	case 17:
		protocol = "udp"
	case 1:
		protocol = "icmp"
	default:
		protocol = fmt.Sprintf("<nexthdr=%d>", key.Nexthdr)
	}

	return fmt.Sprintf("[%s] %08x:%d -> %08x:%d [%s]", ifName, key.SrcAddr, key.SrcPort, key.DstAddr, key.DstPort, protocol)
}

func (r *flowLogProcessor) flowLogRecordKeyToStringV6(key FlowLogKeyV6) string {
	ifName, err := InterfaceByIndex(int(key.Ifindex))
	if err != nil {
		r.logger.Error("InterfaceByIndex",
			logfields.Error, err,
			logfields.LinkIndex, key.Ifindex)
		ifName = "<unknown>"
	}

	protocol := ""
	switch key.Nexthdr {
	case 6:
		protocol = "tcp"
	case 17:
		protocol = "udp"
	case 58:
		protocol = "icmpv6"
	default:
		protocol = fmt.Sprintf("<nexthdr=%d>", key.Nexthdr)
	}

	return fmt.Sprintf("[%s] %s:%d -> %s:%d [%s]", ifName, net.IP(key.SrcAddr[:]), key.SrcPort, net.IP(key.DstAddr[:]), key.DstPort, protocol)
}

func (r *flowLogProcessor) flowLogRecordKeyToStringL2(key FlowLogKeyL2) string {
	ifName, err := InterfaceByIndex(int(key.Ifindex))
	if err != nil {
		r.logger.Error("InterfaceByIndex",
			logfields.Error, err,
			logfields.LinkIndex, key.Ifindex)
		ifName = "<unknown>"
	}
	return fmt.Sprintf("[%s] %s -> %s [%s]", ifName, net.HardwareAddr(key.SrcMac[:]), net.HardwareAddr(key.DstMac[:]), fmt.Sprintf("ethertype=%04x", key.Type))
}
