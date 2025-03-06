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
	"encoding/binary"
	"fmt"
	"log/slog"
	"sort"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type flowLogProcessor struct {
	logger *slog.Logger

	gcFrequency     time.Duration
	reportFrequency time.Duration

	reader *flowLogReader
	sender FlowLogSender
}

type FlowLogSender interface {
	Name() string
	SendFlowLogs(flowLogs FlowLogTable) error
}

func (r *flowLogProcessor) startProcessing(ctx context.Context, health cell.Health) error {
	r.logger.Info("Starting flow log processing")

	reportTicker := time.NewTicker(r.reportFrequency)

	allFlowLogs := make(FlowLogTable)
	newFlowLogs := make(FlowLogTable)

	consequentErrors := 0

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Stopping flow log processing", logfields.Error, ctx.Err())
			return ctx.Err()
		case entry := <-r.reader.flowLogs():
			firstTs := newFlowLogs[entry.Key].firstTs
			if firstTs.IsZero() {
				firstTs = entry.ts
			}
			newFlowLogs[entry.Key] = FlowLogEntry{
				Key:     entry.Key,
				Packets: newFlowLogs[entry.Key].Packets + entry.Packets,
				Bytes:   newFlowLogs[entry.Key].Bytes + entry.Bytes,
				ts:      entry.ts,
				firstTs: firstTs,
			}
		case <-reportTicker.C:
			r.logger.Debug("Reporting flow logs via sender")
			r.mergeFlowLogs(newFlowLogs, allFlowLogs)

			// keep it in code, but do not execute
			if false {
				r.debugDumpFlowLogs(allFlowLogs)
			}

			if err := r.sender.SendFlowLogs(allFlowLogs); err != nil {
				r.logger.Error("Failed to send flow logs", logfields.Error, err)
				health.Degraded("Failed to send flow logs", err)
				consequentErrors += 1
			}

			// In case there is no error, or this was impossible to
			// send out data for ten times in a raw, cleanup the
			// table, such that it's size will not grow forever.
			if consequentErrors%10 == 0 {
				r.cleanupFlowLogs(allFlowLogs, time.Now().Add(-r.gcFrequency))
				consequentErrors = 0
			}

			newFlowLogs = make(FlowLogTable)
		}
	}
}

func (r *flowLogProcessor) mergeFlowLogs(newFlowLogs, allFlowLogs FlowLogTable) {
	totalPackets := uint64(0)
	totalBytes := uint64(0)

	for k, v := range newFlowLogs {
		totalPackets += v.Packets
		totalBytes += v.Bytes

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

	bw := float64(totalBytes) / float64(r.reportFrequency) / 1024 / 1024
	r.logger.Info("Successfully merged new flow logs", "totalPackets", totalPackets, "totalBytes", totalBytes, "bw", bw)
}

func (r *flowLogProcessor) cleanupFlowLogs(bigTable FlowLogTable, cleanupTime time.Time) {
	r.logger.Debug("Cleaning up flow logs", "cleanup-time", cleanupTime)
	for k, v := range bigTable {
		if v.ts.Before(cleanupTime) {
			r.logger.Debug("Deleting flow logs", "key", r.flowLogRecordKeyToString(k))
			delete(bigTable, k)
		}
	}
}

func (r *flowLogProcessor) debugDumpFlowLogs(allFlowLogs FlowLogTable) {
	keys := make([]string, 0, len(allFlowLogs))
	for key := range allFlowLogs {
		keys = append(keys, key)
	}
	sort.SliceStable(keys, func(i, j int) bool { return allFlowLogs[keys[i]].firstTs.Before(allFlowLogs[keys[j]].firstTs) })

	for _, k := range keys {
		v := allFlowLogs[k]
		r.logger.Debug("Flow log table entry", "start", v.firstTs, "last", v.ts, "key", r.flowLogRecordKeyToString(k), "packets", v.Packets, "bytes", v.Bytes)
	}
}

func (r *flowLogProcessor) flowLogRecordKeyToString(key string) string {
	bytes := []byte(key)

	ifindex := int(binary.NativeEndian.Uint32(bytes[ifindexStart : ifindexStart+ifindexSize]))
	srcIP := binary.BigEndian.Uint32(bytes[saddrStart : saddrStart+saddrSize])
	dstIP := binary.BigEndian.Uint32(bytes[daddrStart : daddrStart+daddrSize])
	srcPort := binary.BigEndian.Uint16(bytes[sportStart : sportStart+sportSize])
	dstPort := binary.BigEndian.Uint16(bytes[dportStart : dportStart+dportSize])
	nexthdr := bytes[nexthdrStart]

	ifName, err := InterfaceByIndex(ifindex)
	if err != nil {
		r.logger.Error("InterfaceByIndex", logfields.Error, err, "ifindex", ifindex)
		ifName = "<unknown>"
	}

	protocol := ""
	switch nexthdr {
	case 6:
		protocol = "tcp"
	case 17:
		protocol = "udp"
	case 1:
		protocol = "icmp"
	default:
		protocol = "<unknown>"
		r.logger.Warn("Unexpected flow log protocol", "nexthdr", nexthdr)
	}

	return fmt.Sprintf("[%s] %08x:%d -> %08x:%d [%s]", ifName, srcIP, srcPort, dstIP, dstPort, protocol)
}
