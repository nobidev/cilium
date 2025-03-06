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

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type flowLogReader struct {
	logger      *slog.Logger
	flowLogMap  LBFlowLogMap
	entriesChan chan *FlowLogEntry
}

func (r *flowLogReader) startReading(ctx context.Context, health cell.Health) error {
	r.logger.Info("Starting reading flow log")

	reader, err := r.flowLogMap.newRingBufferReader()
	if err != nil {
		return fmt.Errorf("failed to create ringbuffer reader for reading flow log: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Stop reading flow log", logfields.Error, err)
			return ctx.Err()
		default:
			entry, err := r.readEntry(reader)
			if err != nil {
				r.logger.Error("Failed to read flow logs", logfields.Error, err)
				health.Degraded("Failed to read flow logs", err)
			}

			r.entriesChan <- entry
		}
	}
}

func (r *flowLogReader) flowLogs() <-chan *FlowLogEntry {
	return r.entriesChan
}

func (r *flowLogReader) readEntry(reader RingBufferReader) (*FlowLogEntry, error) {
	rec, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("unexpected flow log reader error: %w", err)
	}

	n := len(rec.RawSample)
	if (n < 32) || (n%32 != 0) {
		return nil, fmt.Errorf("unexpected record size in flow log [size %d, expected 32]", len(rec.RawSample))
	}

	return &FlowLogEntry{
		Key:     string(rec.RawSample[0:bytesStart]),
		Packets: 1,
		Bytes:   binary.LittleEndian.Uint64(rec.RawSample[bytesStart : bytesStart+bytesSize]),
		ts:      time.Now(),
	}, nil
}
