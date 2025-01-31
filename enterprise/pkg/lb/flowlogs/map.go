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
	"errors"
	"fmt"
	"os"
	"sort"

	"encoding/binary"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/time"

	ebpfRingBuf "github.com/cilium/ebpf/ringbuf"
)

type lbFlowLogMap struct {
	bpfMap *ebpf.Map
	reader *ebpfRingBuf.Reader
}

func newLbFlowLogMap(config Config, name string) *lbFlowLogMap {
	return &lbFlowLogMap{
		bpfMap: ebpf.NewMap(&ebpf.MapSpec{
			Name:       name,
			Type:       ebpf.RingBuf,
			MaxEntries: config.LoadbalancerFlowLogsMapSize,
			Pinning:    ebpf.PinByName,
		}),
	}
}

func (m *lbFlowLogMap) openOrCreate(config *Config) error {
	if err := m.bpfMap.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}
	if reader, err := ebpfRingBuf.NewReader(m.bpfMap.Map); err != nil {
		return fmt.Errorf("failed to create ringbuf reader: %w", err)
	} else {
		m.reader = reader
		go flowLogsMainLoop(m.reader, config)
	}

	return nil
}

func (m *lbFlowLogMap) close() error {
	if err := m.bpfMap.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}
	return nil
}

func (m *lbFlowLogMap) Read() ([]byte, error) {
	return []byte{}, nil
}

type FlowLogRecord struct {
	// key part, 16 bytes
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Nexthdr uint8
	Pad0    uint8
	Pad1    uint8
	Pad2    uint8
	// value part
	Bytes uint64
}

func flowLogRecordKeyToString(key string) string {
	bytes := []byte(key)

	srcIP := binary.BigEndian.Uint32(bytes[0:4])
	dstIP := binary.BigEndian.Uint32(bytes[4:8])
	srcPort := binary.BigEndian.Uint16(bytes[8:10])
	dstPort := binary.BigEndian.Uint16(bytes[10:12])

	s := ""
	nexthdr := bytes[12]
	if nexthdr == 6 {
		s = "tcp"
	} else if nexthdr == 17 {
		s = "udp"
	} else if nexthdr == 1 {
		s = "icmp"
	}

	return fmt.Sprintf("%08x:%d -> %08x:%d [%s]", srcIP, srcPort, dstIP, dstPort, s)
}

type FlowLogKey = string
type FlowLogEntry = struct {
	Packets uint64    // ATM, the # of records received
	Bytes   uint64    // bytes, accumulated from summind records
	ts      time.Time // the last update
}
type FlowLogTable = map[FlowLogKey]FlowLogEntry

func prepareFlowLogs(currTable, bigTable FlowLogTable, now time.Time, config *Config) {

	totalPackets := uint64(0)
	totalBytes := uint64(0)

	for k, v := range currTable {
		totalPackets += v.Packets
		totalBytes += v.Bytes

		e := FlowLogEntry{
			Packets: bigTable[k].Packets + v.Packets,
			Bytes:   bigTable[k].Bytes + v.Bytes,
			ts:      v.ts,
		}
		bigTable[k] = e
	}

	bw := float64(totalBytes) / float64(config.LoadbalancerFlowLogsReportFrequency) / 1024 / 1024
	log.Info(fmt.Sprintf("prepareFlowLogs: totalPackets=%d totalBytes=%d bw=%.2f MB/s", totalPackets, totalBytes, bw))
}

func cleanupFlowLogs(bigTable FlowLogTable, now time.Time, config *Config) {
	for k, v := range bigTable {
		if v.ts.Add(config.GarbageCollectorFrequencyToSeconds()).Before(now) {
			delete(bigTable, k)
		}
	}
}

func debugDumpFlowLogs(bigTable FlowLogTable) {
	keys := make([]string, 0, len(bigTable))
	for key := range bigTable {
		keys = append(keys, key)
	}
	sort.SliceStable(keys, func(i, j int) bool { return bigTable[keys[i]].ts.Before(bigTable[keys[j]].ts) })

	for _, k := range keys {
		v := bigTable[k]
		log.Debug(fmt.Sprintf("[%s] %s: %d packets, %d bytes", v.ts, flowLogRecordKeyToString(k), v.Packets, v.Bytes))
	}
}

func read(reader *ebpfRingBuf.Reader, table FlowLogTable, now time.Time) {
	reader.SetDeadline(now.Add(1 * time.Second))

	r, err := reader.Read()
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			log.Debug("flow log reader timeout")
		} else {
			log.Fatal(fmt.Errorf("flow log reader error: %w", err))
		}
	} else {
		n := len(r.RawSample)
		if (n < 24) || (n%24 != 0) {
			log.Error(fmt.Sprintf("record size is %d [expected 24]", len(r.RawSample)))
		} else {
			key := string(r.RawSample[0:16])
			bytes := binary.LittleEndian.Uint64(r.RawSample[16:24])
			e := FlowLogEntry{
				Packets: table[key].Packets + 1,
				Bytes:   table[key].Bytes + bytes,
				ts:      now,
			}
			table[key] = e
		}
	}
}

func flowLogsMainLoop(reader *ebpfRingBuf.Reader, config *Config) {
	prevReportTime := time.Now()
	nextReportTime := prevReportTime.Add(config.ReportFrequencyToSeconds())

	bigTable := make(FlowLogTable)
	currTable := make(FlowLogTable)

	consequentErrors := 0

	for {
		now := time.Now()

		if now.After(nextReportTime) {
			prepareFlowLogs(currTable, bigTable, now, config)

			debugDumpFlowLogs(bigTable)

			if err := sendFlowLogs(bigTable, config); err != nil {
				log.WithError(err).Error("couldn't send flow logs")
				consequentErrors += 1
			}

			// In case there is no error, or this was impossible to
			// send out data for ten times in a raw, cleanup the
			// table, such that it's size will not grow forever
			if consequentErrors%10 == 0 {
				cleanupFlowLogs(bigTable, now, config)
				consequentErrors = 0
			}

			currTable = make(FlowLogTable)

			prevReportTime = now
			nextReportTime = prevReportTime.Add(config.ReportFrequencyToSeconds())
		}

		read(reader, currTable, now)
	}
}
