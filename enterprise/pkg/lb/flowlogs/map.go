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
	"net"

	"log/slog"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/time"

	"golang.org/x/sys/unix"
)

type lbFlowLogMap struct {
	logger *slog.Logger

	/*
	 * To make things scalable the following approach is implemented.
	 * For every flow create two tables: table1 and table2 (e.g.,
	 * v4table1/v4table2 for IPv4, etc.).
	 *
	 * The currentTable variable, via the tableSelector map, controls
	 * which of tables, table1 or table2, the datapath should use to
	 * update flow logs. The following values are accepted:
	 *
	 *     0: flow logs are disabled
	 *     1: flow logs are written to table1
	 *     2: flow logs are written to table2
	 *
	 * Only the cilium agent writes to this variable. When a write
	 * occurs, before summarizing the old table, agent waits for a
	 * period of time long enough that all the writes to the old table
	 * are finished. Then no locking is required to read all the keys
	 * from the inactive table.
	 *
	 * See the ReadFlowLogs() below.
	 */

	currentTable  uint64
	tableSelector *ebpf.Map
	bootTime      time.Time
	// v4
	v4table1 *ebpf.Map
	v4table2 *ebpf.Map
	// v6
	v6table1 *ebpf.Map
	v6table2 *ebpf.Map
	// l2
	l2table1 *ebpf.Map
	l2table2 *ebpf.Map
}

/*
 * The structures below must be in sync with the BPF definitions
 * in lib/enterprise_xdp.h; and vice versa.
 */

type FlowLogKeyV4 = struct {
	Ifindex uint32
	SrcAddr uint32
	DstAddr uint32
	SrcPort uint16
	DstPort uint16
	Nexthdr uint8
	Pad0    uint8
	Pad1    uint8
	Pad2    uint8
}

type FlowLogKeyV6 = struct {
	SrcAddr [16]uint8
	DstAddr [16]uint8
	Ifindex uint32
	SrcPort uint16
	DstPort uint16
	Nexthdr uint8
	Pad0    uint8
	Pad1    uint8
	Pad2    uint8
}

type FlowLogKeyL2 = struct {
	DstMac  [6]uint8
	SrcMac  [6]uint8
	Ifindex uint32
	Type    uint16
	Pad0    uint16
}

type RealValue = struct {
	FlowStartNS uint64
	FlowEndNS   uint64
	Bytes       uint64
	Packets     uint64
}

const FlowLogKeyV4Size = 20
const FlowLogKeyV6Size = 44
const FlowLogKeyL2Size = 20
const FlowLogValueSize = 32

type FlowLogEntry = struct {
	Packets uint64    // ATM, the # of records received
	Bytes   uint64    // bytes, accumulated from summind records
	firstTs time.Time // the first update
	ts      time.Time // the last update
}

type FlowLogTableV4 = map[FlowLogKeyV4]FlowLogEntry
type FlowLogTableV6 = map[FlowLogKeyV6]FlowLogEntry
type FlowLogTableL2 = map[FlowLogKeyL2]FlowLogEntry

func getBootTime() (time.Time, error) {
	var tv unix.Timespec

	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &tv); err != nil {
		return time.Time{}, err
	}

	now := time.Now()
	return now.Add(-time.Duration(tv.Nano())), nil
}

func newLbFlowLogMap(config Config, logger *slog.Logger) (*lbFlowLogMap, error) {

	bootTime, err := getBootTime()
	if err != nil {
		return nil, err
	}

	return &lbFlowLogMap{
		logger:       logger,
		currentTable: uint64(1),
		bootTime:     bootTime,
		tableSelector: ebpf.NewMap(logger, &ebpf.MapSpec{
			Name:       tableSelectorName,
			Type:       ebpf.Array,
			MaxEntries: 1,
			KeySize:    4,
			ValueSize:  8,
			Pinning:    ebpf.PinByName,
		}),
		v4table1: ebpf.NewMap(logger, &ebpf.MapSpec{
			Name:       flv4Map1Name,
			Type:       ebpf.PerCPUHash,
			MaxEntries: config.LoadbalancerFlowLogsMapSize,
			KeySize:    FlowLogKeyV4Size,
			ValueSize:  FlowLogValueSize,
			Pinning:    ebpf.PinByName,
		}),
		v4table2: ebpf.NewMap(logger, &ebpf.MapSpec{
			Name:       flv4Map2Name,
			Type:       ebpf.PerCPUHash,
			MaxEntries: config.LoadbalancerFlowLogsMapSize,
			KeySize:    FlowLogKeyV4Size,
			ValueSize:  FlowLogValueSize,
			Pinning:    ebpf.PinByName,
		}),
		v6table1: ebpf.NewMap(logger, &ebpf.MapSpec{
			Name:       flv6Map1Name,
			Type:       ebpf.PerCPUHash,
			MaxEntries: config.LoadbalancerFlowLogsMapSize,
			KeySize:    FlowLogKeyV6Size,
			ValueSize:  FlowLogValueSize,
			Pinning:    ebpf.PinByName,
		}),
		v6table2: ebpf.NewMap(logger, &ebpf.MapSpec{
			Name:       flv6Map2Name,
			Type:       ebpf.PerCPUHash,
			MaxEntries: config.LoadbalancerFlowLogsMapSize,
			KeySize:    FlowLogKeyV6Size,
			ValueSize:  FlowLogValueSize,
			Pinning:    ebpf.PinByName,
		}),
		l2table1: ebpf.NewMap(logger, &ebpf.MapSpec{
			Name:       fll2Map1Name,
			Type:       ebpf.PerCPUHash,
			MaxEntries: config.LoadbalancerFlowLogsMapSize,
			KeySize:    FlowLogKeyL2Size,
			ValueSize:  FlowLogValueSize,
			Pinning:    ebpf.PinByName,
		}),
		l2table2: ebpf.NewMap(logger, &ebpf.MapSpec{
			Name:       fll2Map2Name,
			Type:       ebpf.PerCPUHash,
			MaxEntries: config.LoadbalancerFlowLogsMapSize,
			KeySize:    FlowLogKeyL2Size,
			ValueSize:  FlowLogValueSize,
			Pinning:    ebpf.PinByName,
		}),
	}, nil
}

func (m *lbFlowLogMap) ktimeToTime(tsSinceBoot uint64) time.Time {
	return m.bootTime.Add(time.Duration(tsSinceBoot))
}

func (m *lbFlowLogMap) openOrCreate() error {
	if err := m.tableSelector.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}
	if err := m.v4table1.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}
	if err := m.v4table2.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}
	if err := m.v6table1.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}
	if err := m.v6table2.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}
	if err := m.l2table1.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}
	if err := m.l2table2.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}

	return nil
}

func (m *lbFlowLogMap) close() error {
	if err := m.l2table2.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	if err := m.l2table1.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	if err := m.v6table2.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	if err := m.v6table1.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	if err := m.v4table2.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	if err := m.v4table1.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	if err := m.tableSelector.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	return nil
}

type LBFlowLogMap interface {
	ReadFlowLogs() (FlowLogTableV4, FlowLogTableV6, FlowLogTableL2, error)
}

func (m *lbFlowLogMap) readFlowLogsV4(table *ebpf.Map) (FlowLogTableV4, error) {
	iterator := table.Iterate()

	var key FlowLogKeyV4
	var values []RealValue

	flowLogTable := make(FlowLogTableV4)

	toDelete := make([]FlowLogKeyV4, 0)

	for iterator.Next(&key, &values) {

		value := RealValue{}
		for _, v := range values {
			value.Bytes += v.Bytes
			value.Packets += v.Packets

			// minimum, or init if zero
			if value.FlowStartNS == 0 {
				value.FlowStartNS = v.FlowStartNS
			} else if value.FlowStartNS > v.FlowStartNS {
				value.FlowStartNS = v.FlowStartNS
			}

			// maximum
			if value.FlowEndNS < v.FlowEndNS {
				value.FlowEndNS = v.FlowEndNS
			}
		}

		flowLogTable[key] = FlowLogEntry{
			Bytes:   value.Bytes,
			Packets: value.Packets,
			firstTs: m.ktimeToTime(value.FlowStartNS),
			ts:      m.ktimeToTime(value.FlowEndNS),
		}

		toDelete = append(toDelete, key)
	}

	if err := iterator.Err(); err != nil {
		return nil, err
	}

	for _, key := range toDelete {
		if err := table.Delete(&key); err != nil {
			return nil, err
		}
	}

	return flowLogTable, nil
}

func (m *lbFlowLogMap) readFlowLogsV6(table *ebpf.Map) (FlowLogTableV6, error) {
	iterator := table.Iterate()

	var key FlowLogKeyV6
	var values []RealValue

	flowLogTable := make(FlowLogTableV6)

	toDelete := make([]FlowLogKeyV6, 0)

	for iterator.Next(&key, &values) {

		value := RealValue{}
		for _, v := range values {
			value.Bytes += v.Bytes
			value.Packets += v.Packets

			// minimum, or init if zero
			if value.FlowStartNS == 0 {
				value.FlowStartNS = v.FlowStartNS
			} else if value.FlowStartNS > v.FlowStartNS {
				value.FlowStartNS = v.FlowStartNS
			}

			// maximum
			if value.FlowEndNS < v.FlowEndNS {
				value.FlowEndNS = v.FlowEndNS
			}
		}

		flowLogTable[key] = FlowLogEntry{
			Bytes:   value.Bytes,
			Packets: value.Packets,
			firstTs: m.ktimeToTime(value.FlowStartNS),
			ts:      m.ktimeToTime(value.FlowEndNS),
		}

		toDelete = append(toDelete, key)
	}

	if err := iterator.Err(); err != nil {
		return nil, err
	}

	for _, key := range toDelete {
		if err := table.Delete(&key); err != nil {
			return nil, err
		}
	}

	return flowLogTable, nil
}

func (m *lbFlowLogMap) readFlowLogsL2(table *ebpf.Map) (FlowLogTableL2, error) {
	iterator := table.Iterate()

	var key FlowLogKeyL2
	var values []RealValue

	flowLogTable := make(FlowLogTableL2)

	toDelete := make([]FlowLogKeyL2, 0)

	for iterator.Next(&key, &values) {

		value := RealValue{}
		for _, v := range values {
			value.Bytes += v.Bytes
			value.Packets += v.Packets

			// minimum, or init if zero
			if value.FlowStartNS == 0 {
				value.FlowStartNS = v.FlowStartNS
			} else if value.FlowStartNS > v.FlowStartNS {
				value.FlowStartNS = v.FlowStartNS
			}

			// maximum
			if value.FlowEndNS < v.FlowEndNS {
				value.FlowEndNS = v.FlowEndNS
			}
		}

		flowLogTable[key] = FlowLogEntry{
			Bytes:   value.Bytes,
			Packets: value.Packets,
			firstTs: m.ktimeToTime(value.FlowStartNS),
			ts:      m.ktimeToTime(value.FlowEndNS),
		}

		toDelete = append(toDelete, key)
	}

	if err := iterator.Err(); err != nil {
		return nil, err
	}

	for _, key := range toDelete {
		if err := table.Delete(&key); err != nil {
			return nil, err
		}
	}

	return flowLogTable, nil
}

func (m *lbFlowLogMap) readFlowLogs(tableV4, tableV6, tableL2 *ebpf.Map) (FlowLogTableV4, FlowLogTableV6, FlowLogTableL2, error) {
	retV4, err := m.readFlowLogsV4(tableV4)
	if err != nil {
		return nil, nil, nil, err
	}

	retV6, err := m.readFlowLogsV6(tableV6)
	if err != nil {
		return nil, nil, nil, err
	}

	retL2, err := m.readFlowLogsL2(tableL2)
	if err != nil {
		return nil, nil, nil, err
	}

	return retV4, retV6, retL2, nil
}

func (m *lbFlowLogMap) ReadFlowLogs() (FlowLogTableV4, FlowLogTableV6, FlowLogTableL2, error) {
	key := uint32(0)

	var mapToDumpV4 *ebpf.Map
	var mapToDumpV6 *ebpf.Map
	var mapToDumpL2 *ebpf.Map

	if m.currentTable == 1 {
		m.currentTable = 2
		mapToDumpV4 = m.v4table1
		mapToDumpV6 = m.v6table1
		mapToDumpL2 = m.l2table1
	} else {
		m.currentTable = 1
		mapToDumpV4 = m.v4table2
		mapToDumpV6 = m.v6table2
		mapToDumpL2 = m.l2table2
	}
	if err := m.tableSelector.Update(key, m.currentTable, 0); err != nil {
		return nil, nil, nil, err
	}

	// Smart synchronization: let all BPF programs to finish writing to the
	// previous table. At least, Go guarantees that sleep will be at least 1 sec
	time.Sleep(1 * time.Second)

	return m.readFlowLogs(mapToDumpV4, mapToDumpV6, mapToDumpL2)
}

var ifaces = map[int]string{}

func InterfaceByIndex(ifindex int) (string, error) {
	if name, ok := ifaces[ifindex]; ok {
		return name, nil
	}

	iface, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return "", err
	}

	ifaces[ifindex] = iface.Name
	return iface.Name, nil
}
