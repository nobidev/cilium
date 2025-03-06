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

	ebpfRingBuf "github.com/cilium/ebpf/ringbuf"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/time"
)

type lbFlowLogMap struct {
	bpfMap  *ebpf.Map
	readers []*ebpfRingBuf.Reader
}

func newLbFlowLogMap(config Config, name string) *lbFlowLogMap {
	return &lbFlowLogMap{
		bpfMap: ebpf.NewMap(&ebpf.MapSpec{
			Name:       name,
			Type:       ebpf.RingBuf,
			MaxEntries: config.LoadbalancerFlowLogsMapSize,
			Pinning:    ebpf.PinByName,
		}),
		readers: []*ebpfRingBuf.Reader{},
	}
}

func (m *lbFlowLogMap) openOrCreate() error {
	if err := m.bpfMap.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}

	return nil
}

func (m *lbFlowLogMap) close() error {
	for _, r := range m.readers {
		r.Close()
	}

	if err := m.bpfMap.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	return nil
}

type RingBufferReader interface {
	Read() (ebpfRingBuf.Record, error)
}

type LBFlowLogMap interface {
	newRingBufferReader() (RingBufferReader, error)
}

func (m *lbFlowLogMap) newRingBufferReader() (RingBufferReader, error) {
	reader, err := ebpfRingBuf.NewReader(m.bpfMap.Map)
	if err != nil {
		return nil, fmt.Errorf("failed to create ringbuf reader: %w", err)
	}

	m.readers = append(m.readers, reader)

	return reader, nil
}

// The FlowLogKey format should be in sync with bpf/lib/enterprise_xdp.h
type FlowLogKey = string

const (
	ifindexStart = 0
	ifindexSize  = 4

	saddrStart = ifindexStart + ifindexSize
	saddrSize  = 4

	daddrStart = saddrStart + saddrSize
	daddrSize  = 4

	sportStart = daddrStart + daddrSize
	sportSize  = 2

	dportStart = sportStart + sportSize
	dportSize  = 2

	nexthdrStart = dportStart + dportSize
	nexthdrSize  = 1

	padSize = 7

	bytesStart = nexthdrStart + nexthdrSize + padSize
	bytesSize  = 8
)

type FlowLogEntry = struct {
	Key     FlowLogKey
	Packets uint64    // ATM, the # of records received
	Bytes   uint64    // bytes, accumulated from summind records
	ts      time.Time // the last update
}

type FlowLogTable = map[FlowLogKey]FlowLogEntry

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
