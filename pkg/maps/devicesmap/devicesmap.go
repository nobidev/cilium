// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicesmap

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

var Cell = cell.Provide(NewDeviceMap)

type DevicesMap struct {
	*bpf.Map
}

const mapName = "cilium_devices"

func NewDeviceMap(lifecycle cell.Lifecycle, logger *slog.Logger) *DevicesMap {
	dm := &DevicesMap{}
	var index Index

	lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			m := bpf.NewMap(
				mapName,
				ebpf.Array,
				&index,
				&DeviceState{},
				4096,
				0,
			)
			if err := m.OpenOrCreate(); err != nil {
				return err
			}
			dm.Map = m
			return nil
		},
	})

	return dm
}

func (m *DevicesMap) Upsert(ifindex uint32, state DeviceState) error {
	key := Index(ifindex)
	return m.Map.Update(&key, &state)
}

func (m *DevicesMap) Delete(ifindex uint32) error {
	key := Index(ifindex)
	_, err := m.Map.SilentDelete(&key)
	return err
}

func (m *DevicesMap) Lookup(ifindex uint32) (*DeviceState, error) {
	key := Index(ifindex)
	state, err := m.Map.Lookup(&key)
	if err != nil {
		return nil, err
	}
	return state.(*DeviceState), nil
}

// IterateCallback represents the signature of the callback used for iteration.
type IterateCallback func(*Index, *DeviceState)

func (m *DevicesMap) IterateWithCallback(cb IterateCallback) error {
	return m.Map.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		cb(k.(*Index), v.(*DeviceState))
	})
}

// Index matches the BPF map key (__u32 ifindex).
type Index uint32

func (k *Index) New() bpf.MapKey {
	return new(Index)
}

func (k *Index) String() string {
	return fmt.Sprintf("%d", uint32(*k))
}

// DeviceState matches struct device_state in bpf/lib/devices.h.
type DeviceState struct {
	MAC types.MACAddr `align:"mac"`
	_   uint16
	L3  DeviceStateL3 `align:"l3"`
	_   uint8         `align:"pad1"`
	_   uint16        `align:"pad2"`
	_   uint32        `align:"pad3"`
}

// DeviceStateL3 represents device L3 states.
type DeviceStateL3 uint8

const deviceStateL3Mask DeviceStateL3 = 1 << iota

func (s *DeviceState) New() bpf.MapValue {
	return &DeviceState{}
}

func (s *DeviceState) String() string {
	return fmt.Sprintf("%s %b", s.MAC.String(), s.L3)
}

func (s *DeviceState) IsL3() bool {
	return s.L3&deviceStateL3Mask != 0
}

func (s *DeviceState) SetL3(enabled bool) {
	if enabled {
		s.L3 |= deviceStateL3Mask
		return
	}
	s.L3 &^= deviceStateL3Mask
}

func NewDeviceState(mac net.HardwareAddr) DeviceState {
	state := DeviceState{}
	if len(mac) == len(state.MAC) {
		copy(state.MAC[:], mac)
	}
	if len(mac) != 6 {
		state.SetL3(true)
	}
	return state
}
